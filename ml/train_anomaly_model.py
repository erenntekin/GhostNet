"""Trains an unsupervised IsolationForest anomaly detector over THREAT_EVENTS:
does this event's source/country/category/score combination stand out from
the rest of the traffic. Same feature set as train_reoffense_model.py.

Run manually to retrain: python ml/train_anomaly_model.py

Outputs: ml/anomaly_model.joblib (fitted pipeline), ml/anomaly_metrics.json
(contamination assumption, observed anomaly rate, sample anomalies).
"""

import json
import os
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import psycopg2
from dotenv import load_dotenv
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

load_dotenv()

ML_DIR = Path(__file__).parent
TOP_N_COUNTRIES = 15
CONTAMINATION = 0.02
CATEGORICAL_FEATURES = ["source", "country_bucket", "category", "risk_level"]
NUMERIC_FEATURES = ["abuse_confidence_score"]


def db_connection():
    return psycopg2.connect(
        host=os.environ.get("POSTGRES_HOST", "localhost"),
        port=os.environ.get("POSTGRES_PORT", "5432"),
        user=os.environ["POSTGRES_USER"],
        password=os.environ["POSTGRES_PASSWORD"],
        dbname=os.environ["POSTGRES_DB"],
    )


def load_events() -> pd.DataFrame:
    conn = db_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT IP, SOURCE, COUNTRY_CODE, ABUSE_CONFIDENCE_SCORE, RISK_LEVEL, CATEGORY "
            "FROM THREAT_EVENTS"
        )
        columns = ["ip", "source", "country_code", "abuse_confidence_score", "risk_level", "category"]
        df = pd.DataFrame(cur.fetchall(), columns=columns)
    finally:
        conn.close()
    return df


def engineer_features(df: pd.DataFrame, top_countries: list[str]) -> pd.DataFrame:
    out = df.copy()
    out["country_bucket"] = out["country_code"].where(out["country_code"].isin(top_countries), "OTHER")
    out["category"] = out["category"].fillna("UNKNOWN")
    out["abuse_confidence_score"] = out["abuse_confidence_score"].fillna(0.0)
    return out


def main() -> None:
    print("Loading THREAT_EVENTS for anomaly detection...")
    raw = load_events()
    print(f"{len(raw):,} events loaded.")

    top_countries = raw["country_code"].value_counts().head(TOP_N_COUNTRIES).index.tolist()
    df = engineer_features(raw, top_countries)
    X = df[CATEGORICAL_FEATURES + NUMERIC_FEATURES]

    preprocessor = ColumnTransformer(
        [
            ("cat", OneHotEncoder(handle_unknown="ignore"), CATEGORICAL_FEATURES),
        ],
        remainder="passthrough",
        sparse_threshold=0,
    )

    model = IsolationForest(contamination=CONTAMINATION, random_state=42, n_jobs=-1)
    pipe = Pipeline([("preprocess", preprocessor), ("clf", model)])
    pipe.fit(X)

    scores = pipe.named_steps["clf"].score_samples(pipe.named_steps["preprocess"].transform(X))
    df["anomaly_score"] = scores
    observed_rate = round(float((pipe.predict(X) == -1).mean()), 4)

    percentile_breakpoints = [round(float(p), 6) for p in np.percentile(scores, np.arange(0, 101))]

    joblib.dump(
        {
            "pipeline": pipe,
            "top_countries": top_countries,
            "categorical_features": CATEGORICAL_FEATURES,
            "numeric_features": NUMERIC_FEATURES,
        },
        ML_DIR / "anomaly_model.joblib",
    )

    metrics = {
        "trained_on_rows": len(raw),
        "contamination": CONTAMINATION,
        "observed_anomaly_rate": observed_rate,
        "score_percentiles": percentile_breakpoints,
        "methodology": (
            "IsolationForest, unsupervised: no label exists for 'unusual event'. Isolates points "
            "that are easy to separate from the rest with few random splits, over the same fields "
            "the reoffense model uses (source, country, category, risk level, initial score). Lower "
            "score = more anomalous."
        ),
    }
    (ML_DIR / "anomaly_metrics.json").write_text(json.dumps(metrics, indent=2, default=str))

    print(f"Observed anomaly rate: {observed_rate * 100:.2f}% (target {CONTAMINATION * 100:.0f}%)")
    print(f"Saved model to {ML_DIR / 'anomaly_model.joblib'}")
    print(f"Saved metrics to {ML_DIR / 'anomaly_metrics.json'}")


if __name__ == "__main__":
    main()
