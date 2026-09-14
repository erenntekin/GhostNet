"""Trains a model to predict whether a newly-seen IP will be flagged again.

Features come only from each IP's first sighting (no label leakage from
later occurrences). Run manually to retrain: python ml/train_reoffense_model.py

Outputs: ml/reoffense_model.joblib (fitted pipeline), ml/model_metrics.json
(evaluation metrics, read by the API).
"""

import json
import os
from pathlib import Path

import joblib
import pandas as pd
import psycopg2
from dotenv import load_dotenv
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

load_dotenv()

ML_DIR = Path(__file__).parent
TOP_N_COUNTRIES = 15
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


def load_training_data() -> pd.DataFrame:
    conn = db_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
            WITH first_seen AS (
                SELECT DISTINCT ON (IP)
                    IP, SOURCE, COUNTRY_CODE, ABUSE_CONFIDENCE_SCORE, RISK_LEVEL, CATEGORY
                FROM THREAT_EVENTS
                ORDER BY IP, LOADED_AT ASC
            ),
            counts AS (
                SELECT IP, COUNT(*) AS report_count FROM THREAT_EVENTS GROUP BY IP
            )
            SELECT f.source, f.country_code, f.abuse_confidence_score, f.risk_level,
                   f.category, (c.report_count > 1) AS reoffended
            FROM first_seen f JOIN counts c ON f.ip = c.ip
            """)
        columns = ["source", "country_code", "abuse_confidence_score", "risk_level", "category", "reoffended"]
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
    print("Loading first-sighting features from THREAT_EVENTS...")
    raw = load_training_data()
    print(
        f"{len(raw):,} distinct IPs, {raw['reoffended'].sum():,} reoffended "
        f"({raw['reoffended'].mean() * 100:.1f}%)"
    )

    top_countries = raw["country_code"].value_counts().head(TOP_N_COUNTRIES).index.tolist()
    df = engineer_features(raw, top_countries)

    X = df[CATEGORICAL_FEATURES + NUMERIC_FEATURES]
    y = df["reoffended"].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    preprocessor = ColumnTransformer(
        [
            ("cat", OneHotEncoder(handle_unknown="ignore"), CATEGORICAL_FEATURES),
        ],
        remainder="passthrough",
    )

    models = {
        "logistic_regression": LogisticRegression(max_iter=1000, class_weight="balanced"),
        "random_forest": RandomForestClassifier(
            n_estimators=200, max_depth=12, class_weight="balanced", random_state=42, n_jobs=-1
        ),
    }

    results = {}
    fitted_pipelines = {}
    for name, clf in models.items():
        pipe = Pipeline([("preprocess", preprocessor), ("clf", clf)])
        pipe.fit(X_train, y_train)
        proba = pipe.predict_proba(X_test)[:, 1]
        pred = pipe.predict(X_test)
        report = classification_report(y_test, pred, output_dict=True)
        auc = roc_auc_score(y_test, proba)
        cm = confusion_matrix(y_test, pred).tolist()
        results[name] = {
            "accuracy": report["accuracy"],
            "precision": report["1"]["precision"],
            "recall": report["1"]["recall"],
            "f1": report["1"]["f1-score"],
            "roc_auc": auc,
            "confusion_matrix": cm,  # [[TN, FP], [FN, TP]]
        }
        fitted_pipelines[name] = pipe
        print(
            f"\n{name}: accuracy={report['accuracy']:.3f} "
            f"precision={report['1']['precision']:.3f} recall={report['1']['recall']:.3f} "
            f"roc_auc={auc:.3f}"
        )

    production_model_name = "random_forest"
    production_pipe = fitted_pipelines[production_model_name]

    feature_names = production_pipe.named_steps["preprocess"].get_feature_names_out()
    importances = production_pipe.named_steps["clf"].feature_importances_
    feature_importance = sorted(zip(feature_names, importances.tolist()), key=lambda kv: kv[1], reverse=True)[
        :15
    ]

    joblib.dump(
        {
            "pipeline": production_pipe,
            "top_countries": top_countries,
            "categorical_features": CATEGORICAL_FEATURES,
            "numeric_features": NUMERIC_FEATURES,
        },
        ML_DIR / "reoffense_model.joblib",
    )

    metrics = {
        "trained_on_rows": len(raw),
        "positive_rate": round(float(raw["reoffended"].mean()), 4),
        "train_rows": len(X_train),
        "test_rows": len(X_test),
        "production_model": production_model_name,
        "models": results,
        "feature_importance": [{"feature": f, "importance": round(i, 4)} for f, i in feature_importance],
        "methodology": (
            "Features come only from each IP's first sighting (source, country, "
            "initial score, category, risk level) -- nothing derived from later "
            "occurrences, so the model can't see the answer before predicting it. "
            "The label is whether that IP was ever flagged again afterward."
        ),
    }
    (ML_DIR / "model_metrics.json").write_text(json.dumps(metrics, indent=2))

    print(f"\nSaved model to {ML_DIR / 'reoffense_model.joblib'}")
    print(f"Saved metrics to {ML_DIR / 'model_metrics.json'}")


if __name__ == "__main__":
    main()
