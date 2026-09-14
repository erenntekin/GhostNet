"""One-time backfill: scores every pre-existing row with ANOMALY_SCORE IS
NULL, same approach as ml/backfill_reoffense_scores.py.

Run after training: python ml/backfill_anomaly_scores.py
"""

import os

import joblib
import pandas as pd
import psycopg2
import psycopg2.extras
from dotenv import load_dotenv
from pathlib import Path

load_dotenv()

ML_DIR = Path(__file__).parent
BATCH_SIZE = 5000


def db_connection():
    return psycopg2.connect(
        host=os.environ.get("POSTGRES_HOST", "localhost"),
        port=os.environ.get("POSTGRES_PORT", "5432"),
        user=os.environ["POSTGRES_USER"],
        password=os.environ["POSTGRES_PASSWORD"],
        dbname=os.environ["POSTGRES_DB"],
    )


def score(pdf: pd.DataFrame, bundle: dict) -> list:
    features = pd.DataFrame(
        {
            "source": pdf["source"],
            "country_bucket": pdf["country_code"].where(
                pdf["country_code"].isin(bundle["top_countries"]), "OTHER"
            ),
            "category": pdf["category"].fillna("UNKNOWN"),
            "risk_level": pdf["risk_level"],
            "abuse_confidence_score": pdf["abuse_confidence_score"].fillna(0.0),
        }
    )
    scores = (
        bundle["pipeline"]
        .named_steps["clf"]
        .score_samples(bundle["pipeline"].named_steps["preprocess"].transform(features))
    )
    return [round(float(s), 4) for s in scores]


def main() -> None:
    bundle = joblib.load(ML_DIR / "anomaly_model.joblib")
    conn = db_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT ctid, SOURCE, COUNTRY_CODE, CATEGORY, RISK_LEVEL, ABUSE_CONFIDENCE_SCORE "
            "FROM THREAT_EVENTS WHERE ANOMALY_SCORE IS NULL"
        )
        rows = cur.fetchall()
        if not rows:
            print("Nothing to backfill. Every row already has a score.")
            return
        print(f"{len(rows):,} unscored rows found.")

        pdf = pd.DataFrame(
            rows,
            columns=["ctid", "source", "country_code", "category", "risk_level", "abuse_confidence_score"],
        )
        pdf["anomaly_score"] = score(pdf, bundle)

        update_cur = conn.cursor()
        total = 0
        for start in range(0, len(pdf), BATCH_SIZE):
            chunk = pdf.iloc[start : start + BATCH_SIZE]
            psycopg2.extras.execute_values(
                update_cur,
                "UPDATE THREAT_EVENTS SET ANOMALY_SCORE = data.anomaly_score "
                "FROM (VALUES %s) AS data(ctid, anomaly_score) "
                "WHERE THREAT_EVENTS.ctid = data.ctid::tid",
                list(chunk[["ctid", "anomaly_score"]].itertuples(index=False, name=None)),
            )
            conn.commit()
            total += len(chunk)
            print(f"  {total:,}/{len(pdf):,} scored and written")

        print(f"Done: {total:,} rows backfilled.")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
