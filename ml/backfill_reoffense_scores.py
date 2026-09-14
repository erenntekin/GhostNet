"""One-time backfill: scores every pre-existing row with REOFFENSE_PROBABILITY
IS NULL, using ctid to target updates since THREAT_EVENTS has no primary key.

Run after training: python ml/backfill_reoffense_scores.py
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
    proba = bundle["pipeline"].predict_proba(features)[:, 1]
    return [round(float(p), 4) for p in proba]


def main() -> None:
    bundle = joblib.load(ML_DIR / "reoffense_model.joblib")
    conn = db_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT ctid, SOURCE, COUNTRY_CODE, CATEGORY, RISK_LEVEL, ABUSE_CONFIDENCE_SCORE "
            "FROM THREAT_EVENTS WHERE REOFFENSE_PROBABILITY IS NULL"
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
        pdf["probability"] = score(pdf, bundle)

        update_cur = conn.cursor()
        total = 0
        for start in range(0, len(pdf), BATCH_SIZE):
            chunk = pdf.iloc[start : start + BATCH_SIZE]
            psycopg2.extras.execute_values(
                update_cur,
                "UPDATE THREAT_EVENTS SET REOFFENSE_PROBABILITY = data.probability "
                "FROM (VALUES %s) AS data(ctid, probability) "
                "WHERE THREAT_EVENTS.ctid = data.ctid::tid",
                list(chunk[["ctid", "probability"]].itertuples(index=False, name=None)),
            )
            conn.commit()
            total += len(chunk)
            print(f"  {total:,}/{len(pdf):,} scored and written")

        print(f"Done: {total:,} rows backfilled.")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
