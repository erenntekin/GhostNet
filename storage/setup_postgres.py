import os

import psycopg2
from dotenv import load_dotenv

load_dotenv()

DDL_STATEMENTS = [
    """
    CREATE TABLE IF NOT EXISTS THREAT_EVENTS (
        IP TEXT,
        COUNTRY_CODE TEXT,
        ABUSE_CONFIDENCE_SCORE DOUBLE PRECISION,
        RISK_LEVEL TEXT,
        LATITUDE DOUBLE PRECISION,
        LONGITUDE DOUBLE PRECISION,
        LAST_REPORTED_AT TEXT,
        EVENT_TIME TIMESTAMP,
        SOURCE TEXT,
        LOADED_AT TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        CATEGORY TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_threat_events_ip ON THREAT_EVENTS (IP)",
    "CREATE INDEX IF NOT EXISTS idx_threat_events_source ON THREAT_EVENTS (SOURCE)",
    "CREATE INDEX IF NOT EXISTS idx_threat_events_loaded_at ON THREAT_EVENTS (LOADED_AT)",
    "ALTER TABLE THREAT_EVENTS ADD COLUMN IF NOT EXISTS REOFFENSE_PROBABILITY DOUBLE PRECISION",
    "ALTER TABLE THREAT_EVENTS ADD COLUMN IF NOT EXISTS ANOMALY_SCORE DOUBLE PRECISION",
    """
    CREATE TABLE IF NOT EXISTS PIPELINE_METRICS (
        BATCH_ID BIGINT,
        BATCH_ROWS INT,
        WRITE_DURATION_MS DOUBLE PRECISION,
        RECORDED_AT TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_pipeline_metrics_recorded_at ON PIPELINE_METRICS (RECORDED_AT)",
    """
    CREATE TABLE IF NOT EXISTS BRIEFING_SNAPSHOTS (
        RECORDED_AT TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        GINI_COEFFICIENT DOUBLE PRECISION,
        TOP_COUNTRY_PCT DOUBLE PRECISION,
        CROSS_SOURCE_PCT DOUBLE PRECISION,
        CATEGORIZED_PCT DOUBLE PRECISION
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_briefing_snapshots_recorded_at ON BRIEFING_SNAPSHOTS (RECORDED_AT)",
]


def main() -> None:
    conn = psycopg2.connect(
        host=os.environ.get("POSTGRES_HOST", "localhost"),
        port=os.environ.get("POSTGRES_PORT", "5432"),
        user=os.environ["POSTGRES_USER"],
        password=os.environ["POSTGRES_PASSWORD"],
        dbname=os.environ["POSTGRES_DB"],
    )
    conn.autocommit = True
    try:
        cur = conn.cursor()
        for statement in DDL_STATEMENTS:
            cur.execute(statement)
            print(f"OK: {statement.strip().splitlines()[0]}...")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
