# Historical reference only, not used by the live pipeline. GhostNet
# migrated off Snowflake to storage/setup_postgres.py: at this data volume
# (tens of thousands of rows, one dashboard, no real query concurrency),
# Snowflake's distributed-warehouse architecture solved a scaling problem
# this project doesn't have. Kept here, not deleted, so the decision and
# the schema it replaced stay visible. Running this requires
# snowflake-connector-python, which is no longer installed.
import os

import snowflake.connector
from dotenv import load_dotenv

load_dotenv()

DDL_STATEMENTS = [
    """
    CREATE WAREHOUSE IF NOT EXISTS GHOSTNET_WH
      WAREHOUSE_SIZE = 'XSMALL'
      AUTO_SUSPEND = 60
      AUTO_RESUME = TRUE
      INITIALLY_SUSPENDED = TRUE
    """,
    "CREATE DATABASE IF NOT EXISTS GHOSTNET",
    "CREATE SCHEMA IF NOT EXISTS GHOSTNET.PUBLIC",
    """
    CREATE TABLE IF NOT EXISTS GHOSTNET.PUBLIC.THREAT_EVENTS (
        ip STRING,
        country_code STRING,
        abuse_confidence_score FLOAT,
        risk_level STRING,
        latitude FLOAT,
        longitude FLOAT,
        last_reported_at STRING,
        event_time TIMESTAMP_NTZ,
        source STRING,
        loaded_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
    )
    """,
]


def main() -> None:
    conn = snowflake.connector.connect(
        account=os.environ["SNOWFLAKE_ACCOUNT"],
        user=os.environ["SNOWFLAKE_USER"],
        password=os.environ["SNOWFLAKE_PASSWORD"],
    )
    try:
        cursor = conn.cursor()
        for statement in DDL_STATEMENTS:
            cursor.execute(statement)
            print(f"OK: {statement.strip().splitlines()[0]}...")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
