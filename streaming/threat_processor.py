import os
import time

import pandas as pd
import psycopg2
import psycopg2.extras
from pyspark.sql import DataFrame, SparkSession
from pyspark.sql.functions import col, from_json, from_unixtime, struct, to_json, udf, when, window
from pyspark.sql.types import ArrayType, DoubleType, StringType, StructField, StructType

KAFKA_BOOTSTRAP_SERVERS = "kafka:19092"
INPUT_TOPIC = "threats.raw"
ENRICHED_TOPIC = "threats.enriched"

DB_COLUMNS = [
    "ip",
    "country_code",
    "abuse_confidence_score",
    "risk_level",
    "latitude",
    "longitude",
    "last_reported_at",
    "event_time",
    "source",
    "category",
]


def to_categories(category):
    return [category] if category else []


categories_udf = udf(to_categories, ArrayType(StringType()))

INSERT_SQL = (
    "INSERT INTO THREAT_EVENTS (IP, COUNTRY_CODE, ABUSE_CONFIDENCE_SCORE, RISK_LEVEL, "
    "LATITUDE, LONGITUDE, LAST_REPORTED_AT, EVENT_TIME, SOURCE, CATEGORY, REOFFENSE_PROBABILITY, "
    "ANOMALY_SCORE) VALUES %s"
)
METRICS_INSERT_SQL = (
    "INSERT INTO PIPELINE_METRICS (BATCH_ID, BATCH_ROWS, WRITE_DURATION_MS) VALUES (%s, %s, %s)"
)

MODEL_PATH = "/opt/ghostnet/ml/reoffense_model.joblib"
_model_bundle = None
_model_load_attempted = False


def get_model_bundle():
    """Loaded once per driver process. Missing model file degrades to NULL
    scores rather than crashing the pipeline."""
    global _model_bundle, _model_load_attempted
    if _model_load_attempted:
        return _model_bundle
    _model_load_attempted = True
    try:
        import joblib

        _model_bundle = joblib.load(MODEL_PATH)
        print(f"Modele de reoffense charge depuis {MODEL_PATH}")
    except Exception as exc:
        print(f"Pas de modele de reoffense charge ({exc}) -- REOFFENSE_PROBABILITY sera NULL")
    return _model_bundle


def score_reoffense_probability(pdf: pd.DataFrame) -> list:
    bundle = get_model_bundle()
    if bundle is None:
        return [None] * len(pdf)
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


ANOMALY_MODEL_PATH = "/opt/ghostnet/ml/anomaly_model.joblib"
_anomaly_bundle = None
_anomaly_load_attempted = False


def get_anomaly_bundle():
    """Same lazy-load-once pattern as get_model_bundle(), for the
    unsupervised IsolationForest anomaly detector."""
    global _anomaly_bundle, _anomaly_load_attempted
    if _anomaly_load_attempted:
        return _anomaly_bundle
    _anomaly_load_attempted = True
    try:
        import joblib

        _anomaly_bundle = joblib.load(ANOMALY_MODEL_PATH)
        print(f"Modele d'anomalie charge depuis {ANOMALY_MODEL_PATH}")
    except Exception as exc:
        print(f"Pas de modele d'anomalie charge ({exc}) -- ANOMALY_SCORE sera NULL")
    return _anomaly_bundle


def score_anomaly(pdf: pd.DataFrame) -> list:
    bundle = get_anomaly_bundle()
    if bundle is None:
        return [None] * len(pdf)
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


def write_batch_to_postgres(batch_df: DataFrame, batch_id: int) -> None:
    pdf = batch_df.select(*DB_COLUMNS).toPandas()
    if pdf.empty:
        return
    pdf["reoffense_probability"] = score_reoffense_probability(pdf)
    pdf["anomaly_score"] = score_anomaly(pdf)
    conn = psycopg2.connect(
        host="postgres",
        port=5432,
        user=os.environ.get("POSTGRES_USER", "ghostnet"),
        password=os.environ.get("POSTGRES_PASSWORD", "ghostnet"),
        dbname=os.environ.get("POSTGRES_DB", "ghostnet"),
    )
    try:
        rows = [tuple(r) for r in pdf.itertuples(index=False, name=None)]
        cur = conn.cursor()
        start = time.monotonic()
        psycopg2.extras.execute_values(cur, INSERT_SQL, rows, page_size=2000)
        write_duration_ms = (time.monotonic() - start) * 1000
        cur.execute(METRICS_INSERT_SQL, (batch_id, len(rows), write_duration_ms))
        conn.commit()
        print(f"Batch {batch_id}: {len(rows)} lignes ecrites dans Postgres en {write_duration_ms:.0f}ms")
    finally:
        conn.close()


COUNTRY_CENTROIDS = {
    "AD": (42.55, 1.58),
    "AE": (23.42, 53.85),
    "AF": (33.94, 67.71),
    "AG": (17.06, -61.80),
    "AI": (18.22, -63.07),
    "AL": (41.15, 20.17),
    "AM": (40.07, 45.04),
    "AO": (-11.20, 17.87),
    "AQ": (-75.25, -0.07),
    "AR": (-38.42, -63.62),
    "AS": (-14.27, -170.13),
    "AT": (47.52, 14.55),
    "AU": (-25.27, 133.78),
    "AW": (12.52, -69.97),
    "AZ": (40.14, 47.58),
    "BA": (43.92, 17.68),
    "BB": (13.19, -59.54),
    "BD": (23.68, 90.36),
    "BE": (50.50, 4.47),
    "BF": (12.24, -1.56),
    "BG": (42.73, 25.49),
    "BH": (25.93, 50.64),
    "BI": (-3.37, 29.92),
    "BJ": (9.31, 2.32),
    "BM": (32.32, -64.75),
    "BN": (4.54, 114.73),
    "BO": (-16.29, -63.59),
    "BR": (-14.24, -51.93),
    "BS": (25.03, -77.40),
    "BT": (27.51, 90.43),
    "BW": (-22.33, 24.68),
    "BY": (53.71, 27.95),
    "BZ": (17.19, -88.50),
    "CA": (56.13, -106.35),
    "CD": (-4.04, 21.76),
    "CF": (6.61, 20.94),
    "CG": (-0.23, 15.83),
    "CH": (46.82, 8.23),
    "CI": (7.54, -5.55),
    "CK": (-21.24, -159.78),
    "CL": (-35.68, -71.54),
    "CM": (7.37, 12.35),
    "CN": (35.86, 104.20),
    "CO": (4.57, -74.30),
    "CR": (9.75, -83.75),
    "CU": (21.52, -77.78),
    "CV": (16.54, -24.01),
    "CY": (35.13, 33.43),
    "CZ": (49.82, 15.47),
    "DE": (51.17, 10.45),
    "DJ": (11.83, 42.59),
    "DK": (56.26, 9.50),
    "DM": (15.41, -61.37),
    "DO": (18.74, -70.16),
    "DZ": (28.03, 1.66),
    "EC": (-1.83, -78.18),
    "EE": (58.60, 25.01),
    "EG": (26.82, 30.80),
    "EH": (24.22, -12.89),
    "ER": (15.18, 39.78),
    "ES": (40.46, -3.75),
    "ET": (9.15, 40.49),
    "FI": (61.92, 25.75),
    "FJ": (-16.58, 179.41),
    "FK": (-51.80, -59.52),
    "FM": (7.43, 150.55),
    "FO": (61.89, -6.91),
    "FR": (46.23, 2.21),
    "GA": (-0.80, 11.61),
    "GB": (55.38, -3.44),
    "GD": (12.26, -61.60),
    "GE": (42.32, 43.36),
    "GF": (3.93, -53.13),
    "GG": (49.47, -2.59),
    "GH": (7.95, -1.02),
    "GI": (36.14, -5.35),
    "GL": (71.71, -42.60),
    "GM": (13.44, -15.31),
    "GN": (9.95, -9.70),
    "GP": (16.27, -61.55),
    "GQ": (1.65, 10.27),
    "GR": (39.07, 21.82),
    "GT": (15.78, -90.23),
    "GU": (13.44, 144.79),
    "GW": (11.80, -15.18),
    "GY": (4.86, -58.93),
    "HK": (22.40, 114.11),
    "HN": (15.20, -86.24),
    "HR": (45.10, 15.20),
    "HT": (18.97, -72.29),
    "HU": (47.16, 19.50),
    "ID": (-0.79, 113.92),
    "IE": (53.41, -8.24),
    "IL": (31.05, 34.85),
    "IM": (54.24, -4.55),
    "IN": (20.59, 78.96),
    "IO": (-6.34, 71.88),
    "IQ": (33.22, 43.68),
    "IR": (32.43, 53.69),
    "IS": (64.96, -19.02),
    "IT": (41.87, 12.57),
    "JE": (49.21, -2.13),
    "JM": (18.11, -77.30),
    "JO": (30.59, 36.24),
    "JP": (36.20, 138.25),
    "KE": (-0.02, 37.91),
    "KG": (41.20, 74.77),
    "KH": (12.57, 104.99),
    "KI": (-3.37, -168.73),
    "KM": (-11.88, 43.87),
    "KN": (17.36, -62.78),
    "KP": (40.34, 127.51),
    "KR": (35.91, 127.77),
    "KW": (29.31, 47.48),
    "KY": (19.51, -80.57),
    "KZ": (48.02, 66.92),
    "LA": (19.86, 102.50),
    "LB": (33.85, 35.86),
    "LC": (13.91, -60.98),
    "LI": (47.17, 9.56),
    "LK": (7.87, 80.77),
    "LR": (6.43, -9.43),
    "LS": (-29.61, 28.23),
    "LT": (55.17, 23.88),
    "LU": (49.82, 6.13),
    "LV": (56.88, 24.60),
    "LY": (26.34, 17.23),
    "MA": (31.79, -7.09),
    "MC": (43.75, 7.41),
    "MD": (47.41, 28.37),
    "ME": (42.71, 19.37),
    "MG": (-18.77, 46.87),
    "MH": (7.13, 171.18),
    "MK": (41.61, 21.75),
    "ML": (17.57, -3.99),
    "MM": (21.91, 95.96),
    "MN": (46.86, 103.85),
    "MO": (22.20, 113.55),
    "MP": (17.33, 145.38),
    "MQ": (14.64, -61.02),
    "MR": (21.01, -10.94),
    "MS": (16.74, -62.19),
    "MT": (35.94, 14.38),
    "MU": (-20.35, 57.55),
    "MV": (3.20, 73.22),
    "MW": (-13.25, 34.30),
    "MX": (23.63, -102.55),
    "MY": (4.21, 101.98),
    "MZ": (-18.67, 35.53),
    "NA": (-22.96, 18.49),
    "NC": (-20.90, 165.62),
    "NE": (17.61, 8.08),
    "NG": (9.08, 8.68),
    "NI": (12.87, -85.21),
    "NL": (52.13, 5.29),
    "NO": (60.47, 8.47),
    "NP": (28.39, 84.12),
    "NR": (-0.52, 166.93),
    "NU": (-19.05, -169.87),
    "NZ": (-40.90, 174.89),
    "OM": (21.51, 55.92),
    "PA": (8.54, -80.78),
    "PE": (-9.19, -75.02),
    "PF": (-17.68, -149.41),
    "PG": (-6.31, 143.96),
    "PH": (12.88, 121.77),
    "PK": (30.38, 69.35),
    "PL": (51.92, 19.15),
    "PM": (46.94, -56.27),
    "PR": (18.22, -66.59),
    "PS": (31.95, 35.23),
    "PT": (39.40, -8.22),
    "PW": (7.51, 134.58),
    "PY": (-23.44, -58.44),
    "QA": (25.35, 51.18),
    "RE": (-21.12, 55.53),
    "RO": (45.94, 24.97),
    "RS": (44.02, 21.01),
    "RU": (61.52, 105.32),
    "RW": (-1.94, 29.87),
    "SA": (23.89, 45.08),
    "SB": (-9.65, 160.16),
    "SC": (-4.68, 55.49),
    "SD": (12.86, 30.22),
    "SE": (60.13, 18.64),
    "SG": (1.35, 103.82),
    "SH": (-24.14, -10.03),
    "SI": (46.15, 14.99),
    "SK": (48.67, 19.70),
    "SL": (8.46, -11.78),
    "SM": (43.94, 12.46),
    "SN": (14.50, -14.45),
    "SO": (5.15, 46.20),
    "SR": (3.92, -56.03),
    "SS": (6.88, 31.31),
    "ST": (0.19, 6.61),
    "SV": (13.79, -88.90),
    "SY": (34.80, 38.997),
    "SZ": (-26.52, 31.47),
    "TC": (21.69, -71.80),
    "TD": (15.45, 18.73),
    "TG": (8.62, 0.82),
    "TH": (15.87, 100.99),
    "TJ": (38.86, 71.28),
    "TL": (-8.87, 125.73),
    "TM": (38.97, 59.56),
    "TN": (33.89, 9.54),
    "TO": (-21.18, -175.20),
    "TR": (38.96, 35.24),
    "TT": (10.69, -61.22),
    "TV": (-7.11, 177.65),
    "TW": (23.70, 120.96),
    "TZ": (-6.37, 34.89),
    "UA": (48.38, 31.17),
    "UG": (1.37, 32.29),
    "US": (37.09, -95.71),
    "UY": (-32.52, -55.77),
    "UZ": (41.38, 64.59),
    "VA": (41.90, 12.45),
    "VC": (12.98, -61.29),
    "VE": (6.42, -66.59),
    "VG": (18.42, -64.62),
    "VI": (18.34, -64.90),
    "VN": (14.06, 108.28),
    "VU": (-15.38, 166.96),
    "WF": (-13.77, -177.16),
    "WS": (-13.76, -172.10),
    "YE": (15.55, 48.52),
    "YT": (-12.83, 45.17),
    "ZA": (-30.56, 22.94),
    "ZM": (-13.13, 27.85),
    "ZW": (-19.02, 29.15),
    "XK": (42.60, 20.90),
}


def centroid_lat(country_code: str) -> float:
    return COUNTRY_CENTROIDS.get(country_code, (0.0, 0.0))[0]


def centroid_lon(country_code: str) -> float:
    return COUNTRY_CENTROIDS.get(country_code, (0.0, 0.0))[1]


centroid_lat_udf = udf(centroid_lat, DoubleType())
centroid_lon_udf = udf(centroid_lon, DoubleType())

MESSAGE_SCHEMA = StructType(
    [
        StructField("ip", StringType()),
        StructField("country_code", StringType()),
        StructField("abuse_confidence_score", DoubleType()),
        StructField("last_reported_at", StringType()),
        StructField("source", StringType()),
        StructField("ingested_at", DoubleType()),
        StructField("category", StringType()),
    ]
)


def main() -> None:
    spark = SparkSession.builder.appName("GhostNetThreatProcessor").getOrCreate()
    spark.sparkContext.setLogLevel("WARN")

    raw = (
        spark.readStream.format("kafka")
        .option("kafka.bootstrap.servers", KAFKA_BOOTSTRAP_SERVERS)
        .option("subscribe", INPUT_TOPIC)
        .option("startingOffsets", "earliest")
        .load()
    )

    parsed = raw.select(from_json(col("value").cast("string"), MESSAGE_SCHEMA).alias("data")).select("data.*")

    enriched = (
        parsed.withColumn("latitude", centroid_lat_udf(col("country_code")))
        .withColumn("longitude", centroid_lon_udf(col("country_code")))
        .withColumn(
            "risk_level",
            when(col("abuse_confidence_score") >= 90, "critical")
            .when(col("abuse_confidence_score") >= 70, "high")
            .when(col("abuse_confidence_score") >= 40, "medium")
            .otherwise("low"),
        )
        .withColumn("event_time", from_unixtime(col("ingested_at")).cast("timestamp"))
        .withColumn("categories", categories_udf(col("category")))
    )

    enriched_console = (
        enriched.writeStream.format("console")
        .outputMode("append")
        .option("truncate", "false")
        .option("numRows", 10)
        .start()
    )

    enriched_kafka = (
        enriched.select(
            col("ip").alias("key"),
            to_json(struct(*DB_COLUMNS, "categories")).alias("value"),
        )
        .writeStream.format("kafka")
        .option("kafka.bootstrap.servers", KAFKA_BOOTSTRAP_SERVERS)
        .option("topic", ENRICHED_TOPIC)
        .option("checkpointLocation", "/opt/ghostnet/streaming/_checkpoints/kafka_enriched")
        .outputMode("append")
        .start()
    )

    enriched_postgres = (
        enriched.writeStream.foreachBatch(write_batch_to_postgres)
        .outputMode("append")
        .trigger(processingTime="5 minutes")
        .option("checkpointLocation", "/opt/ghostnet/streaming/_checkpoints/snowflake")
        .start()
    )

    country_counts = (
        enriched.withWatermark("event_time", "10 minutes")
        .groupBy(window(col("event_time"), "5 minutes", "1 minute"), col("country_code"))
        .count()
        .orderBy(col("count").desc())
    )

    counts_console = (
        country_counts.writeStream.format("console")
        .outputMode("complete")
        .option("truncate", "false")
        .start()
    )

    spark.streams.awaitAnyTermination()


if __name__ == "__main__":
    main()
