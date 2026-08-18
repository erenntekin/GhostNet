import asyncio
import bisect
import json
import os
import threading
import time

import psycopg2
import requests
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from kafka import KafkaConsumer

load_dotenv()

KAFKA_BOOTSTRAP_SERVERS = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
ENRICHED_TOPIC = "threats.enriched"
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
ABUSEIPDB_CHECK_BLOCK_URL = "https://api.abuseipdb.com/api/v2/check-block"
IPAPI_URL = "http://ip-api.com/json/{ip}"

ABUSE_CATEGORIES = {
    1: "DNS Compromise",
    2: "DNS Poisoning",
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted",
}

MITRE_MAP = {
    "DNS Compromise": ("Resource Development", "T1584.002", "Compromise Infrastructure: DNS Server"),
    "DNS Poisoning": ("Resource Development", "T1584.002", "Compromise Infrastructure: DNS Server"),
    "Fraud Orders": ("Impact", "T1657", "Financial Theft"),
    "DDoS Attack": ("Impact", "T1498", "Network Denial of Service"),
    "FTP Brute-Force": ("Credential Access", "T1110", "Brute Force"),
    "Ping of Death": ("Impact", "T1499", "Endpoint Denial of Service"),
    "Phishing": ("Initial Access", "T1566", "Phishing"),
    "Fraud VoIP": ("Impact", "T1657", "Financial Theft"),
    "Open Proxy": ("Command and Control", "T1090", "Proxy"),
    "Web Spam": ("Resource Development", "T1584", "Compromise Infrastructure"),
    "Email Spam": ("Command and Control", "T1071.003", "Application Layer Protocol: Mail"),
    "Blog Spam": ("Resource Development", "T1584", "Compromise Infrastructure"),
    "VPN IP": ("Command and Control", "T1090.003", "Proxy: Multi-hop Proxy"),
    "Port Scan": ("Reconnaissance", "T1595.001", "Active Scanning: Scanning IP Blocks"),
    "Hacking": ("Initial Access", "T1190", "Exploit Public-Facing Application"),
    "SQL Injection": ("Initial Access", "T1190", "Exploit Public-Facing Application"),
    "Spoofing": ("Defense Evasion", "T1036", "Masquerading"),
    "Brute-Force": ("Credential Access", "T1110", "Brute Force"),
    "Bad Web Bot": ("Reconnaissance", "T1595", "Active Scanning"),
    "Exploited Host": ("Resource Development", "T1584.005", "Compromise Infrastructure: Botnet"),
    "Web App Attack": ("Initial Access", "T1190", "Exploit Public-Facing Application"),
    "SSH": ("Credential Access", "T1110", "Brute Force"),
    "IoT Targeted": ("Resource Development", "T1584.005", "Compromise Infrastructure: Botnet"),
}

TACTIC_RECOMMENDATIONS = {
    "Credential Access": "Rate-limit and enforce MFA on exposed logins (SSH, admin, VPN)",
    "Reconnaissance": "Auto-block scanners (fail2ban-style connection throttling)",
    "Resource Development": "Blocklist: these are already-compromised attack infrastructure",
    "Initial Access": "Patch internet-facing app vulnerabilities first",
    "Command and Control": "Add egress filtering, not just inbound blocking",
    "Impact": "Add rate limiting / DDoS mitigation at the edge",
    "Defense Evasion": "Weight cross-source corroboration over any single feed's score",
}


def compute_gini_and_lorenz(counts: list[int]) -> tuple[float, list[dict]]:
    """Gini coefficient and Lorenz curve for geographic concentration (0 = evenly
    spread, 1 = all from one country)."""
    if not counts:
        return 0.0, []
    sorted_counts = sorted(counts)
    n = len(sorted_counts)
    total = sum(sorted_counts)
    if total == 0:
        return 0.0, []

    lorenz = [{"pct_countries": 0.0, "pct_threats": 0.0}]
    cum_count = 0
    cum_threats = 0
    for c in sorted_counts:
        cum_count += 1
        cum_threats += c
        lorenz.append(
            {
                "pct_countries": round(cum_count / n * 100, 2),
                "pct_threats": round(cum_threats / total * 100, 2),
            }
        )

    area_under_lorenz = 0.0
    for i in range(1, len(lorenz)):
        x1, y1 = lorenz[i - 1]["pct_countries"] / 100, lorenz[i - 1]["pct_threats"] / 100
        x2, y2 = lorenz[i]["pct_countries"] / 100, lorenz[i]["pct_threats"] / 100
        area_under_lorenz += (x2 - x1) * (y1 + y2) / 2
    gini = round(1 - 2 * area_under_lorenz, 3)
    return gini, lorenz


app = FastAPI(title="GhostNet API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

connected_clients: set[WebSocket] = set()
main_loop: asyncio.AbstractEventLoop | None = None


def db_connection():
    return psycopg2.connect(
        host=os.environ.get("POSTGRES_HOST", "localhost"),
        port=os.environ.get("POSTGRES_PORT", "5432"),
        user=os.environ["POSTGRES_USER"],
        password=os.environ["POSTGRES_PASSWORD"],
        dbname=os.environ["POSTGRES_DB"],
    )


def kafka_consumer_loop() -> None:
    """Retries on connection failure instead of dying silently. Without
    this, a `docker compose up` that starts the api container before Kafka
    is ready to accept connections leaves this thread dead for the rest of
    the container's life, and the live feed never recovers on its own."""
    while True:
        try:
            consumer = KafkaConsumer(
                ENRICHED_TOPIC,
                bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
                auto_offset_reset="earliest",
                value_deserializer=lambda v: json.loads(v.decode("utf-8")),
            )
            for message in consumer:
                if main_loop is not None:
                    asyncio.run_coroutine_threadsafe(broadcast(message.value), main_loop)
        except Exception as exc:
            print(f"Kafka consumer error ({exc}), retrying in 5s")
            time.sleep(5)


async def broadcast(event: dict) -> None:
    dead = []
    for client in connected_clients:
        try:
            await client.send_json(event)
        except Exception:
            dead.append(client)
    for client in dead:
        connected_clients.discard(client)


@app.on_event("startup")
async def startup() -> None:
    global main_loop
    main_loop = asyncio.get_event_loop()
    thread = threading.Thread(target=kafka_consumer_loop, daemon=True)
    thread.start()


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/api/summary")
def summary() -> dict:
    conn = None
    try:
        conn = db_connection()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM THREAT_EVENTS")
        total = cur.fetchone()[0]

        cur.execute("SELECT RISK_LEVEL, COUNT(*) FROM THREAT_EVENTS GROUP BY RISK_LEVEL")
        by_risk = {row[0]: row[1] for row in cur.fetchall()}

        cur.execute(
            "SELECT COUNTRY_CODE, COUNT(*) AS c FROM THREAT_EVENTS " "GROUP BY COUNTRY_CODE ORDER BY c DESC"
        )
        by_country = [{"country": row[0], "count": row[1]} for row in cur.fetchall()]

        cur.execute("SELECT COUNT(DISTINCT COUNTRY_CODE) FROM THREAT_EVENTS")
        distinct_countries = cur.fetchone()[0]

        cur.execute("SELECT MAX(LOADED_AT) FROM THREAT_EVENTS")
        last_loaded_row = cur.fetchone()[0]
        last_loaded_at = str(last_loaded_row) if last_loaded_row is not None else None

        cur.execute("SELECT COUNT(*) FROM THREAT_EVENTS " "WHERE LOADED_AT >= NOW() - INTERVAL '24 hours'")
        new_last_24h = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM (SELECT IP FROM THREAT_EVENTS GROUP BY IP HAVING COUNT(*) > 1)")
        repeat_offenders = cur.fetchone()[0]

        cur.execute(
            "SELECT COUNT(*) FROM (SELECT IP FROM THREAT_EVENTS GROUP BY IP HAVING COUNT(DISTINCT SOURCE) >= 2)"
        )
        cross_source_corroborated = cur.fetchone()[0]

        cur.execute(
            "SELECT CATEGORY, COUNT(*) FROM THREAT_EVENTS WHERE CATEGORY IS NOT NULL GROUP BY CATEGORY"
        )
        by_category = {row[0]: row[1] for row in cur.fetchall()}

        gini, _ = compute_gini_and_lorenz([c["count"] for c in by_country])

        return {
            "total": total,
            "by_risk": by_risk,
            "top_countries": by_country,
            "distinct_countries": distinct_countries,
            "last_loaded_at": last_loaded_at,
            "new_last_24h": new_last_24h,
            "repeat_offenders": repeat_offenders,
            "cross_source_corroborated": cross_source_corroborated,
            "gini_coefficient": gini,
            "by_category": by_category,
        }
    except Exception:
        raise HTTPException(status_code=503, detail="Database unavailable, try again shortly")
    finally:
        if conn is not None:
            conn.close()


@app.get("/api/attack-patterns")
def attack_patterns() -> dict:
    """Attack category breakdown, with each category's top source country."""
    conn = None
    try:
        conn = db_connection()
        cur = conn.cursor()

        cur.execute("SELECT COUNT(*) FROM THREAT_EVENTS")
        total = cur.fetchone()[0]

        cur.execute(
            "SELECT CATEGORY, COUNT(*) FROM THREAT_EVENTS WHERE CATEGORY IS NOT NULL "
            "GROUP BY CATEGORY ORDER BY 2 DESC"
        )
        category_counts = cur.fetchall()
        total_categorized = sum(c for _, c in category_counts)
        pct_categorized = round(total_categorized / total * 100, 1) if total else 0.0

        cur.execute("""
            SELECT DISTINCT ON (CATEGORY) CATEGORY, COUNTRY_CODE, n
            FROM (
                SELECT CATEGORY, COUNTRY_CODE, COUNT(*) AS n
                FROM THREAT_EVENTS
                WHERE CATEGORY IS NOT NULL AND COUNTRY_CODE IS NOT NULL
                GROUP BY CATEGORY, COUNTRY_CODE
            ) counted
            ORDER BY CATEGORY, n DESC
            """)
        top_country_by_category = {row[0]: {"country": row[1], "count": row[2]} for row in cur.fetchall()}

        categories = [
            {
                "category": cat,
                "count": count,
                "pct_of_categorized": round(count / total_categorized * 100, 1) if total_categorized else 0.0,
                "top_country": top_country_by_category.get(cat),
                "tactic": (MITRE_MAP.get(cat) or (None,))[0],
            }
            for cat, count in category_counts
        ]

        return {
            "total": total,
            "total_categorized": total_categorized,
            "pct_categorized_of_total": pct_categorized,
            "categories": categories,
        }
    except Exception:
        raise HTTPException(status_code=503, detail="Database unavailable, try again shortly")
    finally:
        if conn is not None:
            conn.close()


@app.get("/api/history")
def history(
    page: int = 1,
    page_size: int = 25,
    country: str | None = None,
    risk: str | None = None,
    sort: str = "loaded_at",
) -> dict:
    page = max(1, page)
    page_size = max(1, min(page_size, 100))
    offset = (page - 1) * page_size
    sort_column = {
        "loaded_at": "LOADED_AT",
        "score": "ABUSE_CONFIDENCE_SCORE",
        "reported_at": "LAST_REPORTED_AT",
        "ip": "IP",
        "country": "COUNTRY_CODE",
    }.get(sort, "LOADED_AT")

    conn = None
    try:
        conn = db_connection()
        cur = conn.cursor()
        where_clauses = []
        params: list[str] = []
        if country:
            where_clauses.append("COUNTRY_CODE = %s")
            params.append(country)
        if risk:
            where_clauses.append("RISK_LEVEL = %s")
            params.append(risk)
        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

        cur.execute(f"SELECT COUNT(*) FROM THREAT_EVENTS {where_sql}", params)
        total = cur.fetchone()[0]

        cur.execute(
            f"""
            SELECT IP, COUNTRY_CODE, RISK_LEVEL, ABUSE_CONFIDENCE_SCORE,
                   LAST_REPORTED_AT, LOADED_AT
            FROM THREAT_EVENTS
            {where_sql}
            ORDER BY {sort_column} DESC
            LIMIT {page_size} OFFSET {offset}
            """,
            params,
        )
        items = [
            {
                "ip": r[0],
                "country_code": r[1],
                "risk_level": r[2],
                "abuse_confidence_score": r[3],
                "last_reported_at": str(r[4]) if r[4] else None,
                "loaded_at": str(r[5]) if r[5] else None,
            }
            for r in cur.fetchall()
        ]
        return {"items": items, "total": total, "page": page, "page_size": page_size}
    except Exception:
        raise HTTPException(status_code=503, detail="Database unavailable, try again shortly")
    finally:
        if conn is not None:
            conn.close()


@app.get("/api/repeat-offenders")
def repeat_offenders(page: int = 1, page_size: int = 20) -> dict:
    page = max(1, page)
    page_size = max(1, min(page_size, 100))
    offset = (page - 1) * page_size

    conn = None
    try:
        conn = db_connection()
        cur = conn.cursor()

        cur.execute("SELECT COUNT(*) FROM (SELECT IP FROM THREAT_EVENTS GROUP BY IP HAVING COUNT(*) > 1)")
        total = cur.fetchone()[0]

        cur.execute(
            "SELECT COUNT(*) FROM (SELECT IP FROM THREAT_EVENTS GROUP BY IP HAVING COUNT(DISTINCT SOURCE) >= 2)"
        )
        cross_source_total = cur.fetchone()[0]

        cur.execute(f"""
            SELECT IP, MAX(COUNTRY_CODE) AS country_code, COUNT(*) AS report_count,
                   COUNT(DISTINCT SOURCE) AS source_count, ARRAY_AGG(DISTINCT SOURCE) AS sources,
                   MAX(ABUSE_CONFIDENCE_SCORE) AS max_score, MAX(LAST_REPORTED_AT) AS last_reported_at
            FROM THREAT_EVENTS
            GROUP BY IP
            HAVING COUNT(*) > 1
            ORDER BY source_count DESC, report_count DESC
            LIMIT {page_size} OFFSET {offset}
            """)
        items = [
            {
                "ip": r[0],
                "country_code": r[1],
                "report_count": r[2],
                "source_count": r[3],
                "sources": r[4] or [],
                "max_score": r[5],
                "last_reported_at": str(r[6]) if r[6] else None,
            }
            for r in cur.fetchall()
        ]
        return {
            "items": items,
            "total": total,
            "cross_source_total": cross_source_total,
            "page": page,
            "page_size": page_size,
        }
    except Exception:
        raise HTTPException(status_code=503, detail="Database unavailable, try again shortly")
    finally:
        if conn is not None:
            conn.close()


@app.get("/api/infrastructure-clusters")
def infrastructure_clusters(limit: int = 15) -> dict:
    """Groups flagged IPs by /24 subnet: 3+ distinct malicious IPs in the same
    block is a stronger signal to block the range than any single IP."""
    limit = max(1, min(limit, 50))
    conn = None
    try:
        conn = db_connection()
        cur = conn.cursor()
        cur.execute(f"""
            SELECT
                SPLIT_PART(IP, '.', 1) || '.' || SPLIT_PART(IP, '.', 2) || '.'
                    || SPLIT_PART(IP, '.', 3) || '.0/24' AS subnet,
                COUNT(DISTINCT IP) AS ip_count,
                MAX(COUNTRY_CODE) AS country_code,
                ARRAY_AGG(DISTINCT SOURCE) AS sources,
                MAX(ABUSE_CONFIDENCE_SCORE) AS max_score,
                ARRAY_AGG(DISTINCT IP ORDER BY IP) AS ips
            FROM THREAT_EVENTS
            WHERE IP ~ '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$'
            GROUP BY subnet
            HAVING COUNT(DISTINCT IP) >= 3
            ORDER BY ip_count DESC
            LIMIT {limit}
            """)
        clusters = [
            {
                "subnet": r[0],
                "ip_count": r[1],
                "country_code": r[2],
                "sources": sorted(r[3] or []),
                "max_score": r[4],
                "sample_ips": (r[5] or [])[:8],
            }
            for r in cur.fetchall()
        ]
        return {"clusters": clusters}
    except Exception:
        raise HTTPException(status_code=503, detail="Database unavailable, try again shortly")
    finally:
        if conn is not None:
            conn.close()


@app.get("/api/pipeline-health")
def pipeline_health() -> dict:
    conn = None
    try:
        conn = db_connection()
        cur = conn.cursor()

        cur.execute(
            "SELECT DATE_TRUNC('minute', LOADED_AT) AS batch, COUNT(*) AS n "
            "FROM THREAT_EVENTS GROUP BY batch ORDER BY batch DESC LIMIT 20"
        )
        batches = [{"loaded_at": str(r[0]), "count": r[1]} for r in cur.fetchall()]

        cur.execute(
            "SELECT ROUND((AVG(CASE WHEN LATITUDE != 0 AND LONGITUDE != 0 THEN 1 ELSE 0 END) * 100)::numeric, 1) "
            "FROM THREAT_EVENTS"
        )
        pct_valid_geo = cur.fetchone()[0]

        cur.execute("SELECT SOURCE, COUNT(*) FROM THREAT_EVENTS GROUP BY SOURCE ORDER BY 2 DESC")
        by_source = [{"source": r[0], "count": r[1]} for r in cur.fetchall()]

        cur.execute("SELECT COUNT(DISTINCT DATE_TRUNC('minute', LOADED_AT)) FROM THREAT_EVENTS")
        batch_count = cur.fetchone()[0]

        cur.execute(
            "SELECT "
            "  percentile_cont(0.5) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (LOADED_AT - EVENT_TIME))), "
            "  percentile_cont(0.95) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (LOADED_AT - EVENT_TIME))), "
            "  COUNT(*) "
            "FROM THREAT_EVENTS WHERE EVENT_TIME IS NOT NULL"
        )
        p50, p95, latency_sample_size = cur.fetchone()

        cur.execute("SELECT COUNT(*) FROM THREAT_EVENTS WHERE LOADED_AT > NOW() - INTERVAL '10 minutes'")
        recent_10min = cur.fetchone()[0]

        cur.execute(
            "SELECT "
            "  COUNT(*), "
            "  COUNT(*) FILTER (WHERE COUNTRY_CODE IS NULL OR LENGTH(COUNTRY_CODE) != 2), "
            "  COUNT(*) FILTER (WHERE ABUSE_CONFIDENCE_SCORE IS NOT NULL "
            "    AND (ABUSE_CONFIDENCE_SCORE < 0 OR ABUSE_CONFIDENCE_SCORE > 100)), "
            "  COUNT(*) FILTER (WHERE RISK_LEVEL NOT IN ('low','medium','high','critical')), "
            "  COUNT(*) - COUNT(DISTINCT (IP, SOURCE, LAST_REPORTED_AT)) "
            "FROM THREAT_EVENTS"
        )
        total, bad_country, bad_score, bad_risk, exact_dupes = cur.fetchone()

        cur.execute(
            "SELECT data_type FROM information_schema.columns "
            "WHERE table_name = 'threat_events' AND column_name = 'last_reported_at'"
        )
        lra_row = cur.fetchone()
        lra_is_text = bool(lra_row and lra_row[0] == "text")

        def quality_check(name: str, failed: int, description: str) -> dict:
            pct = round(failed / total * 100, 2) if total else 0.0
            status = "pass" if failed == 0 else ("warn" if pct < 1 else "fail")
            return {
                "name": name,
                "status": status,
                "failed": failed,
                "total": total,
                "pct": pct,
                "description": description,
            }

        quality_checks = [
            quality_check(
                "Country code completeness",
                bad_country,
                "Null or malformed COUNTRY_CODE. Those records can't be geo-prioritized.",
            ),
            quality_check("Score range", bad_score, "ABUSE_CONFIDENCE_SCORE must fall within 0-100."),
            quality_check("Risk level enum", bad_risk, "RISK_LEVEL must be one of low/medium/high/critical."),
            quality_check(
                "Exact duplicates", exact_dupes, "Same IP+source+report-time ingested more than once."
            ),
            {
                "name": "Schema: LAST_REPORTED_AT type",
                "status": "warn" if lra_is_text else "pass",
                "failed": 1 if lra_is_text else 0,
                "total": 1,
                "pct": 100.0 if lra_is_text else 0.0,
                "description": "Stored as TEXT instead of TIMESTAMPTZ. Works via implicit cast today but "
                "should be fixed before more time-based analytics build on it.",
            },
        ]

        return {
            "recent_batches": batches,
            "total_batches": batch_count,
            "pct_valid_geo": float(pct_valid_geo) if pct_valid_geo is not None else None,
            "by_source": by_source,
            "latency_p50_seconds": round(p50, 1) if p50 is not None else None,
            "latency_p95_seconds": round(p95, 1) if p95 is not None else None,
            "latency_sample_size": latency_sample_size,
            "throughput_per_min": round(recent_10min / 10, 1),
            "quality_checks": quality_checks,
        }
    except Exception:
        raise HTTPException(status_code=503, detail="Database unavailable, try again shortly")
    finally:
        if conn is not None:
            conn.close()


@app.get("/api/pipeline-metrics")
def pipeline_metrics() -> dict:
    """Spark Structured Streaming micro-batch write metrics."""
    conn = None
    try:
        conn = db_connection()
        cur = conn.cursor()
        cur.execute(
            "SELECT BATCH_ID, BATCH_ROWS, WRITE_DURATION_MS, RECORDED_AT "
            "FROM PIPELINE_METRICS ORDER BY RECORDED_AT DESC LIMIT 20"
        )
        rows = cur.fetchall()
        batches = [
            {
                "batch_id": r[0],
                "rows": r[1],
                "write_duration_ms": round(r[2], 1),
                "rows_per_sec": round(r[1] / (r[2] / 1000), 1) if r[2] else None,
                "recorded_at": str(r[3]),
            }
            for r in rows
        ]
        cur.execute(
            "SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY WRITE_DURATION_MS), "
            "percentile_cont(0.95) WITHIN GROUP (ORDER BY WRITE_DURATION_MS), COUNT(*) "
            "FROM PIPELINE_METRICS"
        )
        p50, p95, sample_size = cur.fetchone()
        return {
            "recent_batches": batches,
            "write_duration_p50_ms": round(p50, 1) if p50 is not None else None,
            "write_duration_p95_ms": round(p95, 1) if p95 is not None else None,
            "sample_size": sample_size,
            "trigger_interval": "5 minutes",
        }
    except Exception:
        raise HTTPException(status_code=503, detail="Database unavailable, try again shortly")
    finally:
        if conn is not None:
            conn.close()


MODEL_METRICS_PATH = os.path.join(os.path.dirname(__file__), "..", "ml", "model_metrics.json")


@app.get("/api/ml/model-info")
def ml_model_info() -> dict:
    """Reoffense model training metrics plus a live-scored-rows count."""
    try:
        with open(MODEL_METRICS_PATH) as f:
            metrics = json.load(f)
    except FileNotFoundError:
        raise HTTPException(
            status_code=503,
            detail="No trained model found. Run ml/train_reoffense_model.py first.",
        )

    conn = None
    try:
        conn = db_connection()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*), COUNT(REOFFENSE_PROBABILITY) FROM THREAT_EVENTS")
        total, scored = cur.fetchone()
        metrics["live_scored_count"] = scored
        metrics["live_total_count"] = total
    except Exception:
        metrics["live_scored_count"] = None
        metrics["live_total_count"] = None
    finally:
        if conn is not None:
            conn.close()

    return metrics


ANOMALY_METRICS_PATH = os.path.join(os.path.dirname(__file__), "..", "ml", "anomaly_metrics.json")
_anomaly_percentiles: list[float] | None = None
_anomaly_percentiles_loaded = False


def unusual_pct(score: float | None) -> int | None:
    """Converts a raw IsolationForest score into "more unusual than X% of
    events", via the 101 percentile breakpoints saved at training time."""
    global _anomaly_percentiles, _anomaly_percentiles_loaded
    if score is None:
        return None
    if not _anomaly_percentiles_loaded:
        _anomaly_percentiles_loaded = True
        try:
            with open(ANOMALY_METRICS_PATH) as f:
                _anomaly_percentiles = json.load(f).get("score_percentiles")
        except FileNotFoundError:
            _anomaly_percentiles = None
    if not _anomaly_percentiles:
        return None
    percentile = bisect.bisect_right(_anomaly_percentiles, score)
    return max(0, min(100, 100 - percentile))


@app.get("/api/ml/anomaly-info")
def ml_anomaly_info() -> dict:
    """Anomaly (IsolationForest) model metrics, same shape as /api/ml/model-info."""
    try:
        with open(ANOMALY_METRICS_PATH) as f:
            metrics = json.load(f)
    except FileNotFoundError:
        raise HTTPException(
            status_code=503,
            detail="No trained anomaly model found. Run ml/train_anomaly_model.py first.",
        )
    metrics.pop("score_percentiles", None)

    conn = None
    try:
        conn = db_connection()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*), COUNT(ANOMALY_SCORE) FROM THREAT_EVENTS")
        total, scored = cur.fetchone()
        metrics["live_scored_count"] = scored
        metrics["live_total_count"] = total
    except Exception:
        metrics["live_scored_count"] = None
        metrics["live_total_count"] = None
    finally:
        if conn is not None:
            conn.close()

    return metrics


def rarest_feature_reason(
    source: str | None,
    country: str | None,
    category: str | None,
    source_counts: dict,
    country_counts: dict,
    category_counts: dict,
    total: int,
) -> str | None:
    """Approximates "why was this flagged" as whichever of source/country/
    category is rarest across the dataset. Not true SHAP-style attribution."""
    if total == 0:
        return None
    candidates = []
    if source:
        candidates.append(("source", source, source_counts.get(source, 0)))
    if country:
        candidates.append(("country", country, country_counts.get(country, 0)))
    if category:
        candidates.append(("category", category, category_counts.get(category, 0)))
    else:
        candidates.append(("category", "uncategorized", category_counts.get(None, 0)))
    if not candidates:
        return None
    label, value, count = min(candidates, key=lambda c: c[2])
    pct = count / total * 100
    if pct >= 5:
        return None
    pct_label = "<0.1%" if pct < 0.1 else f"{pct:.1f}%"
    return f"{label} '{value}' seen in only {pct_label} of all traffic"


@app.get("/api/anomalies")
def anomalies(limit: int = 8) -> dict:
    """Most statistically unusual events in the recent window, ranked by
    ANOMALY_SCORE (lower = more anomalous)."""
    conn = None
    try:
        conn = db_connection()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT IP, SOURCE, COUNTRY_CODE, CATEGORY, RISK_LEVEL, ABUSE_CONFIDENCE_SCORE,
                   ANOMALY_SCORE, LOADED_AT
            FROM (SELECT * FROM THREAT_EVENTS ORDER BY LOADED_AT DESC LIMIT 2000) recent
            WHERE ANOMALY_SCORE IS NOT NULL
            ORDER BY ANOMALY_SCORE ASC
            LIMIT %s
            """,
            (limit,),
        )
        rows = cur.fetchall()

        cur.execute("SELECT COUNT(*) FROM THREAT_EVENTS")
        total = cur.fetchone()[0]
        cur.execute("SELECT SOURCE, COUNT(*) FROM THREAT_EVENTS GROUP BY SOURCE")
        source_counts = dict(cur.fetchall())
        cur.execute("SELECT COUNTRY_CODE, COUNT(*) FROM THREAT_EVENTS GROUP BY COUNTRY_CODE")
        country_counts = dict(cur.fetchall())
        cur.execute("SELECT CATEGORY, COUNT(*) FROM THREAT_EVENTS GROUP BY CATEGORY")
        category_counts = dict(cur.fetchall())

        return {
            "items": [
                {
                    "ip": r[0],
                    "source": r[1],
                    "country_code": r[2],
                    "category": r[3],
                    "risk_level": r[4],
                    "abuse_confidence_score": r[5],
                    "anomaly_score": r[6],
                    "unusual_pct": unusual_pct(r[6]),
                    "loaded_at": str(r[7]),
                    "why": rarest_feature_reason(
                        r[1], r[2], r[3], source_counts, country_counts, category_counts, total
                    ),
                }
                for r in rows
            ],
        }
    except Exception:
        raise HTTPException(status_code=503, detail="Database unavailable, try again shortly")
    finally:
        if conn is not None:
            conn.close()


@app.get("/api/trends")
def trends(limit: int = 200) -> dict:
    """Full BRIEFING_SNAPSHOTS time series (written at most once/hour)."""
    conn = None
    try:
        conn = db_connection()
        cur = conn.cursor()
        cur.execute(
            "SELECT RECORDED_AT, GINI_COEFFICIENT, CROSS_SOURCE_PCT, CATEGORIZED_PCT "
            "FROM BRIEFING_SNAPSHOTS ORDER BY RECORDED_AT ASC LIMIT %s",
            (limit,),
        )
        rows = cur.fetchall()
        return {
            "snapshots": [
                {"recorded_at": str(r[0]), "gini": r[1], "cross_source_pct": r[2], "categorized_pct": r[3]}
                for r in rows
            ],
        }
    except Exception:
        raise HTTPException(status_code=503, detail="Database unavailable, try again shortly")
    finally:
        if conn is not None:
            conn.close()


@app.get("/api/briefing")
def briefing() -> dict:
    """Written analysis and ranked action list, computed live from THREAT_EVENTS."""
    conn = None
    try:
        conn = db_connection()
        cur = conn.cursor()

        cur.execute("SELECT COUNT(*) FROM THREAT_EVENTS")
        total = cur.fetchone()[0]

        cur.execute(
            "SELECT COUNTRY_CODE, COUNT(*) AS c FROM THREAT_EVENTS " "GROUP BY COUNTRY_CODE ORDER BY c DESC"
        )
        by_country = [(row[0], row[1]) for row in cur.fetchall()]
        gini, _ = compute_gini_and_lorenz([c for _, c in by_country])
        top_country, top_count = by_country[0]
        top_pct = round(top_count / total * 100, 1) if total else 0

        cur.execute("""
            WITH offender_counts AS (
                SELECT IP, COUNT(*) AS report_count FROM THREAT_EVENTS GROUP BY IP
            )
            SELECT COUNT(*), MAX(report_count) FROM offender_counts WHERE report_count > 1
            """)
        repeat_count, max_repeats = cur.fetchone()
        repeat_pct = round(repeat_count / total * 100, 1) if total else 0

        cur.execute(
            "SELECT COUNT(*) FROM (SELECT IP FROM THREAT_EVENTS GROUP BY IP HAVING COUNT(DISTINCT SOURCE) >= 2)"
        )
        cross_source_count = cur.fetchone()[0]

        cur.execute("SELECT SOURCE, COUNT(*) FROM THREAT_EVENTS GROUP BY SOURCE")
        sources = cur.fetchall()

        cur.execute("SELECT MAX(LOADED_AT) FROM THREAT_EVENTS")
        last_loaded = cur.fetchone()[0]

        cross_source_pct = round(cross_source_count / total * 100, 1) if total else 0.0

        cur.execute(
            "SELECT RECORDED_AT, GINI_COEFFICIENT, CROSS_SOURCE_PCT, "
            "EXTRACT(EPOCH FROM (NOW() - RECORDED_AT)) / 60 AS age_minutes "
            "FROM BRIEFING_SNAPSHOTS ORDER BY RECORDED_AT DESC LIMIT 1"
        )
        prev_snapshot = cur.fetchone()
        cur.execute(
            "SELECT MAX(RECORDED_AT) IS NULL OR MAX(RECORDED_AT) < NOW() - INTERVAL '1 hour' FROM BRIEFING_SNAPSHOTS"
        )
        should_snapshot = cur.fetchone()[0]

        def age_label(age_minutes: float) -> str:
            if age_minutes < 90:
                return f"{round(age_minutes)}min ago"
            return f"{round(age_minutes / 60, 1)}h ago"

        def trend_suffix(current: float, previous: float | None, unit: str = "pts") -> str:
            if previous is None:
                return ""
            delta = round(current - previous, 2)
            if abs(delta) < 0.05:
                return ""
            when = age_label(prev_snapshot[3])
            arrow = "↑" if delta > 0 else "↓"
            return f" ({arrow}{abs(delta)}{unit} vs {when})"

        prev_gini = prev_snapshot[1] if prev_snapshot else None
        prev_cross_source_pct = prev_snapshot[2] if prev_snapshot else None

        recommendations = []
        limitations = []

        top5_countries = [c for c, _ in by_country[:5]]
        top5_cum_pct = round(sum(c for _, c in by_country[:5]) / total * 100, 1) if total else 0
        top5_label = (
            ", ".join(top5_countries[:-1]) + f" and {top5_countries[-1]}"
            if len(top5_countries) > 1
            else (top5_countries[0] if top5_countries else "")
        )
        recommendations.append(
            {
                "priority": "high",
                "action": f"Write geo-based rate-limit or block rules for {top5_label} first",
                "impact": f"These 5 countries alone account for {top5_cum_pct}% of all traffic, "
                f"the fewest rules for the most coverage{trend_suffix(gini, prev_gini, ' Gini')}.",
                "exhibit_id": "exhibit-geo",
            }
        )

        if max_repeats and max_repeats <= 3:
            limitations.append(
                f"{repeat_count:,} IPs ({repeat_pct}%) repeated, but never more than {max_repeats}×, so "
                "corroboration is a weak signal on this dataset so far."
            )

        if cross_source_count > 0:
            recommendations.append(
                {
                    "priority": "high",
                    "action": f"Block the {cross_source_count:,} cross-source-corroborated IPs now",
                    "impact": f"Lowest false-positive risk of any signal available"
                    f"{trend_suffix(cross_source_pct, prev_cross_source_pct)}.",
                    "exhibit_id": "exhibit-corroboration",
                }
            )
        else:
            recommendations.append(
                {
                    "priority": "medium",
                    "action": f"Block all {repeat_count:,} persistently-flagged IPs",
                    "impact": "Strongest signal available until cross-source data accumulates.",
                    "exhibit_id": "exhibit-corroboration",
                }
            )

        if len(sources) <= 1:
            recommendations.append(
                {
                    "priority": "medium",
                    "action": "Add a second ingestion source (Spamhaus DROP, FireHOL)",
                    "impact": f"100% of data currently comes from {sources[0][0] if sources else 'one source'} alone. "
                    "Adding one closes that blind spot, no API key needed.",
                    "exhibit_id": "exhibit-pipeline",
                }
            )

        cur.execute(
            "SELECT CATEGORY, COUNT(*) FROM THREAT_EVENTS WHERE CATEGORY IS NOT NULL GROUP BY CATEGORY"
        )
        category_counts = cur.fetchall()
        total_categorized = sum(c for _, c in category_counts)
        pct_categorized_of_total = round(total_categorized / total * 100, 1) if total else 0.0

        if total_categorized > 0:
            tactic_counts: dict[str, int] = {}
            for cat, c in category_counts:
                m = MITRE_MAP.get(cat)
                if not m:
                    continue
                tactic = m[0]
                tactic_counts[tactic] = tactic_counts.get(tactic, 0) + c

            if tactic_counts:
                top_tactic, top_tactic_count = max(tactic_counts.items(), key=lambda kv: kv[1])
                pct_of_categorized = round(top_tactic_count / total_categorized * 100, 1)
                recommendation_text = TACTIC_RECOMMENDATIONS.get(top_tactic)

                if recommendation_text:
                    top_tactic_categories = [c for c, m in MITRE_MAP.items() if m[0] == top_tactic]
                    cur.execute(
                        "SELECT COUNT(DISTINCT IP) FROM THREAT_EVENTS WHERE CATEGORY = ANY(%s)",
                        (top_tactic_categories,),
                    )
                    top_tactic_ip_count = cur.fetchone()[0]

                    recommendations.append(
                        {
                            "priority": "medium",
                            "action": f"{recommendation_text} ({top_tactic_ip_count:,} IPs flagged so far)",
                            "impact": f"{pct_of_categorized}% of all categorized traffic maps to {top_tactic}, "
                            f"more than any other tactic. It's the single largest attack-type signal available.",
                            "exhibit_id": None,
                        }
                    )

        limitations += [
            f"Only {pct_categorized_of_total}% of events carry a known attack category. AbuseIPDB's bulk "
            "feed, most of this dataset, reports none at all.",
            "Pipeline latency figures (Data page) only cover live-ingested traffic. The historical backfill "
            "has no event timestamp to measure against.",
            "Live per-IP lookups depend on AbuseIPDB's free tier (1000/day). When exhausted, decisions fall "
            "back to this pipeline's own history alone.",
        ]

        if should_snapshot:
            cur.execute(
                "INSERT INTO BRIEFING_SNAPSHOTS (GINI_COEFFICIENT, TOP_COUNTRY_PCT, CROSS_SOURCE_PCT, CATEGORIZED_PCT) "
                "VALUES (%s, %s, %s, %s)",
                (gini, top_pct, cross_source_pct, pct_categorized_of_total),
            )
            conn.commit()

        return {
            "limitations": limitations,
            "trend_available": prev_snapshot is not None,
            "generated_at": str(last_loaded),
            "recommendations": recommendations,
        }
    except Exception:
        raise HTTPException(status_code=503, detail="Database unavailable, try again shortly")
    finally:
        if conn is not None:
            conn.close()


def fetch_local_history(ip: str) -> list[dict]:
    conn = db_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT COUNTRY_CODE, RISK_LEVEL, ABUSE_CONFIDENCE_SCORE, "
            "LAST_REPORTED_AT, LOADED_AT, SOURCE, REOFFENSE_PROBABILITY, CATEGORY FROM THREAT_EVENTS "
            "WHERE IP = %s ORDER BY LOADED_AT DESC LIMIT 50",
            (ip,),
        )
        rows = cur.fetchall()
        return [
            {
                "country_code": r[0],
                "risk_level": r[1],
                "abuse_confidence_score": r[2],
                "last_reported_at": r[3],
                "loaded_at": str(r[4]),
                "source": r[5],
                "reoffense_probability": r[6],
                "category": r[7],
            }
            for r in rows
        ]
    finally:
        conn.close()


def fetch_live_lookup(ip: str) -> dict | None:
    if not ABUSEIPDB_API_KEY:
        return None
    try:
        response = requests.get(
            ABUSEIPDB_CHECK_URL,
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
            timeout=10,
        )
        response.raise_for_status()
        data = response.json().get("data")
        if not data:
            return None
        recent_categories = []
        for report in (data.get("reports") or [])[:10]:
            for cat_id in report.get("categories", []):
                name = ABUSE_CATEGORIES.get(cat_id)
                if name and name not in recent_categories:
                    recent_categories.append(name)
        return {
            "country_code": data.get("countryCode"),
            "country_name": data.get("countryName"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "hostnames": data.get("hostnames") or [],
            "usage_type": data.get("usageType"),
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "num_distinct_users": data.get("numDistinctUsers"),
            "is_whitelisted": data.get("isWhitelisted"),
            "is_public": data.get("isPublic"),
            "is_tor": data.get("isTor"),
            "recent_categories": recent_categories,
        }
    except Exception:
        return None


def fetch_geo_precise(ip: str) -> dict | None:
    try:
        response = requests.get(
            IPAPI_URL.format(ip=ip),
            params={
                "fields": "status,country,countryCode,regionName,city,lat,lon,proxy,hosting,as,mobile,timezone"
            },
            timeout=10,
        )
        response.raise_for_status()
        data = response.json()
        if data.get("status") != "success":
            return None
        return {
            "city": data.get("city"),
            "region": data.get("regionName"),
            "lat": data.get("lat"),
            "lon": data.get("lon"),
            "is_proxy_or_vpn": data.get("proxy"),
            "is_hosting": data.get("hosting"),
            "is_mobile": data.get("mobile"),
            "asn": data.get("as"),
            "timezone": data.get("timezone"),
        }
    except Exception:
        return None


@app.get("/api/ip/{ip}")
def ip_lookup(ip: str) -> dict:
    try:
        local_history = fetch_local_history(ip)
    except Exception:
        local_history = []
    live_lookup = fetch_live_lookup(ip)
    geo = fetch_geo_precise(ip)
    if live_lookup is not None:
        live_lookup["geo"] = geo
    return {"ip": ip, "local_history": local_history, "live_lookup": live_lookup, "geo": geo}


@app.get("/api/attribution/{ip}")
def attribution(ip: str) -> dict:
    """Machine-facing endpoint: returns a block/monitor/insufficient_data
    decision for an IP, not just raw fields to re-interpret."""
    try:
        local_history = fetch_local_history(ip)
    except Exception:
        local_history = []
    live = fetch_live_lookup(ip)
    geo = fetch_geo_precise(ip)

    if live is None and not local_history:
        return {
            "ip": ip,
            "known_threat": False,
            "recommendation": "insufficient_data",
            "reason": "No record of this IP in AbuseIPDB or in GhostNet's own pipeline.",
            "source": "GhostNet",
        }

    score = live.get("abuse_confidence_score") if live else None
    reporters = live.get("num_distinct_users") if live else None
    reports = live.get("total_reports") if live else None
    categories = (live.get("recent_categories") if live else None) or []
    corroborating_sources = sorted({h["source"] for h in local_history if h.get("source")})

    mitre = []
    for cat in categories:
        m = MITRE_MAP.get(cat)
        if m:
            mitre.append({"category": cat, "tactic": m[0], "technique_id": m[1], "technique_name": m[2]})

    if score is not None and (
        (score >= 90 and (reporters or 0) >= 10) or (score >= 70 and (reporters or 0) >= 20)
    ):
        recommendation = "block"
        reason = (
            f"High confidence ({score}/100) with strong corroboration ({reporters} independent reporters)."
        )
    elif len(corroborating_sources) >= 2:
        recommendation = "block"
        reason = (
            f"Independently confirmed by {len(corroborating_sources)} separate threat-intel sources in "
            f"GhostNet's own pipeline ({', '.join(corroborating_sources)}). Cross-source agreement carries "
            "lower false-positive risk than relying on any single feed."
        )
    elif (score is not None and score >= 50) or (reporters or 0) >= 3:
        recommendation = "monitor"
        reason = f"Moderate signal (score={score}, reporters={reporters}), worth watching but not yet decisive."
    elif local_history:
        recommendation = "monitor"
        reason = f"Seen {len(local_history)} time(s) in GhostNet's own pipeline, but not independently corroborated by AbuseIPDB."
    elif score is not None and geo and geo.get("is_hosting"):
        recommendation = "monitor"
        reason = (
            f"Weak signal alone (score={score}) wouldn't warrant action, but this IP sits on rented "
            "datacenter/hosting infrastructure, a different risk profile than a residential compromise, "
            "worth monitoring rather than dismissing."
        )
    else:
        recommendation = "insufficient_data"
        reason = "Known but corroboration is too weak to act on automatically."

    return {
        "ip": ip,
        "known_threat": score is not None or len(local_history) > 0,
        "confidence_score": score,
        "distinct_reporters": reporters,
        "total_reports": reports,
        "seen_in_local_pipeline": len(local_history),
        "corroborating_sources": corroborating_sources,
        "categories": categories,
        "mitre_attack": mitre,
        "recommendation": recommendation,
        "reason": reason,
        "source": "GhostNet (AbuseIPDB + local Kafka/Spark/Postgres pipeline)",
    }


def decode_cidr_reports(reported: list[dict]) -> list[dict]:
    out = []
    for r in reported:
        out.append(
            {
                "ip": r.get("ipAddress"),
                "abuse_confidence_score": r.get("abuseConfidenceScore"),
                "total_reports": r.get("numReports"),
                "last_reported_at": r.get("mostRecentReport"),
            }
        )
    return out


@app.get("/api/cidr/{cidr:path}")
def cidr_lookup(cidr: str) -> dict:
    if not ABUSEIPDB_API_KEY:
        return {"error": "AbuseIPDB API key not configured"}
    try:
        response = requests.get(
            ABUSEIPDB_CHECK_BLOCK_URL,
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"network": cidr, "maxAgeInDays": 30},
            timeout=15,
        )
        response.raise_for_status()
        data = response.json().get("data")
        if not data:
            return {"error": "No data returned for this range"}
        reported = decode_cidr_reports(data.get("reportedAddress") or [])

        ips = [r["ip"] for r in reported if r.get("ip")]
        if ips:
            try:
                conn = db_connection()
                cur = conn.cursor()
                placeholders = ",".join(["%s"] * len(ips))
                cur.execute(
                    f"SELECT IP, COUNT(DISTINCT SOURCE) FROM THREAT_EVENTS "
                    f"WHERE IP IN ({placeholders}) GROUP BY IP",
                    ips,
                )
                source_counts = {row[0]: row[1] for row in cur.fetchall()}
                conn.close()
                for r in reported:
                    r["source_count"] = source_counts.get(r["ip"], 0)
            except Exception:
                for r in reported:
                    r["source_count"] = None

        return {
            "network_address": data.get("networkAddress"),
            "netmask": data.get("netmask"),
            "num_possible_hosts": data.get("numPossibleHosts"),
            "address_space": data.get("addressSpaceDesc"),
            "reported": reported,
        }
    except requests.RequestException as exc:
        return {"error": f"Lookup failed: {exc}"}


@app.websocket("/ws/live")
async def ws_live(websocket: WebSocket) -> None:
    await websocket.accept()
    connected_clients.add(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        connected_clients.discard(websocket)
