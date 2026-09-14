import json
import os
import time

import psycopg2
import requests
from dotenv import load_dotenv
from kafka import KafkaProducer

load_dotenv()

KAFKA_BOOTSTRAP_SERVERS = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
ENRICHED_TOPIC = "threats.enriched"
INTERVAL_SECONDS = 20
SAMPLE_SIZE = 3
CACHE_SIZE = 500
IPAPI_URL = "http://ip-api.com/json/{ip}"

geo_cache: dict[str, dict | None] = {}


def db_connection():
    return psycopg2.connect(
        host=os.environ.get("POSTGRES_HOST", "localhost"),
        port=os.environ.get("POSTGRES_PORT", "5432"),
        user=os.environ["POSTGRES_USER"],
        password=os.environ["POSTGRES_PASSWORD"],
        dbname=os.environ["POSTGRES_DB"],
    )


def fetch_pool() -> list[dict]:
    """One-shot fetch (at startup, not per-tick) of events to replay in
    chronological order. Restricted to rows no older than the earliest
    categorized event, so every source is in the mix from tick one instead
    of a long AbuseIPDB-only stretch before any categorized row plays."""
    conn = db_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            f"SELECT IP, COUNTRY_CODE, ABUSE_CONFIDENCE_SCORE, RISK_LEVEL, "
            f"LATITUDE, LONGITUDE, LAST_REPORTED_AT, SOURCE, CATEGORY "
            f"FROM (SELECT * FROM THREAT_EVENTS "
            f"WHERE LAST_REPORTED_AT >= (SELECT MIN(LAST_REPORTED_AT) FROM THREAT_EVENTS WHERE CATEGORY IS NOT NULL) "
            f"ORDER BY RANDOM() LIMIT {CACHE_SIZE}) sample "
            f"ORDER BY LAST_REPORTED_AT"
        )
        rows = cur.fetchall()
        return [
            {
                "ip": r[0],
                "country_code": r[1],
                "abuse_confidence_score": r[2],
                "risk_level": r[3],
                "latitude": r[4],
                "longitude": r[5],
                "last_reported_at": str(r[6]) if r[6] else None,
                "source": r[7],
                "known_category": r[8],
            }
            for r in rows
        ]
    finally:
        conn.close()


def geolocate(ip: str, fallback_lat: float, fallback_lon: float) -> tuple[float, float, str | None]:
    """Real per-IP city-level geolocation, cached so each IP only ever costs one API call."""
    if ip in geo_cache:
        cached = geo_cache[ip]
        if cached:
            return cached["lat"], cached["lon"], cached["city"]
        return fallback_lat, fallback_lon, None
    try:
        response = requests.get(
            IPAPI_URL.format(ip=ip),
            params={"fields": "status,city,lat,lon"},
            timeout=5,
        )
        data = response.json()
        if data.get("status") == "success" and data.get("lat") is not None:
            geo_cache[ip] = {"lat": data["lat"], "lon": data["lon"], "city": data.get("city")}
            return data["lat"], data["lon"], data.get("city")
    except requests.RequestException:
        pass
    geo_cache[ip] = None
    return fallback_lat, fallback_lon, None


def categorize(known_category: str | None) -> list[str]:
    """Category straight from ingestion, no live AbuseIPDB /check fallback:
    that used to burn the shared 1000/day quota and silently return nothing
    once exhausted (confirmed: 60/60 AbuseIPDB events got no category in one
    test hour). An uncategorized IP now just says so instead."""
    return [known_category] if known_category else []


def main() -> None:
    producer = KafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
    )
    print("Chargement initial du pool d'evenements depuis Postgres (une seule fois)...")
    pool = fetch_pool()
    print(
        f"Rejeu en direct : {SAMPLE_SIZE} evenements pris parmi {len(pool)} en cache, "
        f"dans l'ordre chronologique reel (LAST_REPORTED_AT), toutes les {INTERVAL_SECONDS}s, "
        f"vers '{ENRICHED_TOPIC}' (0 requete Postgres apres ce chargement initial)"
    )
    idx = 0
    while True:
        try:
            if not pool:
                time.sleep(INTERVAL_SECONDS)
                continue
            batch = [pool[(idx + i) % len(pool)] for i in range(min(SAMPLE_SIZE, len(pool)))]
            idx = (idx + SAMPLE_SIZE) % len(pool)
            for entry in batch:
                lat, lon, city = geolocate(entry["ip"], entry["latitude"], entry["longitude"])
                categories = categorize(entry.get("known_category"))
                message = {k: v for k, v in entry.items() if k != "known_category"} | {
                    "latitude": lat,
                    "longitude": lon,
                    "city": city,
                    "categories": categories,
                    "event_time": time.strftime("%Y-%m-%dT%H:%M:%S"),
                }
                producer.send(ENRICHED_TOPIC, key=entry["ip"].encode("utf-8"), value=message)
            producer.flush()
            print(
                f"{len(batch)} evenements rejoues (position {idx}/{len(pool)}, "
                f"geo cache: {len(geo_cache)} IPs)"
            )
        except Exception as exc:
            print(f"Erreur pendant le cycle: {exc}")
        time.sleep(INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
