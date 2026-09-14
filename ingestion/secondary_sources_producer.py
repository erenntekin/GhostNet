import json
import os
import time
from datetime import datetime, timezone

import psycopg2
import requests
from dotenv import load_dotenv
from kafka import KafkaProducer

load_dotenv()

KAFKA_BOOTSTRAP_SERVERS = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
TOPIC = "threats.raw"
IPAPI_URL = "http://ip-api.com/json/{ip}"
MAX_NEW_IPS_PER_SOURCE = 200

PROVIDERS = {
    "blocklistde": {
        "kind": "blocklistde_lists",
        "lists": {
            "bruteforcelogin": ("Brute-Force", 90.0),
            "ssh": ("SSH", 85.0),
            "bots": ("Bad Web Bot", 80.0),
            "mail": ("Email Spam", 75.0),
            "ftp": ("FTP Brute-Force", 80.0),
        },
    },
    "cinsscore": {
        "kind": "flat_list",
        "url": "http://cinsscore.com/list/ci-badguys.txt",
        "category": "Exploited Host",
        "score": 85.0,
    },
    "emergingthreats": {
        "kind": "flat_list",
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "category": "Exploited Host",
        "score": 85.0,
    },
}
BLOCKLISTDE_LIST_URL = "https://lists.blocklist.de/lists/{name}.txt"


def db_connection():
    return psycopg2.connect(
        host=os.environ.get("POSTGRES_HOST", "localhost"),
        port=os.environ.get("POSTGRES_PORT", "5432"),
        user=os.environ["POSTGRES_USER"],
        password=os.environ["POSTGRES_PASSWORD"],
        dbname=os.environ["POSTGRES_DB"],
    )


def fetch_known_ips(source: str) -> set[str]:
    """IPs already ingested from this source in a prior run, so re-runs only
    process genuinely new addresses instead of re-geolocating everything."""
    conn = db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT DISTINCT IP FROM THREAT_EVENTS WHERE SOURCE = %s", (source,))
        return {r[0] for r in cur.fetchall()}
    finally:
        conn.close()


def fetch_text_list(url: str) -> list[str]:
    response = requests.get(url, timeout=20, headers={"User-Agent": "GhostNet-Ingestion/1.0"})
    response.raise_for_status()
    lines = []
    for raw in response.text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        lines.append(line.split()[0])  # some feeds append comments after the IP
    return lines


def geolocate_country(ip: str) -> str | None:
    try:
        response = requests.get(IPAPI_URL.format(ip=ip), params={"fields": "status,countryCode"}, timeout=5)
        data = response.json()
        if data.get("status") == "success":
            return data.get("countryCode")
    except requests.RequestException:
        pass
    return None


def publish(
    producer: KafkaProducer, ip: str, country: str | None, score: float, source: str, category: str
) -> None:
    message = {
        "ip": ip,
        "country_code": country,
        "abuse_confidence_score": score,
        "last_reported_at": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "ingested_at": time.time(),
        "category": category,
    }
    producer.send(TOPIC, key=ip.encode("utf-8"), value=message)


def run_blocklistde(producer: KafkaProducer, cfg: dict) -> int:
    source = "blocklistde"
    known = fetch_known_ips(source)
    print(f"[{source}] {len(known)} IPs deja en base pour cette source.")

    per_list_cap = max(1, MAX_NEW_IPS_PER_SOURCE // len(cfg["lists"]))
    new_count = 0
    for list_name, (category, score) in cfg["lists"].items():
        try:
            ips = fetch_text_list(BLOCKLISTDE_LIST_URL.format(name=list_name))
        except requests.RequestException as exc:
            print(f"[{source}] erreur en recuperant la liste '{list_name}': {exc}")
            continue

        list_new_count = 0
        for ip in ips:
            if list_new_count >= per_list_cap:
                break
            if ip in known:
                continue
            known.add(ip)
            country = geolocate_country(ip)
            time.sleep(1.4)  # stay well under ip-api's ~45 req/min free-tier limit
            publish(producer, ip, country, score, source, category)
            list_new_count += 1
            new_count += 1
        print(f"[{source}] liste '{list_name}': {list_new_count} nouvelles IPs.")

    return new_count


def run_flat_list(producer: KafkaProducer, source: str, cfg: dict) -> int:
    known = fetch_known_ips(source)
    print(f"[{source}] {len(known)} IPs deja en base pour cette source.")

    try:
        ips = fetch_text_list(cfg["url"])
    except requests.RequestException as exc:
        print(f"[{source}] erreur en recuperant la liste: {exc}")
        return 0

    new_count = 0
    for ip in ips:
        if new_count >= MAX_NEW_IPS_PER_SOURCE:
            break
        if ip in known:
            continue
        known.add(ip)
        country = geolocate_country(ip)
        time.sleep(1.4)
        publish(producer, ip, country, cfg["score"], source, cfg["category"])
        new_count += 1

    return new_count


INTERVAL_SECONDS = 1800


def run_once(producer: KafkaProducer) -> int:
    total = 0
    for source, cfg in PROVIDERS.items():
        if cfg["kind"] == "blocklistde_lists":
            total += run_blocklistde(producer, cfg)
        else:
            total += run_flat_list(producer, source, cfg)
    producer.flush()
    return total


def main() -> None:
    producer = KafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
    )
    print(f"Boucle demarree : blocklist.de + CINS + Emerging Threats toutes les {INTERVAL_SECONDS}s")
    while True:
        try:
            total = run_once(producer)
            print(f"{total} nouvelles IPs publiees sur '{TOPIC}' (toutes sources secondaires confondues)")
        except Exception as exc:
            print(f"Erreur pendant le cycle: {exc}")
        time.sleep(INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
