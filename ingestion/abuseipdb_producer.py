import json
import os
import time

import requests
from dotenv import load_dotenv
from kafka import KafkaProducer

load_dotenv()

ABUSEIPDB_API_KEY = os.environ["ABUSEIPDB_API_KEY"]
KAFKA_BOOTSTRAP_SERVERS = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
TOPIC = "threats.raw"

BLACKLIST_URL = "https://api.abuseipdb.com/api/v2/blacklist"


def fetch_blacklist(confidence_minimum: int = 25) -> list[dict]:
    response = requests.get(
        BLACKLIST_URL,
        headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
        params={"confidenceMinimum": confidence_minimum},
        timeout=30,
    )
    response.raise_for_status()
    return response.json()["data"]


def publish_to_kafka(producer: KafkaProducer, entries: list[dict]) -> None:
    for entry in entries:
        message = {
            "ip": entry["ipAddress"],
            "country_code": entry.get("countryCode"),
            "abuse_confidence_score": entry.get("abuseConfidenceScore"),
            "last_reported_at": entry.get("lastReportedAt"),
            "source": "abuseipdb",
            "ingested_at": time.time(),
            "category": None,
        }
        producer.send(TOPIC, key=entry["ipAddress"].encode("utf-8"), value=message)
    producer.flush()


def main() -> None:
    producer = KafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
    )
    entries = fetch_blacklist()
    publish_to_kafka(producer, entries)
    print(f"{len(entries)} IPs publiees sur le topic '{TOPIC}'")


if __name__ == "__main__":
    main()
