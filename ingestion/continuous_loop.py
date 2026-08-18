import json
import random
import time

from kafka import KafkaProducer

from abuseipdb_producer import (
    KAFKA_BOOTSTRAP_SERVERS,
    TOPIC,
    fetch_blacklist,
    publish_to_kafka,
)

INTERVAL_SECONDS = 180
SAMPLE_SIZE = 15


def main() -> None:
    producer = KafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
    )
    print(f"Boucle demarree : un echantillon de {SAMPLE_SIZE} IPs toutes les {INTERVAL_SECONDS}s")
    while True:
        try:
            entries = fetch_blacklist()
            sample = random.sample(entries, min(SAMPLE_SIZE, len(entries)))
            publish_to_kafka(producer, sample)
            print(f"{len(sample)} IPs publiees sur '{TOPIC}'")
        except Exception as exc:
            print(f"Erreur pendant le cycle: {exc}")
        time.sleep(INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
