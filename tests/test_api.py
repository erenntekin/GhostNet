"""Integration tests: hit the real FastAPI app against the real Postgres
instance (docker-compose's postgres service, reachable on localhost like
any other host-side script in this project -- see .env.example). These
don't touch Kafka: TestClient(app) without the `with` context manager
never fires the startup event that spawns the consumer thread.
"""

import pytest
from fastapi.testclient import TestClient

from api.main import app

client = TestClient(app)


def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_summary_shape():
    response = client.get("/api/summary")
    assert response.status_code == 200
    body = response.json()
    assert isinstance(body["total"], int)
    assert isinstance(body["top_countries"], list)
    assert 0.0 <= body["gini_coefficient"] <= 1.0
    if body["top_countries"]:
        assert {"country", "count"} <= body["top_countries"][0].keys()


def test_attack_patterns_percentages_are_consistent():
    response = client.get("/api/attack-patterns")
    assert response.status_code == 200
    body = response.json()
    assert isinstance(body["categories"], list)
    for category in body["categories"]:
        assert 0 <= category["pct_of_categorized"] <= 100


def test_repeat_offenders_pagination():
    response = client.get("/api/repeat-offenders?page=1&page_size=5")
    assert response.status_code == 200
    body = response.json()
    assert len(body["items"]) <= 5


def test_ip_lookup_degrades_gracefully_on_malformed_input():
    # No local format validation -- a bad IP is passed straight through to
    # local history / external lookups, which fail soft (None), rather than
    # a 4xx. This asserts that documented behavior, not validation that
    # doesn't exist.
    response = client.get("/api/ip/not-an-ip")
    assert response.status_code == 200
    body = response.json()
    assert body["ip"] == "not-an-ip"
    assert body["local_history"] == []


@pytest.mark.parametrize("cidr", ["10.0.0.0/24", "192.168.1.0/24"])
def test_cidr_lookup_accepts_valid_cidr_notation(cidr):
    response = client.get(f"/api/cidr/{cidr}")
    assert response.status_code == 200
