import api.main as main
from api.main import decode_cidr_reports, rarest_feature_reason, unusual_pct


def test_unusual_pct_none_score_returns_none():
    assert unusual_pct(None) is None


def _linear_percentiles():
    # Real breakpoints are 101 values (0th to 100th percentile, see
    # ml/train_anomaly_model.py) -- match that shape so bisecting against
    # it actually lands on a 0-100 scale like the real data does.
    return [-1.0 + i * 0.02 for i in range(101)]


def test_unusual_pct_lowest_score_is_most_unusual(monkeypatch):
    monkeypatch.setattr(main, "_anomaly_percentiles_loaded", True)
    monkeypatch.setattr(main, "_anomaly_percentiles", _linear_percentiles())
    assert unusual_pct(-1.1) == 100


def test_unusual_pct_highest_score_is_least_unusual(monkeypatch):
    monkeypatch.setattr(main, "_anomaly_percentiles_loaded", True)
    monkeypatch.setattr(main, "_anomaly_percentiles", _linear_percentiles())
    assert unusual_pct(1.0) == 0


def test_unusual_pct_missing_percentiles_returns_none(monkeypatch):
    monkeypatch.setattr(main, "_anomaly_percentiles_loaded", True)
    monkeypatch.setattr(main, "_anomaly_percentiles", None)
    assert unusual_pct(-0.5) is None


def test_rarest_feature_reason_zero_total_returns_none():
    assert rarest_feature_reason("abuseipdb", "US", "SSH", {}, {}, {}, 0) is None


def test_rarest_feature_reason_common_values_are_not_called_out():
    # every candidate field appears in >= 5% of traffic, so nothing is rare
    reason = rarest_feature_reason(
        "abuseipdb", "US", "SSH",
        {"abuseipdb": 500}, {"US": 500}, {"SSH": 500},
        total=1000,
    )
    assert reason is None


def test_rarest_feature_reason_flags_the_rarest_field():
    # country "MC" is the rarest of the three (0.5% of traffic)
    reason = rarest_feature_reason(
        "abuseipdb", "MC", "SSH",
        {"abuseipdb": 900}, {"MC": 5}, {"SSH": 900},
        total=1000,
    )
    assert reason == "country 'MC' seen in only 0.5% of all traffic"


def test_rarest_feature_reason_uses_uncategorized_when_no_category():
    reason = rarest_feature_reason(
        "abuseipdb", "MC", None,
        {"abuseipdb": 900}, {"MC": 50}, {None: 1},
        total=1000,
    )
    assert "category 'uncategorized'" in reason


def test_rarest_feature_reason_formats_sub_tenth_percent():
    reason = rarest_feature_reason(
        "rare_source", "US", "SSH",
        {"rare_source": 1}, {"US": 900}, {"SSH": 900},
        total=10000,
    )
    assert "<0.1%" in reason


def test_decode_cidr_reports_maps_abuseipdb_field_names():
    raw = [{
        "ipAddress": "1.2.3.4",
        "abuseConfidenceScore": 75,
        "numReports": 3,
        "mostRecentReport": "2026-01-01T00:00:00Z",
    }]
    decoded = decode_cidr_reports(raw)
    assert decoded == [{
        "ip": "1.2.3.4",
        "abuse_confidence_score": 75,
        "total_reports": 3,
        "last_reported_at": "2026-01-01T00:00:00Z",
    }]


def test_decode_cidr_reports_handles_missing_fields():
    decoded = decode_cidr_reports([{"ipAddress": "1.2.3.4"}])
    assert decoded == [{
        "ip": "1.2.3.4",
        "abuse_confidence_score": None,
        "total_reports": None,
        "last_reported_at": None,
    }]


def test_decode_cidr_reports_empty_list():
    assert decode_cidr_reports([]) == []
