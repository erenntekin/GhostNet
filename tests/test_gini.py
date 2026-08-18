from api.main import compute_gini_and_lorenz


def test_empty_input_returns_zero():
    gini, lorenz = compute_gini_and_lorenz([])
    assert gini == 0.0
    assert lorenz == []


def test_all_zero_counts_returns_zero():
    gini, lorenz = compute_gini_and_lorenz([0, 0, 0])
    assert gini == 0.0
    assert lorenz == []


def test_perfectly_even_distribution_is_zero():
    gini, _ = compute_gini_and_lorenz([10, 10, 10, 10])
    assert gini == 0.0


def test_one_country_taking_everything_is_maximally_unequal():
    # Needs at least two entities to show inequality -- a single-country
    # list is trivially "even" (100% of countries have 100% of threats).
    gini, _ = compute_gini_and_lorenz([0, 0, 0, 100])
    assert gini > 0.7


def test_concentrated_distribution_scores_higher_than_spread_one():
    concentrated, _ = compute_gini_and_lorenz([1, 1, 1, 97])
    spread, _ = compute_gini_and_lorenz([25, 25, 25, 25])
    assert concentrated > spread


def test_lorenz_curve_starts_at_origin_and_ends_at_full_share():
    _, lorenz = compute_gini_and_lorenz([5, 15, 30, 50])
    assert lorenz[0] == {"pct_countries": 0.0, "pct_threats": 0.0}
    assert lorenz[-1] == {"pct_countries": 100.0, "pct_threats": 100.0}
