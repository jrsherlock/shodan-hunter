"""Unit tests for hunter.shodan_api.

Every test stubs the network: ``_api`` returns a fake ``shodan.Shodan`` and
``_rest_get`` returns canned dicts. We assert credit accounting (via the temp
DB counter) and cache behavior (via mock call counts / the ``_cache`` marker).
"""

from __future__ import annotations

import shodan

from hunter import config, db, shodan_api


# ── search: 1 credit on miss, free on cache hit ──────────────────────────────


def test_search_spends_one_credit_on_miss(patch_api):
    patch_api.search.return_value = {"total": 3, "matches": []}
    assert db.credits_used_today() == 0

    res = shodan_api.search("apache port:443")
    assert res["_cache"] == "miss"
    assert res["total"] == 3
    assert db.credits_used_today() == 1
    patch_api.search.assert_called_once()


def test_search_cache_hit_is_free(patch_api):
    patch_api.search.return_value = {"total": 3, "matches": []}

    first = shodan_api.search("apache port:443")
    assert first["_cache"] == "miss"
    assert db.credits_used_today() == 1

    second = shodan_api.search("apache port:443")
    assert second["_cache"] == "hit"
    # No additional credit spent and the API was not called a second time.
    assert db.credits_used_today() == 1
    patch_api.search.assert_called_once()


def test_search_normalizes_whitespace_for_cache_key(patch_api):
    patch_api.search.return_value = {"total": 1, "matches": []}
    shodan_api.search("apache   port:443")
    # extra internal whitespace collapses to the same key -> hit, no new credit
    res = shodan_api.search("apache port:443")
    assert res["_cache"] == "hit"
    assert db.credits_used_today() == 1


def test_search_wraps_api_error(patch_api):
    patch_api.search.side_effect = shodan.APIError("boom")
    try:
        shodan_api.search("whatever")
        raise AssertionError("expected ShodanError")
    except shodan_api.ShodanError as e:
        assert "boom" in str(e)
    # credit was spent before the call failed (matches app accounting expectations)
    assert db.credits_used_today() == 1


# ── count (FREE) ─────────────────────────────────────────────────────────────


def test_count_with_facets_caches_and_is_free(patch_api):
    patch_api.count.return_value = {
        "total": 42,
        "facets": {"port": [{"value": 80, "count": 5}]},
    }

    first = shodan_api.count("nginx", facets=["port"])
    assert first["_cache"] == "miss"
    assert first["total"] == 42

    second = shodan_api.count("nginx", facets=["port"])
    assert second["_cache"] == "hit"

    # count never spends a credit, and the cached second call skips the API.
    assert db.credits_used_today() == 0
    patch_api.count.assert_called_once()


def test_count_without_facets_not_cached(patch_api):
    patch_api.count.return_value = {"total": 7}
    shodan_api.count("nginx")
    shodan_api.count("nginx")
    # no facets -> no caching -> API hit twice, still free
    assert patch_api.count.call_count == 2
    assert db.credits_used_today() == 0


def test_facet_summary_returns_facets_map(patch_api):
    patch_api.count.return_value = {
        "total": 9,
        "facets": {"country": [{"value": "US", "count": 9}]},
    }
    out = shodan_api.facet_summary("apache", ["country"])
    assert out == {"country": [{"value": "US", "count": 9}]}
    assert db.credits_used_today() == 0


def test_facet_summary_empty_facets_short_circuits(patch_api):
    out = shodan_api.facet_summary("apache", [])
    assert out == {}
    patch_api.count.assert_not_called()


# ── honeyscore (FREE, cached) ────────────────────────────────────────────────


def test_honeyscore_returns_float_and_caches(patch_api):
    patch_api.labs.honeyscore.return_value = 0.7

    assert shodan_api.honeyscore("1.1.1.1") == 0.7
    # second call served from cache; fake not invoked again
    assert shodan_api.honeyscore("1.1.1.1") == 0.7
    patch_api.labs.honeyscore.assert_called_once()
    assert db.credits_used_today() == 0


def test_honeyscore_404_returns_none_and_caches_negative(patch_api):
    patch_api.labs.honeyscore.side_effect = shodan.APIError("No information available")

    assert shodan_api.honeyscore("8.8.8.8") is None
    # negative result cached -> not re-invoked
    assert shodan_api.honeyscore("8.8.8.8") is None
    patch_api.labs.honeyscore.assert_called_once()


def test_honeyscore_empty_ip_returns_none_without_call(patch_api):
    assert shodan_api.honeyscore("") is None
    assert shodan_api.honeyscore("   ") is None
    patch_api.labs.honeyscore.assert_not_called()


def test_honeyscore_non_404_api_error_raises(patch_api):
    patch_api.labs.honeyscore.side_effect = shodan.APIError("rate limited")
    try:
        shodan_api.honeyscore("5.5.5.5")
        raise AssertionError("expected ShodanError")
    except shodan_api.ShodanError as e:
        assert "rate limited" in str(e)


def test_honeyscore_many_dedupes_and_caps(patch_api):
    patch_api.labs.honeyscore.return_value = 0.3
    out = shodan_api.honeyscore_many(["1.1.1.1", "1.1.1.1", "2.2.2.2"], cap=5)
    assert out == {"1.1.1.1": 0.3, "2.2.2.2": 0.3}
    # de-duped to 2 unique IPs
    assert patch_api.labs.honeyscore.call_count == 2


# ── DNS resolve/reverse via monkeypatched _rest_get ──────────────────────────


def test_dns_resolve_parses_and_caches(monkeypatch):
    calls = []

    def fake_rest_get(path, params):
        calls.append((path, params))
        return {"a.com": "1.2.3.4", "b.com": "5.6.7.8"}

    monkeypatch.setattr(shodan_api, "_rest_get", fake_rest_get)

    out = shodan_api.dns_resolve(["a.com", "b.com"])
    assert out == {"a.com": "1.2.3.4", "b.com": "5.6.7.8"}
    assert calls[0][0] == "/dns/resolve"

    # second call is fully cached per-item -> no further REST hits
    out2 = shodan_api.dns_resolve(["a.com", "b.com"])
    assert out2 == out
    assert len(calls) == 1


def test_dns_reverse_parses_and_caches(monkeypatch):
    calls = []

    def fake_rest_get(path, params):
        calls.append(path)
        return {"1.2.3.4": ["host-a.example.com"], "5.6.7.8": []}

    monkeypatch.setattr(shodan_api, "_rest_get", fake_rest_get)

    out = shodan_api.dns_reverse(["1.2.3.4", "5.6.7.8"])
    assert out == {"1.2.3.4": ["host-a.example.com"], "5.6.7.8": []}
    assert calls == ["/dns/reverse"]

    out2 = shodan_api.dns_reverse(["1.2.3.4", "5.6.7.8"])
    assert out2 == out
    assert calls == ["/dns/reverse"]  # served from cache


def test_dns_resolve_missing_hostname_maps_to_none(monkeypatch):
    monkeypatch.setattr(shodan_api, "_rest_get", lambda path, params: {})
    out = shodan_api.dns_resolve(["nope.invalid"])
    assert out == {"nope.invalid": None}


# ── domain_info (1 credit, cached) ───────────────────────────────────────────


def test_domain_info_spends_credit_then_caches(patch_api):
    patch_api.dns.domain_info.return_value = {"domain": "acme.com", "subdomains": ["a"], "data": []}

    first = shodan_api.domain_info("ACME.com")
    assert first["_cache"] == "miss"
    assert db.credits_used_today() == 1

    second = shodan_api.domain_info("acme.com")
    assert second["_cache"] == "hit"
    assert db.credits_used_today() == 1
    patch_api.dns.domain_info.assert_called_once()


def test_domain_info_no_data_marker_is_cached_negative(patch_api):
    patch_api.dns.domain_info.side_effect = shodan.APIError("No information available")
    out = shodan_api.domain_info("ghost.example")
    assert out["no_data"] is True
    assert out["subdomains"] == []
    # negative payload cached; credit still spent (spend happens before the call)
    assert db.credits_used_today() == 1


# ── budget exhaustion ────────────────────────────────────────────────────────


def test_search_raises_budget_exceeded_when_cap_hit(patch_api, monkeypatch):
    monkeypatch.setattr(config, "DAILY_BUDGET", 1)
    patch_api.search.return_value = {"total": 0, "matches": []}

    # first miss spends the only credit
    shodan_api.search("q1")
    assert db.credits_used_today() == 1

    # second distinct query is a cache miss -> spend() trips the cap
    try:
        shodan_api.search("q2")
        raise AssertionError("expected BudgetExceeded")
    except db.BudgetExceeded:
        pass


# ── community queries (FREE, cached) ─────────────────────────────────────────


def test_community_queries_cached(patch_api):
    patch_api.queries.return_value = {"matches": [{"title": "x"}], "total": 1}
    a = shodan_api.community_queries()
    b = shodan_api.community_queries()
    assert a == b
    patch_api.queries.assert_called_once()
    assert db.credits_used_today() == 0
