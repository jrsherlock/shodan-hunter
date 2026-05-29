"""Unit tests for hunter.recon — pure data-shaping helpers (no network)."""

from __future__ import annotations

from hunter import recon


# ── split_blob ──────────────────────────────────────────────────────────────


def test_split_blob_splits_on_mixed_delimiters():
    assert recon.split_blob("a, b;c   d\ne") == ["a", "b", "c", "d", "e"]


def test_split_blob_empty_and_whitespace():
    assert recon.split_blob("") == []
    assert recon.split_blob("   \n  ") == []


# ── parse_ip_targets ─────────────────────────────────────────────────────────


def test_parse_ip_targets_bare_ip_stays_bare():
    targets, invalid = recon.parse_ip_targets("1.2.3.4")
    assert targets == ["1.2.3.4"]
    assert invalid == []


def test_parse_ip_targets_cidr_is_normalized():
    # host bits set -> network address; /24 preserved
    targets, invalid = recon.parse_ip_targets("10.0.0.5/24")
    assert targets == ["10.0.0.0/24"]
    assert invalid == []


def test_parse_ip_targets_invalid_tokens_collected():
    targets, invalid = recon.parse_ip_targets("garbage 999.1.1.1 5.5.5.5")
    assert targets == ["5.5.5.5"]
    assert invalid == ["garbage", "999.1.1.1"]


def test_parse_ip_targets_dedupes_both_lists():
    targets, invalid = recon.parse_ip_targets("1.2.3.4 1.2.3.4 nope nope 10.0.0.0/24 10.0.0.0/24")
    assert targets == ["1.2.3.4", "10.0.0.0/24"]
    assert invalid == ["nope"]


def test_parse_ip_targets_empty():
    assert recon.parse_ip_targets("") == ([], [])


# ── count_hosts ──────────────────────────────────────────────────────────────


def test_count_hosts_single_ip():
    assert recon.count_hosts(["1.2.3.4"]) == 1


def test_count_hosts_cidr():
    assert recon.count_hosts(["10.0.0.0/24"]) == 256


def test_count_hosts_mixed_and_invalid_counts_as_one():
    # /30 = 4 addresses, single = 1, invalid token falls back to 1
    assert recon.count_hosts(["10.0.0.0/30", "8.8.8.8", "notanip"]) == 6


# ── classify_dns_inputs ──────────────────────────────────────────────────────


def test_classify_dns_inputs_hostnames_vs_ips():
    out = recon.classify_dns_inputs("example.com 8.8.8.8 sub.acme.org")
    assert out["hostnames"] == ["example.com", "sub.acme.org"]
    assert out["ips"] == ["8.8.8.8"]
    assert out["invalid"] == []


def test_classify_dns_inputs_strips_scheme_path_and_port():
    out = recon.classify_dns_inputs("https://acme.io/login host.example.org:8080")
    assert out["hostnames"] == ["acme.io", "host.example.org"]
    assert out["ips"] == []


def test_classify_dns_inputs_ipv4_with_port_becomes_ip():
    # single colon -> port stripped -> recognized as an IP
    out = recon.classify_dns_inputs("1.2.3.4:80")
    assert out["ips"] == ["1.2.3.4"]
    assert out["hostnames"] == []


def test_classify_dns_inputs_ipv6_literals_preserved():
    out = recon.classify_dns_inputs("::1 2001:db8::1")
    assert out["ips"] == ["::1", "2001:db8::1"]
    assert out["hostnames"] == []


def test_classify_dns_inputs_junk_is_invalid():
    out = recon.classify_dns_inputs("not_a_host!! &&&")
    assert out["hostnames"] == []
    assert out["ips"] == []
    assert out["invalid"] == ["not_a_host!!", "&&&"]


def test_classify_dns_inputs_dedupes():
    out = recon.classify_dns_inputs("a.com a.com 1.1.1.1 1.1.1.1")
    assert out["hostnames"] == ["a.com"]
    assert out["ips"] == ["1.1.1.1"]


# ── facet_chartdata ──────────────────────────────────────────────────────────


def test_facet_chartdata_empty_inputs():
    assert recon.facet_chartdata(None) == []
    assert recon.facet_chartdata({}) == []


def test_facet_chartdata_pct_scaled_against_max():
    data = {"port": [{"value": 80, "count": 10}, {"value": 443, "count": 5}]}
    out = recon.facet_chartdata(data)
    assert len(out) == 1
    grp = out[0]
    assert grp["name"] == "port"
    assert grp["label"] == "Top ports"
    assert grp["items"][0] == {"value": 80, "count": 10, "pct": 100}
    assert grp["items"][1] == {"value": 443, "count": 5, "pct": 50}


def test_facet_chartdata_orders_by_default_facets():
    # supply facets out of DEFAULT_FACETS order; expect them re-sorted
    data = {
        "os": [{"value": "linux", "count": 1}],
        "country": [{"value": "US", "count": 1}],
        "port": [{"value": 80, "count": 1}],
    }
    names = [g["name"] for g in recon.facet_chartdata(data)]
    # DEFAULT_FACETS = country, port, org, product, asn, os
    assert names == ["country", "port", "os"]


def test_facet_chartdata_unknown_facet_sorts_last_and_titlecased():
    data = {
        "weird": [{"value": "x", "count": 1}],
        "country": [{"value": "US", "count": 1}],
    }
    out = recon.facet_chartdata(data)
    assert [g["name"] for g in out] == ["country", "weird"]
    assert out[-1]["label"] == "Weird"  # FACET_LABELS fallback = name.title()


def test_facet_chartdata_zero_counts_do_not_divide_by_zero():
    data = {"org": [{"value": "a", "count": 0}, {"value": "b", "count": 0}]}
    out = recon.facet_chartdata(data)
    assert [it["pct"] for it in out[0]["items"]] == [0, 0]


def test_facet_chartdata_missing_count_key_defaults_zero():
    data = {"asn": [{"value": "AS1"}]}
    out = recon.facet_chartdata(data)
    assert out[0]["items"][0] == {"value": "AS1", "count": 0, "pct": 0}


# ── annotate_matches ─────────────────────────────────────────────────────────


def test_annotate_matches_merges_idb_and_honey():
    matches = [{"ip_str": "1.1.1.1"}, {"ip_str": "2.2.2.2"}]
    idb = {
        "1.1.1.1": {"tags": ["cloud"], "vulns": ["CVE-1"], "ports": [80, 443]},
    }
    honey = {"1.1.1.1": 0.9, "2.2.2.2": 0.1}
    out = recon.annotate_matches(matches, idb, honey, threshold=0.5)

    assert out is matches  # mutates in place
    assert out[0]["idb_tags"] == ["cloud"]
    assert out[0]["idb_vulns"] == ["CVE-1"]
    assert out[0]["idb_ports"] == [80, 443]
    assert out[0]["honeyscore"] == 0.9
    assert out[0]["is_honeypot"] is True

    # second host has no idb entry -> empty enrichment, below-threshold honey
    assert out[1]["idb_tags"] == []
    assert out[1]["idb_vulns"] == []
    assert out[1]["idb_ports"] == []
    assert out[1]["honeyscore"] == 0.1
    assert out[1]["is_honeypot"] is False


def test_annotate_matches_threshold_boundary_is_inclusive():
    matches = [{"ip_str": "9.9.9.9"}]
    out = recon.annotate_matches(matches, {}, {"9.9.9.9": 0.5}, threshold=0.5)
    assert out[0]["is_honeypot"] is True


def test_annotate_matches_none_score_is_not_honeypot():
    matches = [{"ip_str": "9.9.9.9"}]
    out = recon.annotate_matches(matches, {}, {"9.9.9.9": None}, threshold=0.5)
    assert out[0]["honeyscore"] is None
    assert out[0]["is_honeypot"] is False


def test_annotate_matches_handles_none_matches_and_missing_ip():
    assert recon.annotate_matches(None, {}, {}, 0.5) == []
    # a match with no ip_str must not crash
    matches = [{}]
    out = recon.annotate_matches(matches, {}, {}, 0.5)
    assert out[0]["is_honeypot"] is False


# ── honeypot_flag ────────────────────────────────────────────────────────────


def test_honeypot_flag():
    assert recon.honeypot_flag(0.9, 0.5) is True
    assert recon.honeypot_flag(0.5, 0.5) is True
    assert recon.honeypot_flag(0.49, 0.5) is False
    assert recon.honeypot_flag(None, 0.5) is False
