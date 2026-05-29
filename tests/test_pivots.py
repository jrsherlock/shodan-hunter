"""Unit tests for pivot-query generation and browsable service links."""

from __future__ import annotations

from hunter import pivots

# A representative (trimmed) Shodan host record.
HOST = {
    "ip_str": "203.0.113.5",
    "org": "Acme Industries",
    "asn": "AS15169",
    "hostnames": ["web.acme.com", "alt.acme.com"],
    "vulns": ["CVE-2021-44228", "CVE-2019-0708"],
    "data": [
        {
            "port": 443, "transport": "tcp", "product": "nginx", "version": "1.18.0",
            "ssl": {"cert": {"subject": {"CN": "acme.com"}}},
            "http": {"status": 200, "favicon": {"hash": -247388890}},
        },
        {"port": 22, "transport": "tcp", "product": "OpenSSH", "version": "8.2"},
    ],
}


def _queries(host, idb=None):
    return {p["query"] for p in pivots.host_pivots(host, idb)}


def test_pivots_cover_core_attributes():
    qs = _queries(HOST)
    assert 'org:"Acme Industries"' in qs
    assert "asn:AS15169" in qs
    assert "net:203.0.113.0/24" in qs
    assert 'product:"nginx" version:"1.18.0"' in qs
    assert "ssl.cert.subject.cn:\"acme.com\"" in qs
    assert "http.favicon.hash:-247388890" in qs
    assert "vuln:CVE-2021-44228" in qs


def test_every_pivot_has_label_and_why():
    for p in pivots.host_pivots(HOST):
        assert p["label"] and p["why"] and p["query"]


def test_pivots_deduped():
    qs = [p["query"] for p in pivots.host_pivots(HOST)]
    assert len(qs) == len(set(qs))


def test_asn_gets_as_prefix_when_missing():
    qs = _queries({"ip_str": "1.2.3.4", "asn": "15169"})
    assert "asn:AS15169" in qs


def test_quotes_in_org_are_stripped_to_keep_query_valid():
    # An org with an embedded quote must not produce a malformed filter.
    qs = _queries({"ip_str": "1.2.3.4", "org": 'Ac"me'})
    assert 'org:"Acme"' in qs


def test_vulns_dict_form_handled():
    qs = _queries({"ip_str": "1.2.3.4", "data": [{"port": 80,
                   "vulns": {"CVE-2017-5638": {}}}]})
    assert "vuln:CVE-2017-5638" in qs


def test_idb_vulns_used_when_host_has_none():
    qs = _queries({"ip_str": "1.2.3.4"}, {"vulns": ["CVE-2020-0001"]})
    assert "vuln:CVE-2020-0001" in qs


def test_empty_host_yields_no_pivots():
    assert pivots.host_pivots({}) == []
    assert pivots.host_pivots(None) == []


def test_pivot_count_capped():
    big = {"ip_str": "1.2.3.4", "org": "O",
           "data": [{"port": p, "product": f"prod{p}"} for p in range(40)]}
    assert len(pivots.host_pivots(big)) <= 14


# ── service_url (browser-side liveness link) ──────────────────────────────────


def test_service_url_https_for_tls():
    svc = {"port": 8443, "ssl": {"cert": {}}}
    assert pivots.service_url("1.2.3.4", svc) == "https://1.2.3.4:8443"


def test_service_url_http_for_plain_web():
    svc = {"port": 8080, "http": {"status": 200}}
    assert pivots.service_url("1.2.3.4", svc) == "http://1.2.3.4:8080"


def test_service_url_none_for_non_web():
    assert pivots.service_url("1.2.3.4", {"port": 22, "product": "OpenSSH"}) is None
    assert pivots.service_url("1.2.3.4", {"product": "x"}) is None  # no port
