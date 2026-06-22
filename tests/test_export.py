"""Unit tests for the result-export shapers and serializers."""

from __future__ import annotations

import csv
import io
import json

from hunter import export


# ── filename / slug ──────────────────────────────────────────────────────────


def test_filename_is_slugged_and_stamped():
    fn = export.filename("Acme Corp.com", "domain", "csv")
    assert fn.startswith("acme-corp.com-domain-")
    assert fn.endswith("Z.csv")


def test_filename_falls_back_for_empty_stem():
    assert export.filename("", "search", "json").startswith("export-search-")


# ── domain rows ──────────────────────────────────────────────────────────────


def test_domain_rows_builds_fqdn_and_joins_ports():
    data = {
        "domain": "example.com",
        "data": [
            {"subdomain": "www", "type": "A", "value": "1.2.3.4",
             "ports": [80, 443], "last_seen": "2026-06-21"},
            {"subdomain": "", "type": "MX", "value": "mail.example.com",
             "ports": [], "last_seen": "2026-06-18"},
        ],
    }
    cols, rows = export.domain_rows(data)
    assert cols[0] == "fqdn"
    assert rows[0]["fqdn"] == "www.example.com"
    assert rows[0]["ports"] == "80 443"
    # apex record (no subdomain) uses the bare domain
    assert rows[1]["fqdn"] == "example.com"


def test_domain_rows_empty_is_safe():
    cols, rows = export.domain_rows(None)
    assert rows == [] and "fqdn" in cols


# ── search rows ──────────────────────────────────────────────────────────────


def test_search_rows_flattens_nested_fields():
    matches = [{
        "ip_str": "9.9.9.9", "port": 443, "transport": "tcp",
        "org": "Acme", "asn": "AS123",
        "location": {"country_code": "US", "city": "Des Moines"},
        "hostnames": ["a.example.com", "b.example.com"],
        "product": "nginx", "version": "1.25",
        "vulns": {"CVE-2021-1": {}}, "idb_vulns": ["CVE-2021-2"],
        "idb_tags": ["cloud"], "is_honeypot": True,
    }]
    cols, rows = export.search_rows(matches)
    r = rows[0]
    assert r["ip"] == "9.9.9.9" and r["port"] == 443
    assert r["country"] == "US" and r["city"] == "Des Moines"
    assert r["hostnames"] == "a.example.com; b.example.com"
    # vulns merged from both sources, deduped + sorted
    assert r["vulns"] == "CVE-2021-1; CVE-2021-2"
    assert r["tags"] == "cloud"
    assert r["honeypot"] == "yes"


def test_search_rows_handles_sparse_match():
    cols, rows = export.search_rows([{"ip_str": "1.1.1.1"}])
    assert rows[0]["org"] == "" and rows[0]["honeypot"] == ""


# ── dns rows ─────────────────────────────────────────────────────────────────


def test_dns_rows_covers_forward_and_reverse():
    result = {
        "resolve": {"example.com": "1.2.3.4", "nx.example.com": None},
        "reverse": {"8.8.8.8": ["dns.google"]},
    }
    cols, rows = export.dns_rows(result)
    fwd = [r for r in rows if r["direction"] == "forward"]
    rev = [r for r in rows if r["direction"] == "reverse"]
    assert {"input": "example.com", "direction": "forward", "result": "1.2.3.4"} in fwd
    assert rev[0]["result"] == "dns.google"


# ── host rows ────────────────────────────────────────────────────────────────


def test_host_rows_one_row_per_service_with_context():
    data = {
        "ip_str": "9.9.9.9", "org": "Acme", "country_code": "US",
        "vulns": ["CVE-2020-0001"],
        "data": [
            {"port": 443, "transport": "tcp", "product": "nginx", "version": "1.25",
             "_shodan": {"module": "https"}, "cpe23": ["cpe:/a:nginx:nginx"],
             "ssl": {"cert": {"subject": {"CN": "acme.com"}}},
             "http": {"title": "Home", "server": "nginx"},
             "vulns": {"CVE-2021-1": {}}, "timestamp": "2026-06-20"},
            {"port": 22, "transport": "tcp", "product": "OpenSSH"},
        ],
    }
    cols, rows = export.host_rows(data, idb={"vulns": ["CVE-2019-9"], "tags": ["cloud"]})
    assert len(rows) == 2
    https = rows[0]
    assert https["port"] == 443 and https["module"] == "https"
    assert https["ssl_cn"] == "acme.com" and https["http_title"] == "Home"
    assert https["org"] == "Acme" and https["country"] == "US"
    # service + host + idb CVEs merged onto the row
    assert https["vulns"] == "CVE-2019-9; CVE-2020-0001; CVE-2021-1"
    assert https["tags"] == "cloud"
    # host-level CVEs still ride along on a service with none of its own
    assert "CVE-2020-0001" in rows[1]["vulns"]


def test_host_rows_summary_row_when_no_services():
    data = {"ip_str": "1.1.1.1", "org": "X", "no_data": True, "data": []}
    cols, rows = export.host_rows(data, idb={"cpes": ["cpe:/a:foo"]})
    assert len(rows) == 1
    assert rows[0]["ip"] == "1.1.1.1" and rows[0]["port"] == ""
    assert rows[0]["cpe"] == "cpe:/a:foo"


def test_host_rows_empty_host_yields_no_rows():
    cols, rows = export.host_rows({}, idb=None)
    assert rows == [] and "ip" in cols


# ── serializers ──────────────────────────────────────────────────────────────


def test_csv_bytes_roundtrips_and_has_bom():
    cols, rows = export.domain_rows(
        {"domain": "x.com", "data": [{"subdomain": "a", "type": "A",
                                      "value": "1.1.1.1", "ports": [80]}]})
    raw = export.csv_bytes(cols, rows)
    assert raw.startswith(b"\xef\xbb\xbf")  # utf-8-sig BOM for Excel
    text = raw.decode("utf-8-sig")
    parsed = list(csv.DictReader(io.StringIO(text)))
    assert parsed[0]["fqdn"] == "a.x.com"
    assert parsed[0]["ports"] == "80"


def test_csv_quotes_cells_with_commas():
    raw = export.csv_bytes(["a"], [{"a": "one, two"}]).decode("utf-8-sig")
    rows = list(csv.reader(io.StringIO(raw)))
    assert rows[1] == ["one, two"]  # comma survived intact (was quoted)


def test_json_bytes_wraps_meta_columns_rows():
    cols, rows = export.dns_rows({"resolve": {"a.com": "1.1.1.1"}})
    doc = json.loads(export.json_bytes({"type": "dns"}, cols, rows))
    assert doc["meta"]["type"] == "dns"
    assert doc["meta"]["count"] == 1
    assert "exported_at" in doc["meta"]
    assert doc["columns"] == cols
    assert doc["rows"][0]["input"] == "a.com"
