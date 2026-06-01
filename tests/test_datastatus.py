"""Unit tests for hunter.datastatus — parsing the data-status page and shaping
it for the dashboard. Pure functions only; no network.
"""

from __future__ import annotations

from hunter import datastatus

# A compact stand-in mirroring the real page's structure: inline `var x = [...]`
# chart datasets, a choropleth `const topCountries`, a `var scanned`, an
# "Updated at" stamp, and a CVE spotlight table.
FIXTURE = """
<html><body>
<p>Updated at 2026-04-02</p>
<script>
var categories = [{"count": 100, "name": "Other"}, {"count": 60, "name": "Web"}, {"count": 40, "name": "Email"}];
var topPorts = [{"count": 80, "percentage": 40.0, "port": 80}, {"count": 20, "percentage": 10.0, "port": 443}];
var services = [{"count": 180, "name": "tcp"}, {"count": 20, "name": "udp"}];
var orgs = [{"count": 50, "name": "Google LLC"}, {"count": 25, "name": "Cloudflare, Inc."}];
var products = [{"count": 30, "name": "nginx"}, {"count": 10, "name": "Apache httpd"}];
var scanned = 8;
//- CHOROPLETH
(() => { const topCountries = [{"code": "US", "count": 120, "name": "United States"}, {"code": "DE", "count": 30, "name": "Germany"}]; })();
</script>
<table>
  <thead><tr><th>CVE ID</th><th>Count</th><th>EPSS</th><th>CVSS</th></tr></thead>
  <tbody>
    <tr><td>CVE-2024-38475</td><td>956,145</td><td>0.94</td><td>9.1</td></tr>
    <tr><td>CVE-2022-28615</td><td>833,303</td><td>0.01</td><td>9.1</td></tr>
    <tr><td>CVE-2023-1111</td><td>500,000</td><td>0.60</td><td>6.5</td></tr>
  </tbody>
</table>
</body></html>
"""


# ── parse_html ───────────────────────────────────────────────────────────────


def test_parse_extracts_all_datasets():
    snap = datastatus.parse_html(FIXTURE)
    assert snap["updated"] == "2026-04-02"
    assert snap["categories"][0] == {"count": 100, "name": "Other"}
    assert [p["port"] for p in snap["ports"]] == [80, 443]
    assert {s["name"] for s in snap["protocols"]} == {"tcp", "udp"}
    assert snap["orgs"][0]["name"] == "Google LLC"
    assert snap["products"][0]["name"] == "nginx"
    assert snap["countries"][0]["code"] == "US"     # choropleth IIFE const parsed
    assert snap["hostname_scanned"] == 8


def test_parse_cve_table_rows():
    snap = datastatus.parse_html(FIXTURE)
    by_id = {c["id"]: c for c in snap["cves"]}
    assert by_id["CVE-2024-38475"] == {
        "id": "CVE-2024-38475", "count": 956145, "epss": 0.94, "cvss": 9.1,
    }
    assert len(snap["cves"]) == 3


def test_parse_missing_pieces_degrade_to_empty():
    snap = datastatus.parse_html("<html>nothing here</html>")
    assert snap["updated"] is None
    assert snap["categories"] == []
    assert snap["cves"] == []
    assert snap["hostname_scanned"] == 0


# ── build_view ───────────────────────────────────────────────────────────────


def test_build_view_hero_and_percentages():
    view = datastatus.build_view(datastatus.parse_html(FIXTURE))
    # total = sum of category counts = 200
    assert view["total"] == 200
    assert view["hero"]["country_count"] == 2
    assert view["hero"]["category_count"] == 3
    assert view["hero"]["top_port"] == 80
    # tcp 180 / (180+20) = 90%
    assert view["hero"]["tcp_pct"] == 90.0
    assert view["hero"]["udp_pct"] == 10.0
    # hostname coverage 8 / 200 = 4%
    assert view["hostname"]["pct"] == 4.0


def test_build_view_doughnut_gradient_is_css_conic():
    view = datastatus.build_view(datastatus.parse_html(FIXTURE))
    grad = view["categories"]["gradient"]
    assert grad.startswith("conic-gradient(")
    # first segment (Other, 50% of 200) coloured from the palette
    assert datastatus.PALETTE[0] in grad
    assert view["categories"]["segments"][0]["pct"] == 50.0


def test_build_view_country_bars_get_flags():
    view = datastatus.build_view(datastatus.parse_html(FIXTURE))
    us = view["countries"][0]
    assert us["code"] == "US"
    assert us["flag"] == "\U0001F1FA\U0001F1F8"
    # bar widths scaled to the largest country (US=120 → 100%)
    assert us["barpct"] == 100.0


def test_build_view_cve_groups_split_by_severity_and_epss():
    view = datastatus.build_view(datastatus.parse_html(FIXTURE))
    # Critical = CVSS >= 9.0 → the two 9.1 CVEs, sorted by prevalence
    crit_ids = [v["id"] for v in view["cve_critical"]]
    assert crit_ids == ["CVE-2024-38475", "CVE-2022-28615"]
    assert all(v["severity"] == "critical" for v in view["cve_critical"])
    # High EPSS = EPSS >= 0.5 → the 0.94 and 0.60 rows, highest EPSS first
    epss_ids = [v["id"] for v in view["cve_high_epss"]]
    assert epss_ids == ["CVE-2024-38475", "CVE-2023-1111"]
    assert view["cve_high_epss"][0]["epss_pct"] == 94.0
