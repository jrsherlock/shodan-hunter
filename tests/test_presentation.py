"""Unit tests for the SOC-console presentation helpers in hunter.recon.

All pure data-shaping — no network, no templating.
"""

from __future__ import annotations

from hunter import recon


# ── severity_from_cvss ───────────────────────────────────────────────────────


def test_severity_bands():
    assert recon.severity_from_cvss(9.8) == "critical"
    assert recon.severity_from_cvss(9.0) == "critical"
    assert recon.severity_from_cvss(7.5) == "high"
    assert recon.severity_from_cvss(7.0) == "high"
    assert recon.severity_from_cvss(4.0) == "medium"
    assert recon.severity_from_cvss(0.1) == "low"
    assert recon.severity_from_cvss(0.0) == "unknown"


def test_severity_unparseable_is_unknown():
    assert recon.severity_from_cvss(None) == "unknown"
    assert recon.severity_from_cvss("n/a") == "unknown"


def test_severity_numeric_string_is_parsed():
    assert recon.severity_from_cvss("8.1") == "high"


# ── merge_vulns ──────────────────────────────────────────────────────────────


def test_merge_vulns_dict_and_list_dedupe_keep_highest_cvss():
    dict_src = {"CVE-1": {"cvss": 5.0, "verified": False},
                "CVE-2": {"cvss": 9.1, "verified": True}}
    list_src = ["CVE-1", "CVE-3"]
    out = recon.merge_vulns(dict_src, list_src, {"CVE-1": {"cvss": 7.7}})
    by_id = {v["id"]: v for v in out}

    # CVE-1 seen three times -> highest CVSS wins
    assert by_id["CVE-1"]["cvss"] == 7.7
    assert by_id["CVE-1"]["severity"] == "high"
    # CVE-2 verified flag preserved
    assert by_id["CVE-2"]["verified"] is True
    assert by_id["CVE-2"]["severity"] == "critical"
    # CVE-3 came only from a bare list -> no score
    assert by_id["CVE-3"]["cvss"] is None
    assert by_id["CVE-3"]["severity"] == "unknown"


def test_merge_vulns_sorted_highest_first_scoreless_last():
    out = recon.merge_vulns(["CVE-NONE"], {"CVE-HI": {"cvss": 9.9},
                                           "CVE-MID": {"cvss": 5.0}})
    assert [v["id"] for v in out] == ["CVE-HI", "CVE-MID", "CVE-NONE"]


def test_merge_vulns_ignores_junk_sources():
    assert recon.merge_vulns(None, "nope", 42) == []


# ── country_flag ─────────────────────────────────────────────────────────────


def test_country_flag_valid_code():
    assert recon.country_flag("US") == "\U0001F1FA\U0001F1F8"
    assert recon.country_flag("de") == "\U0001F1E9\U0001F1EA"  # case-insensitive


def test_country_flag_rejects_non_codes():
    assert recon.country_flag("USA") == ""
    assert recon.country_flag("") == ""
    assert recon.country_flag(None) == ""
    assert recon.country_flag("12") == ""


# ── tag_meta ─────────────────────────────────────────────────────────────────


def test_tag_meta_known_tag():
    meta = recon.tag_meta("honeypot")
    assert meta["kind"] == "honeypot"
    assert meta["icon"]  # has an emoji
    assert meta["label"] == "honeypot"


def test_tag_meta_unknown_tag_is_generic_no_icon():
    meta = recon.tag_meta("some-weird-tag")
    assert meta == {"label": "some-weird-tag", "icon": "", "kind": "generic"}


# ── match_screenshot ─────────────────────────────────────────────────────────


def test_match_screenshot_from_opts():
    banner = {"opts": {"screenshot": {"data": "BASE64", "mime": "image/png"}}}
    assert recon.match_screenshot(banner) == {"data": "BASE64", "mime": "image/png"}


def test_match_screenshot_top_level_defaults_mime():
    banner = {"screenshot": {"data": "ABC"}}
    assert recon.match_screenshot(banner) == {"data": "ABC", "mime": "image/jpeg"}


def test_match_screenshot_absent():
    assert recon.match_screenshot({"port": 80}) is None
    assert recon.match_screenshot(None) is None


# ── group_by_host ────────────────────────────────────────────────────────────


def test_group_by_host_collapses_services_into_one_card():
    matches = [
        {"ip_str": "1.1.1.1", "port": 443, "org": "Acme", "product": "nginx",
         "version": "1.25", "hostnames": ["a.acme.com"], "timestamp": "2024-05-01T00:00:00",
         "location": {"country_code": "US", "country_name": "United States"},
         "idb_tags": ["cloud"], "vulns": {"CVE-A": {"cvss": 9.1}}},
        {"ip_str": "1.1.1.1", "port": 22, "product": "OpenSSH",
         "hostnames": ["a.acme.com", "b.acme.com"], "timestamp": "2024-06-01T00:00:00",
         "idb_vulns": ["CVE-B"]},
        {"ip_str": "2.2.2.2", "port": 80, "org": "Globex",
         "location": {"country_code": "DE"}},
    ]
    hosts = recon.group_by_host(matches)

    assert [h["ip_str"] for h in hosts] == ["1.1.1.1", "2.2.2.2"]  # first-seen order
    h1 = hosts[0]
    assert h1["ports"] == [22, 443]               # unioned + sorted
    assert h1["org"] == "Acme"
    assert h1["hostnames"] == ["a.acme.com", "b.acme.com"]  # deduped union
    assert "nginx 1.25" in h1["products"] and "OpenSSH" in h1["products"]
    assert h1["last_seen"] == "2024-06-01T00:00:00"  # most recent across services
    assert h1["country_code"] == "US"
    assert h1["flag"] == recon.country_flag("US")
    # vulns merged across the dict source and the InternetDB list, sorted
    assert [v["id"] for v in h1["vulns"]] == ["CVE-A", "CVE-B"]
    assert h1["vulns"][0]["severity"] == "critical"


def test_group_by_host_honeypot_ored_across_services():
    matches = [
        {"ip_str": "9.9.9.9", "port": 1, "is_honeypot": False},
        {"ip_str": "9.9.9.9", "port": 2, "is_honeypot": True},
    ]
    hosts = recon.group_by_host(matches)
    assert hosts[0]["is_honeypot"] is True


def test_group_by_host_first_screenshot_wins():
    matches = [
        {"ip_str": "3.3.3.3", "port": 1},
        {"ip_str": "3.3.3.3", "port": 2, "opts": {"screenshot": {"data": "IMG"}}},
    ]
    hosts = recon.group_by_host(matches)
    assert hosts[0]["screenshot"] == {"data": "IMG", "mime": "image/jpeg"}


def test_group_by_host_skips_rows_without_ip_and_handles_empty():
    assert recon.group_by_host(None) == []
    assert recon.group_by_host([{"port": 80}]) == []


# ── result_summary ───────────────────────────────────────────────────────────


def test_result_summary_counts_and_top_cve():
    hosts = [
        {"country_code": "US", "is_honeypot": True,
         "vulns": [{"id": "CVE-X"}, {"id": "CVE-Y"}]},
        {"country_code": "US", "is_honeypot": False,
         "vulns": [{"id": "CVE-X"}]},
        {"country_code": "DE", "is_honeypot": False, "vulns": []},
    ]
    s = recon.result_summary(hosts)
    assert s["host_count"] == 3
    assert s["country_count"] == 2        # US, DE
    assert s["honeypot_count"] == 1
    assert s["vuln_host_count"] == 2
    assert s["top_cve"] == {"id": "CVE-X", "hosts": 2}  # seen on two hosts


def test_result_summary_no_vulns_no_top_cve():
    s = recon.result_summary([{"country_code": "US", "is_honeypot": False, "vulns": []}])
    assert s["top_cve"] is None
    assert s["vuln_host_count"] == 0
