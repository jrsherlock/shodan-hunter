"""Route/integration tests via FastAPI TestClient.

Every external dependency is monkeypatched so these tests make ZERO network
calls. The ``client`` fixture (see conftest.py) overrides the auth dependency
and stubs ``shodan_api.api_info`` (called by ``_ctx`` on every render).
"""

from __future__ import annotations

from hunter import config, db, internetdb, monitor, recon, shodan_api


# ── healthz (no auth) ────────────────────────────────────────────────────────


def test_healthz_no_auth(api_info_stub):
    # /healthz has no auth dependency, so use a bare client without overrides.
    from fastapi.testclient import TestClient

    from hunter.app import app

    with TestClient(app) as c:
        r = c.get("/healthz")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    # Unauthenticated endpoint must not leak config (bind, features…).
    assert body == {"ok": True}


# ── home ─────────────────────────────────────────────────────────────────────


def test_home_renders(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]


# ── dns ──────────────────────────────────────────────────────────────────────


def test_dns_form_renders(client):
    assert client.get("/dns").status_code == 200


def test_dns_post_runs_and_audits(client, monkeypatch):
    sample = {
        "hostnames": ["a.com"],
        "ips": ["1.1.1.1"],
        "invalid": [],
        "resolve": {"a.com": "1.2.3.4"},
        "reverse": {"1.1.1.1": ["one.example.com"]},
    }
    monkeypatch.setattr(recon, "bulk_dns", lambda blob: sample)

    r = client.post("/dns", data={"blob": "a.com 1.1.1.1"})
    assert r.status_code == 200

    rows = db.recent_audit()
    assert len(rows) == 1
    assert rows[0]["action"] == "dns"
    assert rows[0]["result_total"] == 2  # 1 resolve + 1 reverse
    assert rows[0]["credits"] == 0


# ── domain ───────────────────────────────────────────────────────────────────


def test_domain_query_param(client, monkeypatch):
    sample = {
        "domain": "acme.com",
        "subdomains": ["www", "mail"],
        "data": [],
        "tags": [],
        "_cache": "miss",
    }
    monkeypatch.setattr(shodan_api, "domain_info", lambda d, **k: sample)

    r = client.get("/domain", params={"q": "acme.com"})
    assert r.status_code == 200

    rows = db.recent_audit()
    assert rows[0]["action"] == "domain"
    assert rows[0]["result_total"] == 2  # two subdomains
    assert rows[0]["credits"] == 1       # _cache == miss


def test_domain_no_query_does_not_call_api(client, monkeypatch):
    monkeypatch.setattr(shodan_api, "domain_info",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("should not be called")))
    r = client.get("/domain")
    assert r.status_code == 200
    assert db.recent_audit() == []  # nothing looked up, nothing logged


# ── library ──────────────────────────────────────────────────────────────────


def test_library_lists_community_queries(client, monkeypatch):
    data = {"matches": [{"title": "Open RDP", "query": "port:3389", "tags": ["rdp"]}], "total": 1}
    called = {}

    def fake_community_queries(page=1, **k):
        called["page"] = page
        return data

    monkeypatch.setattr(shodan_api, "community_queries", fake_community_queries)

    r = client.get("/library")
    assert r.status_code == 200
    assert "Open RDP" in r.text
    assert called["page"] == 1


def test_library_search_uses_query_search(client, monkeypatch):
    monkeypatch.setattr(shodan_api, "query_search",
                        lambda q, page=1, **k: {"matches": [{"title": "hit-" + q}]})
    # community_queries must NOT be used when a search term is present
    monkeypatch.setattr(shodan_api, "community_queries",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("should not be called")))
    r = client.get("/library", params={"q": "webcam"})
    assert r.status_code == 200
    assert "hit-webcam" in r.text


# ── scan (disabled by default) ───────────────────────────────────────────────


def test_scan_page_renders_disabled(client):
    assert config.SCAN_ENABLED is False
    r = client.get("/scan")
    assert r.status_code == 200
    assert "disabled" in r.text.lower()


def test_scan_post_forbidden_when_disabled(client, monkeypatch):
    # submit must never be reached while scanning is disabled
    monkeypatch.setattr("hunter.scans.submit",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("should not be called")))
    r = client.post("/scan", data={"targets": "1.2.3.4", "confirm": "yes"})
    assert r.status_code == 403


# ── alerts ───────────────────────────────────────────────────────────────────


def test_alerts_page_renders(client, monkeypatch):
    monkeypatch.setattr(monitor, "list_with_meta", lambda: [])
    monkeypatch.setattr(monitor, "triggers_catalog", lambda: [])
    r = client.get("/alerts")
    assert r.status_code == 200


def test_alerts_page_lists_alerts(client, monkeypatch):
    alerts = [{
        "id": "A1", "name": "prod", "ips": ["1.1.1.1"], "filters": {"ip": ["1.1.1.1"]},
        "triggers": ["malware"], "size": 1, "expires": None, "created": None,
        "created_by": "tester",
    }]
    monkeypatch.setattr(monitor, "list_with_meta", lambda: alerts)
    monkeypatch.setattr(monitor, "triggers_catalog",
                        lambda: [{"name": "malware", "rule": "", "description": "d"}])
    r = client.get("/alerts")
    assert r.status_code == 200
    assert "prod" in r.text


# ── idb json ─────────────────────────────────────────────────────────────────


def test_idb_json(client, monkeypatch):
    enrich = {"tags": ["cloud"], "vulns": ["CVE-1"], "cpes": [], "hostnames": [], "ports": [443]}
    monkeypatch.setattr(internetdb, "lookup", lambda ip: enrich)
    r = client.get("/idb/1.1.1.1")
    assert r.status_code == 200
    body = r.json()
    assert body["ip"] == "1.1.1.1"
    assert body["tags"] == ["cloud"]
    assert body["ports"] == [443]


# ── honeyscore json ──────────────────────────────────────────────────────────


def test_honeyscore_json(client, monkeypatch):
    monkeypatch.setattr(shodan_api, "honeyscore", lambda ip, **k: 0.42)
    r = client.get("/api/honeyscore/1.1.1.1")
    assert r.status_code == 200
    assert r.json() == {"ip": "1.1.1.1", "honeyscore": 0.42}


def test_honeyscore_json_none(client, monkeypatch):
    monkeypatch.setattr(shodan_api, "honeyscore", lambda ip, **k: None)
    r = client.get("/api/honeyscore/8.8.8.8")
    assert r.status_code == 200
    assert r.json() == {"ip": "8.8.8.8", "honeyscore": None}


# ── api/count (JSON helper) ──────────────────────────────────────────────────


def test_api_count_json(client, monkeypatch):
    monkeypatch.setattr(shodan_api, "count", lambda q, **k: {"total": 11, "_cache": "miss"})
    r = client.get("/api/count", params={"q": "apache"})
    assert r.status_code == 200
    assert r.json()["total"] == 11
