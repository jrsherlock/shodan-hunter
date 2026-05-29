"""Security-control tests: CSRF origin guard, truthy form coercion, and IP
path-param validation. All offline — the ``client`` fixture overrides auth and
stubs api_info (see conftest.py)."""

from __future__ import annotations

import pytest

from hunter import config, recon, scans, shodan_api


# ── #2: config.truthy — non-empty strings like "false"/"0" must NOT be truthy ──


@pytest.mark.parametrize("raw", ["1", "true", "True", "  yes ", "on", "ON"])
def test_truthy_accepts_canonical_true(raw):
    assert config.truthy(raw) is True


@pytest.mark.parametrize("raw", ["", "0", "false", "off", "no", "false ", None, "x"])
def test_truthy_rejects_everything_else(raw):
    # bool("false") is True — config.truthy must not be fooled by that.
    assert config.truthy(raw) is False


# ── #1: CSRF — cross-origin POSTs are blocked, same-origin/headerless pass ─────


def _stub_dns(monkeypatch):
    monkeypatch.setattr(recon, "bulk_dns", lambda blob: {
        "hostnames": [], "ips": [], "invalid": [], "resolve": {}, "reverse": {},
    })


def test_post_blocked_from_foreign_origin(client, monkeypatch):
    _stub_dns(monkeypatch)
    r = client.post("/dns", data={"blob": "x"}, headers={"origin": "https://evil.example"})
    assert r.status_code == 403
    assert "csrf" in r.text.lower()


def test_post_blocked_from_foreign_referer(client, monkeypatch):
    _stub_dns(monkeypatch)
    r = client.post("/dns", data={"blob": "x"}, headers={"referer": "https://evil.example/x"})
    assert r.status_code == 403


def test_post_allowed_from_same_origin(client, monkeypatch):
    # TestClient's Host is "testserver"; a matching Origin must pass.
    _stub_dns(monkeypatch)
    r = client.post("/dns", data={"blob": "x"}, headers={"origin": "http://testserver"})
    assert r.status_code == 200


def test_post_allowed_without_origin_header(client, monkeypatch):
    # No Origin/Referer (curl, server-to-server): no ambient creds, no CSRF risk.
    _stub_dns(monkeypatch)
    r = client.post("/dns", data={"blob": "x"})
    assert r.status_code == 200


def test_alert_delete_blocked_cross_origin(client, monkeypatch):
    monkeypatch.setattr(config, "ALERTS_ENABLED", True)
    monkeypatch.setattr("hunter.monitor.delete",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not run")))
    r = client.post("/alerts/A1/delete", headers={"origin": "https://evil.example"})
    assert r.status_code == 403


# ── #2 (integration): confirm="false" must not authorize a scan ────────────────


def test_scan_confirm_false_not_authorized(client, monkeypatch):
    monkeypatch.setattr(config, "SCAN_ENABLED", True)
    captured = {}

    def fake_submit(raw, *, user, user_confirmed=False):
        captured["user_confirmed"] = user_confirmed
        raise scans.ScanNotAuthorized("nope")

    monkeypatch.setattr(scans, "submit", fake_submit)
    # Same-origin so the CSRF guard passes and we exercise the confirm parsing.
    r = client.post("/scan", data={"targets": "1.2.3.4", "confirm": "false"},
                    headers={"origin": "http://testserver"})
    assert r.status_code == 200          # route renders the error, doesn't 500
    assert captured["user_confirmed"] is False


def test_scan_confirm_yes_authorized_flag(client, monkeypatch):
    monkeypatch.setattr(config, "SCAN_ENABLED", True)
    captured = {}

    def fake_submit(raw, *, user, user_confirmed=False):
        captured["user_confirmed"] = user_confirmed
        return {"targets": ["1.2.3.4"], "result": {}, "authorization": "ok", "scan_id": None}

    monkeypatch.setattr(scans, "submit", fake_submit)
    monkeypatch.setattr(recon, "count_hosts", lambda t: 1)
    r = client.post("/scan", data={"targets": "1.2.3.4", "confirm": "yes"},
                    headers={"origin": "http://testserver"})
    assert r.status_code == 200
    assert captured["user_confirmed"] is True


# ── #5: IP path-param validation on the outbound-fanning routes ────────────────


@pytest.mark.parametrize("path", [
    "/idb/not-an-ip",
    "/api/honeyscore/not-an-ip",
    "/host/not-an-ip",
])
def test_invalid_ip_rejected(client, monkeypatch, path):
    # Stub the upstreams so a regression (validation removed) wouldn't silently
    # pass by hitting the network — it must 422 before reaching these.
    monkeypatch.setattr("hunter.internetdb.lookup",
                        lambda ip: (_ for _ in ()).throw(AssertionError("must not run")))
    monkeypatch.setattr(shodan_api, "honeyscore",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not run")))
    monkeypatch.setattr(shodan_api, "host",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not run")))
    r = client.get(path)
    assert r.status_code == 422


def test_valid_ip_passes_validation(client, monkeypatch):
    monkeypatch.setattr("hunter.internetdb.lookup", lambda ip: {
        "tags": [], "vulns": [], "cpes": [], "hostnames": [], "ports": [],
    })
    r = client.get("/idb/8.8.8.8")
    assert r.status_code == 200
    assert r.json()["ip"] == "8.8.8.8"
