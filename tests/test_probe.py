"""Tests for the liveness probe module + route.

No real outbound sockets: socket.create_connection is monkeypatched. The
private-address guard and the SH_ENABLE_PROBE gate are exercised directly."""

from __future__ import annotations

import socket

import pytest

from hunter import config, db, probe


@pytest.fixture
def probe_on(monkeypatch):
    monkeypatch.setattr(config, "PROBE_ENABLED", True)
    monkeypatch.setattr(config, "PROBE_ALLOW_PRIVATE", False)
    monkeypatch.setattr(config, "PROBE_TIMEOUT", 3.0)


def test_disabled_raises(monkeypatch):
    monkeypatch.setattr(config, "PROBE_ENABLED", False)
    with pytest.raises(probe.ProbeDisabled):
        probe.probe("8.8.8.8", 443)


def test_private_target_refused(probe_on):
    for ip in ("127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.1.1"):
        with pytest.raises(probe.ProbeNotAllowed):
            probe.probe(ip, 80)


def test_private_target_allowed_when_opted_in(probe_on, monkeypatch):
    monkeypatch.setattr(config, "PROBE_ALLOW_PRIVATE", True)
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: _FakeSock())
    assert probe.probe("10.0.0.1", 80)["status"] == "up"


def test_bad_ip_and_port(probe_on):
    with pytest.raises(ValueError):
        probe.probe("not-an-ip", 80)
    with pytest.raises(ValueError):
        probe.probe("8.8.8.8", 70000)


class _FakeSock:
    def __enter__(self): return self
    def __exit__(self, *a): return False


def test_up(probe_on, monkeypatch):
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: _FakeSock())
    assert probe.probe("8.8.8.8", 443)["status"] == "up"


def test_timeout(probe_on, monkeypatch):
    def boom(*a, **k): raise socket.timeout()
    monkeypatch.setattr(socket, "create_connection", boom)
    r = probe.probe("8.8.8.8", 443)
    assert r["status"] == "timeout"


def test_refused_is_down(probe_on, monkeypatch):
    def boom(*a, **k): raise ConnectionRefusedError()
    monkeypatch.setattr(socket, "create_connection", boom)
    assert probe.probe("8.8.8.8", 443)["status"] == "down"


def test_other_oserror_is_error(probe_on, monkeypatch):
    def boom(*a, **k): raise OSError("no route to host")
    monkeypatch.setattr(socket, "create_connection", boom)
    r = probe.probe("8.8.8.8", 443)
    assert r["status"] == "error"


# ── route ─────────────────────────────────────────────────────────────────────


def test_probe_route_403_when_disabled(client, monkeypatch):
    monkeypatch.setattr(config, "PROBE_ENABLED", False)
    r = client.post("/probe", data={"ip": "8.8.8.8", "port": 443},
                    headers={"origin": "http://testserver"})
    assert r.status_code == 403


def test_probe_route_blocks_cross_origin(client, monkeypatch):
    monkeypatch.setattr(config, "PROBE_ENABLED", True)
    r = client.post("/probe", data={"ip": "8.8.8.8", "port": 443},
                    headers={"origin": "https://evil.example"})
    assert r.status_code == 403  # CSRF guard, before probe logic


def test_probe_route_up_and_audited(client, monkeypatch):
    monkeypatch.setattr(config, "PROBE_ENABLED", True)
    monkeypatch.setattr(probe, "probe",
                        lambda ip, port: {"status": "up", "ms": 12, "detail": "connected in 12 ms"})
    r = client.post("/probe", data={"ip": "8.8.8.8", "port": 443},
                    headers={"origin": "http://testserver"})
    assert r.status_code == 200
    assert r.json()["status"] == "up"
    rows = db.recent_audit()
    assert rows and rows[0]["action"] == "probe"


def test_probe_route_invalid_ip_422(client, monkeypatch):
    monkeypatch.setattr(config, "PROBE_ENABLED", True)
    r = client.post("/probe", data={"ip": "nope", "port": 443},
                    headers={"origin": "http://testserver"})
    assert r.status_code == 422
