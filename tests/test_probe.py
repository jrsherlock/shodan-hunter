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


# ── banner grab ─────────────────────────────────────────────────────────────


class _FakeBannerSock:
    """Serves a canned response over recv(); records what was sent."""
    def __init__(self, response: bytes = b""):
        self._buf = response
        self.sent = b""
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def sendall(self, data): self.sent += data
    def settimeout(self, t): pass
    def recv(self, n):
        out, self._buf = self._buf[:n], self._buf[n:]
        return out


def _patch_sock(monkeypatch, response: bytes) -> dict:
    """Patch create_connection to hand back a fake sock; expose it for assertions."""
    created: dict = {}
    def fake_conn(*a, **k):
        sock = _FakeBannerSock(response)
        created["sock"] = sock
        return sock
    monkeypatch.setattr(socket, "create_connection", fake_conn)
    return created


def test_banner_grab_reads_payload_and_response(probe_on, monkeypatch):
    created = _patch_sock(monkeypatch, b"SSH-2.0-OpenSSH_8.9\r\n")
    r = probe.banner_grab("8.8.8.8", 22, payload=b"hello\r\n")
    assert r["status"] == "up"
    assert r["banner"].startswith("SSH-2.0-OpenSSH")
    assert r["bytes"] == len(b"SSH-2.0-OpenSSH_8.9\r\n")
    assert r["hex"].startswith("5353482d")        # "SSH-" in hex
    assert created["sock"].sent == b"hello\r\n"    # payload was actually sent


def test_banner_grab_empty_when_silent(probe_on, monkeypatch):
    _patch_sock(monkeypatch, b"")
    r = probe.banner_grab("8.8.8.8", 10001)
    assert r["status"] == "empty"
    assert r["bytes"] == 0


def test_banner_grab_gated_and_fenced(probe_on, monkeypatch):
    monkeypatch.setattr(config, "PROBE_ENABLED", False)
    with pytest.raises(probe.ProbeDisabled):
        probe.banner_grab("8.8.8.8", 22)
    monkeypatch.setattr(config, "PROBE_ENABLED", True)
    with pytest.raises(probe.ProbeNotAllowed):
        probe.banner_grab("127.0.0.1", 22)


# ── Veeder-Root ATG ─────────────────────────────────────────────────────────

SAMPLE_ATG = (
    "\x01I20100\r\n"
    "JUN  3, 2026  7:59 PM\r\n"
    "\r\n"
    "MILLERS PRICE       \r\n"
    "755 S CARBON AVE    \r\n"
    "PRICE  UTAH         \r\n"
    "\r\n"
    "IN-TANK INVENTORY\r\n"
    "\r\n"
    "TANK PRODUCT             VOLUME TC VOLUME   ULLAGE   HEIGHT    WATER     TEMP\r\n"
    "  1  UNLEADED              3540      3533     8087    32.08     0.00    62.91\r\n"
    "  2  PREMIUM               4477      4469     3352    50.94     0.00    62.17\r\n"
    "  3  ETHANOL FREE          1171      1170     4758    24.31     0.00    60.23\r\n"
    "  4  DIESEL                3389      3385     4440    41.38     0.00    61.13\r\n"
    "\x03"
).encode("latin-1")


def test_veeder_root_sends_readonly_inventory_command(probe_on, monkeypatch):
    created = _patch_sock(monkeypatch, SAMPLE_ATG)
    probe.veeder_root_atg("8.8.8.8", 10001)
    # Exactly the SOH-framed read command — never a setup/write command.
    assert created["sock"].sent == b"\x01I20100"


def test_veeder_root_parses_report(probe_on, monkeypatch):
    _patch_sock(monkeypatch, SAMPLE_ATG)
    r = probe.veeder_root_atg("8.8.8.8", 10001)
    assert r["status"] == "up"
    assert r["is_atg"] is True
    atg = r["atg"]
    assert atg["report_time"].startswith("JUN")
    assert atg["station"]["name"] == "MILLERS PRICE"
    assert "755 S CARBON AVE" in atg["station"]["address"]
    assert [t["tank"] for t in atg["tanks"]] == [1, 2, 3, 4]
    # multi-word product names survive the parse
    assert atg["tanks"][2]["product"] == "ETHANOL FREE"
    assert atg["tanks"][0]["volume"] == 3540.0
    assert atg["tanks"][3]["temp"] == 61.13


def test_veeder_root_not_atg_on_silent_port(probe_on, monkeypatch):
    _patch_sock(monkeypatch, b"")
    r = probe.veeder_root_atg("8.8.8.8", 10001)
    assert r["is_atg"] is False
    assert r["atg"]["tanks"] == []


# ── /atg route ──────────────────────────────────────────────────────────────


def test_atg_route_403_when_disabled(client, monkeypatch):
    monkeypatch.setattr(config, "PROBE_ENABLED", False)
    r = client.post("/atg", data={"ip": "8.8.8.8", "port": 10001},
                    headers={"origin": "http://testserver"})
    assert r.status_code == 403


def test_atg_route_blocks_cross_origin(client, monkeypatch):
    monkeypatch.setattr(config, "PROBE_ENABLED", True)
    r = client.post("/atg", data={"ip": "8.8.8.8", "port": 10001},
                    headers={"origin": "https://evil.example"})
    assert r.status_code == 403


def test_atg_route_up_and_audited(client, monkeypatch):
    monkeypatch.setattr(config, "PROBE_ENABLED", True)
    monkeypatch.setattr(probe, "veeder_root_atg", lambda ip, port: {
        "status": "up", "ms": 20, "bytes": 200, "is_atg": True,
        "atg": {"tanks": [{"tank": 1}, {"tank": 2}]},
    })
    r = client.post("/atg", data={"ip": "8.8.8.8", "port": 10001},
                    headers={"origin": "http://testserver"})
    assert r.status_code == 200
    assert r.json()["is_atg"] is True
    rows = db.recent_audit()
    assert rows and rows[0]["action"] == "atg"
