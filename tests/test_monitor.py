"""Unit tests for hunter.monitor — alert registration + local mirror."""

from __future__ import annotations

import pytest

from hunter import db, monitor, shodan_api


# ── create ───────────────────────────────────────────────────────────────────


def test_create_parses_ips_calls_create_alert_and_mirrors(monkeypatch):
    calls = {}

    def fake_create_alert(name, ip, expires=0):
        calls["create"] = (name, ip)
        return {"id": "AID-1", "name": name, "filters": {"ip": ip}}

    enabled_triggers = []

    def fake_enable(aid, trigger):
        enabled_triggers.append((aid, trigger))
        return {"ok": True}

    monkeypatch.setattr(shodan_api, "create_alert", fake_create_alert)
    monkeypatch.setattr(shodan_api, "enable_alert_trigger", fake_enable)

    res = monitor.create("watch-prod", "1.2.3.4, 10.0.0.0/24", user="tester",
                         triggers=["malware", "new_service"])

    assert res["id"] == "AID-1"
    assert res["targets"] == ["1.2.3.4", "10.0.0.0/24"]
    assert res["triggers_enabled"] == ["malware", "new_service"]
    # create_alert got the parsed/normalized targets
    assert calls["create"] == ("watch-prod", ["1.2.3.4", "10.0.0.0/24"])
    assert enabled_triggers == [("AID-1", "malware"), ("AID-1", "new_service")]

    # local mirror row written with attribution
    meta = db.get_alert_meta("AID-1")
    assert meta is not None
    assert meta["created_by"] == "tester"
    assert meta["name"] == "watch-prod"


def test_create_swallows_bad_trigger(monkeypatch):
    monkeypatch.setattr(shodan_api, "create_alert",
                        lambda name, ip, expires=0: {"id": "AID-2", "filters": {"ip": ip}})

    def flaky_enable(aid, trigger):
        if trigger == "bad":
            raise shodan_api.ShodanError("unknown trigger")
        return {"ok": True}

    monkeypatch.setattr(shodan_api, "enable_alert_trigger", flaky_enable)

    res = monitor.create("w", "1.2.3.4", user="tester", triggers=["good", "bad"])
    # one bad trigger does not drop the alert; only the good one is recorded
    assert res["triggers_enabled"] == ["good"]
    assert db.get_alert_meta("AID-2")["triggers_json"] == '["good"]'


def test_create_raises_on_invalid_ips(monkeypatch):
    monkeypatch.setattr(shodan_api, "create_alert",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("should not be called")))
    with pytest.raises(ValueError) as ei:
        monitor.create("w", "garbage 999.999.999.999", user="tester")
    assert "invalid IP/CIDR" in str(ei.value)


def test_create_raises_on_empty_ips(monkeypatch):
    monkeypatch.setattr(shodan_api, "create_alert",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("should not be called")))
    with pytest.raises(ValueError) as ei:
        monitor.create("w", "   ", user="tester")
    assert "no IP/CIDR" in str(ei.value)


# ── list_with_meta ───────────────────────────────────────────────────────────


def test_list_with_meta_normalizes_and_attaches_created_by(monkeypatch):
    raw = [
        {"id": "A1", "name": "n1", "filters": {"ip": ["1.1.1.1", "2.2.2.2"]},
         "triggers": {"malware": {}}, "size": 2},
        {"id": "A2", "name": "n2", "filters": {"ip": "9.9.9.9"}, "triggers": {}},
    ]
    monkeypatch.setattr(shodan_api, "list_alerts", lambda *a, **k: raw)

    # pre-seed a mirror row so created_by gets attached for A1
    db.upsert_alert(aid="A1", name="n1", filters={"ip": ["1.1.1.1"]},
                    triggers=["malware"], created_by="alice")

    out = monitor.list_with_meta()
    by_id = {a["id"]: a for a in out}

    assert by_id["A1"]["ips"] == ["1.1.1.1", "2.2.2.2"]
    assert by_id["A1"]["triggers"] == ["malware"]   # from dict keys
    assert by_id["A1"]["created_by"] == "alice"

    assert by_id["A2"]["ips"] == ["9.9.9.9"]         # scalar ip -> list
    assert by_id["A2"]["triggers"] == []
    assert by_id["A2"]["created_by"] is None         # no mirror row yet

    # list_with_meta also upserts a mirror for previously-unknown alerts
    assert db.get_alert_meta("A2") is not None


# ── delete ───────────────────────────────────────────────────────────────────


def test_delete_calls_api_and_removes_mirror(monkeypatch):
    deleted = []
    monkeypatch.setattr(shodan_api, "delete_alert", lambda aid: deleted.append(aid))

    db.upsert_alert(aid="A9", name="n", filters={}, triggers=[], created_by="bob")
    assert db.get_alert_meta("A9") is not None

    monitor.delete("A9")
    assert deleted == ["A9"]
    assert db.get_alert_meta("A9") is None


# ── triggers_catalog (cached) ────────────────────────────────────────────────


def test_triggers_catalog_caches(monkeypatch):
    catalog = [{"name": "malware", "rule": "...", "description": "d"}]
    call_count = {"n": 0}

    def fake_triggers():
        call_count["n"] += 1
        return catalog

    monkeypatch.setattr(shodan_api, "alert_triggers", fake_triggers)

    assert monitor.triggers_catalog() == catalog
    assert monitor.triggers_catalog() == catalog
    # second call served from the SQLite cache
    assert call_count["n"] == 1
