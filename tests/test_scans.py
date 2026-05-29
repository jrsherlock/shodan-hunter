"""Unit tests for hunter.scans — the authorization gate and submit flow."""

from __future__ import annotations

import ipaddress

from hunter import config, db, scans, shodan_api


# ── authorize: every branch ──────────────────────────────────────────────────


def test_authorize_allowlist_covered_true():
    ok, reason = scans.authorize(
        ["1.2.3.4"], allowlist=["1.2.3.0/24"], user_confirmed=False, max_hosts=4096
    )
    assert ok is True
    assert reason == "within configured allowlist"


def test_authorize_allowlist_uncovered_names_bad_target():
    ok, reason = scans.authorize(
        ["1.2.3.4", "9.9.9.9"], allowlist=["1.2.3.0/24"],
        user_confirmed=False, max_hosts=4096,
    )
    assert ok is False
    assert "outside the scan allowlist" in reason
    assert "9.9.9.9" in reason
    assert "1.2.3.4" not in reason  # the covered one is not named


def test_authorize_empty_allowlist_unconfirmed_false():
    ok, reason = scans.authorize(
        ["1.2.3.4"], allowlist=[], user_confirmed=False, max_hosts=4096
    )
    assert ok is False
    assert "no allowlist configured" in reason


def test_authorize_empty_allowlist_confirmed_true():
    ok, reason = scans.authorize(
        ["1.2.3.4"], allowlist=[], user_confirmed=True, max_hosts=4096
    )
    assert ok is True
    assert "operator-confirmed" in reason


def test_authorize_over_max_hosts_false():
    # /24 = 256 hosts, ceiling of 1 -> rejected before the allowlist check
    ok, reason = scans.authorize(
        ["10.0.0.0/24"], allowlist=["10.0.0.0/8"], user_confirmed=True, max_hosts=1
    )
    assert ok is False
    assert "exceeds the per-scan ceiling" in reason
    assert "256 hosts" in reason


def test_authorize_max_hosts_takes_priority_over_allowlist():
    # Even a fully-covered, confirmed request is rejected when too large.
    ok, _ = scans.authorize(
        ["10.0.0.0/8"], allowlist=["10.0.0.0/8"], user_confirmed=True, max_hosts=10
    )
    assert ok is False


# ── _covered: IPv4/IPv6 mismatch must not crash ──────────────────────────────


def test_covered_version_mismatch_is_false_not_crash():
    allow = [ipaddress.ip_network("10.0.0.0/8")]
    assert scans._covered("2001:db8::/32", allow) is False


def test_covered_invalid_target_is_false():
    allow = [ipaddress.ip_network("10.0.0.0/8")]
    assert scans._covered("definitely-not-an-ip", allow) is False


def test_covered_true_for_subnet():
    allow = [ipaddress.ip_network("192.168.0.0/16")]
    assert scans._covered("192.168.1.0/24", allow) is True


# ── submit: happy path records a scan_jobs row ───────────────────────────────


def test_submit_happy_path_records_job(monkeypatch):
    monkeypatch.setattr(config, "SCAN_ALLOWLIST", ["1.2.3.0/24"])
    monkeypatch.setattr(config, "SCAN_MAX_HOSTS", 4096)

    captured = {}

    def fake_submit_scan(targets, *, force=False):
        captured["targets"] = targets
        return {"id": "abc", "count": 1, "credits_left": 5, "status": "SUBMITTING"}

    monkeypatch.setattr(shodan_api, "submit_scan", fake_submit_scan)

    out = scans.submit("1.2.3.4", user="tester")
    assert out["scan_id"] == "abc"
    assert out["targets"] == ["1.2.3.4"]
    assert out["authorization"] == "within configured allowlist"
    assert captured["targets"] == ["1.2.3.4"]

    row = db.get_scan_row("abc")
    assert row is not None
    assert row["scan_id"] == "abc"
    assert row["submitted_by"] == "tester"
    assert row["host_count"] == 1
    assert row["targets"] == "1.2.3.4"
    assert row["status"] == "SUBMITTING"


def test_submit_invalid_targets_raises_input_error(monkeypatch):
    # submit_scan must never be called when input is malformed
    monkeypatch.setattr(shodan_api, "submit_scan",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("should not be called")))
    try:
        scans.submit("not-an-ip", user="tester", user_confirmed=True)
        raise AssertionError("expected ScanInputError")
    except scans.ScanInputError as e:
        assert "invalid scan targets" in str(e)
        assert "not-an-ip" in str(e)


def test_submit_empty_targets_raises_input_error(monkeypatch):
    monkeypatch.setattr(shodan_api, "submit_scan",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("should not be called")))
    try:
        scans.submit("   ", user="tester", user_confirmed=True)
        raise AssertionError("expected ScanInputError")
    except scans.ScanInputError as e:
        assert "no scan targets" in str(e)


def test_submit_unauthorized_raises_when_gate_fails(monkeypatch):
    # empty allowlist + not confirmed -> gate fails before any API call
    monkeypatch.setattr(config, "SCAN_ALLOWLIST", [])
    monkeypatch.setattr(shodan_api, "submit_scan",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("should not be called")))
    try:
        scans.submit("1.2.3.4", user="tester", user_confirmed=False)
        raise AssertionError("expected ScanNotAuthorized")
    except scans.ScanNotAuthorized as e:
        assert "no allowlist configured" in str(e)
    # nothing recorded
    assert db.recent_scans() == []


def test_submit_no_id_in_response_records_nothing(monkeypatch):
    monkeypatch.setattr(config, "SCAN_ALLOWLIST", [])
    monkeypatch.setattr(shodan_api, "submit_scan", lambda *a, **k: {"error": "nope"})
    out = scans.submit("1.2.3.4", user="tester", user_confirmed=True)
    assert out["scan_id"] is None
    assert db.recent_scans() == []
