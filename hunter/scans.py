"""On-demand scan submission with an authorization gate.

Scanning hits your account's *scan* credit pool and, more importantly, points
Shodan's crawlers at a target. We never submit a scan unless the targets are
either inside a configured allowlist (SH_SCAN_ALLOWLIST) or the operator has
explicitly confirmed authorization for this request. Every submission is logged.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from . import config, db, recon, shodan_api


class ScanInputError(ValueError):
    """Targets were malformed or empty."""


class ScanNotAuthorized(PermissionError):
    """Targets failed the authorization gate."""


def _covered(target: str, allow_nets: list[ipaddress._BaseNetwork]) -> bool:
    try:
        tnet = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return False
    for a in allow_nets:
        try:
            if tnet.version == a.version and tnet.subnet_of(a):
                return True
        except (TypeError, ValueError):
            continue
    return False


def authorize(
    targets: list[str], *, allowlist: list[str], user_confirmed: bool, max_hosts: int,
) -> tuple[bool, str]:
    """Decide whether a scan of `targets` may proceed. Returns (ok, reason)."""
    n = recon.count_hosts(targets)
    if n > max_hosts:
        return False, f"{n} hosts exceeds the per-scan ceiling (SH_SCAN_MAX_HOSTS={max_hosts})"
    if allowlist:
        allow_nets = []
        for a in allowlist:
            try:
                allow_nets.append(ipaddress.ip_network(a, strict=False))
            except ValueError:
                continue
        uncovered = [t for t in targets if not _covered(t, allow_nets)]
        if uncovered:
            return False, "outside the scan allowlist: " + ", ".join(uncovered)
        return True, "within configured allowlist"
    if not user_confirmed:
        return False, (
            "no allowlist configured (SH_SCAN_ALLOWLIST is empty) — explicit "
            "authorization confirmation is required for each scan"
        )
    return True, "operator-confirmed authorization (no allowlist configured)"


def submit(raw: str, *, user: str, user_confirmed: bool = False) -> dict[str, Any]:
    """Validate + authorize + submit a scan. Raises ScanInputError /
    ScanNotAuthorized on rejection; otherwise records the job and returns it."""
    targets, invalid = recon.parse_ip_targets(raw)
    if invalid:
        raise ScanInputError("invalid scan targets: " + ", ".join(invalid))
    if not targets:
        raise ScanInputError("no scan targets provided")

    ok, reason = authorize(
        targets,
        allowlist=config.SCAN_ALLOWLIST,
        user_confirmed=user_confirmed,
        max_hosts=config.SCAN_MAX_HOSTS,
    )
    if not ok:
        raise ScanNotAuthorized(reason)

    res = shodan_api.submit_scan(targets)
    scan_id = res.get("id") if isinstance(res, dict) else None
    if scan_id:
        db.record_scan(
            scan_id=scan_id,
            targets=", ".join(targets),
            host_count=recon.count_hosts(targets),
            status=res.get("status") or "SUBMITTING",
            submitted_by=user,
        )
    return {"targets": targets, "result": res, "authorization": reason, "scan_id": scan_id}


def refresh(scan_id: str) -> dict[str, Any]:
    """Poll live status, persist it, return both the live status and local row."""
    status = shodan_api.scan_status(scan_id)
    db.update_scan_status(scan_id, status.get("status") if isinstance(status, dict) else None)
    return {"status": status, "row": db.get_scan_row(scan_id)}
