"""Network alerts / continuous monitoring.

Shodan is the source of truth for registered alerts; this module wraps the
management calls and keeps a small local mirror so the team log knows *who*
registered each alert. Live event delivery (a service appearing, a CVE
matching) is streamed by Shodan's alert firehose — surfacing that stream is a
future step; this module covers registration, triggers, and inspection.
"""

from __future__ import annotations

from typing import Any

from . import db, recon, shodan_api

_TRIGGER_TTL = 86400  # trigger catalog is essentially static


def triggers_catalog() -> list[dict[str, Any]]:
    """Available alert triggers ({name, rule, description}). Cached 24h."""
    hit = db.cache_get("alert_triggers", "all")
    if hit is not None:
        return hit
    cat = shodan_api.alert_triggers()
    db.cache_put("alert_triggers", "all", cat, _TRIGGER_TTL)
    return cat


def _normalize(alert: dict[str, Any]) -> dict[str, Any]:
    filters = alert.get("filters") or {}
    ip = filters.get("ip")
    ips = ip if isinstance(ip, list) else ([ip] if ip else [])
    triggers = alert.get("triggers") or {}
    return {
        "id": alert.get("id"),
        "name": alert.get("name"),
        "ips": ips,
        "filters": filters,
        "triggers": list(triggers.keys()) if isinstance(triggers, dict) else list(triggers or []),
        "size": alert.get("size"),
        "expires": alert.get("expires") or alert.get("expiration"),
        "created": alert.get("created"),
    }


def list_with_meta() -> list[dict[str, Any]]:
    """All registered alerts, normalized + annotated with local created_by."""
    out: list[dict[str, Any]] = []
    for a in shodan_api.list_alerts():
        n = _normalize(a)
        meta = db.get_alert_meta(n["id"]) if n["id"] else None
        n["created_by"] = (meta or {}).get("created_by")
        if n["id"]:
            db.upsert_alert(
                aid=n["id"], name=n["name"], filters=n["filters"],
                triggers=n["triggers"], created_by=n["created_by"],
            )
        out.append(n)
    return out


def create(name: str, raw_ips: str, *, user: str,
           triggers: list[str] | None = None) -> dict[str, Any]:
    """Register an alert over the given IP/CIDR blob and enable any triggers."""
    targets, invalid = recon.parse_ip_targets(raw_ips)
    if invalid:
        raise ValueError("invalid IP/CIDR: " + ", ".join(invalid))
    if not targets:
        raise ValueError("no IP/CIDR provided to monitor")

    res = shodan_api.create_alert(name, targets)
    aid = res.get("id") if isinstance(res, dict) else None

    enabled: list[str] = []
    for t in triggers or []:
        try:
            shodan_api.enable_alert_trigger(aid, t)
            enabled.append(t)
        except shodan_api.ShodanError:
            pass  # one bad trigger shouldn't drop the whole alert

    if aid:
        db.upsert_alert(
            aid=aid, name=name,
            filters=(res.get("filters") if isinstance(res, dict) else None) or {"ip": targets},
            triggers=enabled, created_by=user,
        )
    return {"id": aid, "result": res, "triggers_enabled": enabled, "targets": targets}


def delete(aid: str) -> None:
    shodan_api.delete_alert(aid)
    db.delete_alert_row(aid)


def set_trigger(aid: str, trigger: str, enabled: bool) -> None:
    if enabled:
        shodan_api.enable_alert_trigger(aid, trigger)
    else:
        shodan_api.disable_alert_trigger(aid, trigger)
