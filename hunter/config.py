"""Environment configuration. Loaded once at import."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _float(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


_TRUTHY = ("1", "true", "yes", "on")


def truthy(raw: str | None) -> bool:
    """Canonical truthy check for user/form-supplied strings.

    Use this — never ``bool(s)`` — to interpret a form field as a flag: a
    non-empty string like ``"false"``/``"0"``/``"off"`` is truthy under
    ``bool()``, which would wrongly authorize e.g. a scan submitted with
    ``confirm=false``.
    """
    return (raw or "").strip().lower() in _TRUTHY


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    return truthy(raw)


def _csv(name: str) -> list[str]:
    raw = os.environ.get(name, "")
    return [item.strip() for item in raw.split(",") if item.strip()]


# Shodan
SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "").strip() or None

# Azure OpenAI
AZURE_ENDPOINT = os.environ.get("AZURE_OPENAI_ENDPOINT", "").strip() or None
AZURE_API_KEY = os.environ.get("AZURE_OPENAI_API_KEY", "").strip() or None
AZURE_DEPLOYMENT = os.environ.get("AZURE_OPENAI_DEPLOYMENT", "").strip() or None
AZURE_API_VERSION = os.environ.get("AZURE_OPENAI_API_VERSION", "2024-10-21").strip()

# Auth — "user1:pw1,user2:pw2"
def _parse_users(raw: str) -> dict[str, str]:
    users: dict[str, str] = {}
    for pair in raw.split(","):
        pair = pair.strip()
        if not pair or ":" not in pair:
            continue
        u, _, p = pair.partition(":")
        u, p = u.strip(), p.strip()
        if u and p:
            users[u] = p
    return users


AUTH_USERS = _parse_users(os.environ.get("SH_AUTH_USERS", ""))

# Bind
BIND_HOST = os.environ.get("SH_HOST", "127.0.0.1").strip()
BIND_PORT = _int("SH_PORT", 8000)

# Storage
DB_PATH = Path(os.environ.get("SH_DB", "./data/hunter.db")).resolve()
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

# Budget
DAILY_BUDGET = _int("SH_DAILY_BUDGET", 200)

# Cache TTL for repeat searches (seconds)
SEARCH_CACHE_TTL = _int("SH_SEARCH_CACHE_TTL", 600)
HOST_CACHE_TTL = _int("SH_HOST_CACHE_TTL", 3600)
DOMAIN_CACHE_TTL = _int("SH_DOMAIN_CACHE_TTL", 21600)      # 6h — passive DNS is slow-moving
HONEYSCORE_CACHE_TTL = _int("SH_HONEYSCORE_CACHE_TTL", 86400)  # 24h
DNS_CACHE_TTL = _int("SH_DNS_CACHE_TTL", 3600)            # 1h for resolve/reverse
QUERIES_CACHE_TTL = _int("SH_QUERIES_CACHE_TTL", 3600)    # 1h for community query directory
DATASTATUS_CACHE_TTL = _int("SH_DATASTATUS_CACHE_TTL", 21600)  # 6h — the snapshot refreshes ~daily

# Honeypot flag: InternetDB/honeyscore >= this fraction earns a "honeypot?" badge.
HONEYPOT_THRESHOLD = _float("SH_HONEYPOT_THRESHOLD", 0.5)

# How many search-result rows to enrich with honeyscore per page (each is a free
# API call, but capped so a 100-row page doesn't fan out 100 round-trips).
HONEYSCORE_ROW_CAP = _int("SH_HONEYSCORE_ROW_CAP", 25)

# ── On-demand scanning (uses *scan* credits, not query credits) ─────────────
# Off by default: submitting scans is a write action against your account's
# scan-credit pool and must only target ranges you're authorized to scan.
SCAN_ENABLED = _bool("SH_ENABLE_SCAN", False)
# CIDRs / IPs you are authorized to scan. When set, scan requests are rejected
# unless every target falls inside the allowlist. When empty, the UI requires an
# explicit per-request "I am authorized" confirmation (still logged).
SCAN_ALLOWLIST = _csv("SH_SCAN_ALLOWLIST")
# Hard ceiling on host count per scan submission, regardless of allowlist.
SCAN_MAX_HOSTS = _int("SH_SCAN_MAX_HOSTS", 4096)

# ── Liveness probe (opens an outbound socket to the target) ─────────────────
# Off by default: this is the only feature that connects out to an
# operator-chosen host. When enabled, private/loopback/reserved targets are
# still refused unless PROBE_ALLOW_PRIVATE is also set (prevents using it as an
# internal port scanner). Every probe is audit-logged.
PROBE_ENABLED = _bool("SH_ENABLE_PROBE", False)
PROBE_ALLOW_PRIVATE = _bool("SH_PROBE_ALLOW_PRIVATE", False)
PROBE_TIMEOUT = _float("SH_PROBE_TIMEOUT", 3.0)

# ── Network alerts / monitoring ─────────────────────────────────────────────
# Registering alerts consumes your plan's monitored-IP pool. Management actions
# (create/list/delete) cost no query credits.
ALERTS_ENABLED = _bool("SH_ENABLE_ALERTS", True)


def status() -> dict:
    """Quick visibility for the UI: what's configured, what isn't."""
    return {
        "shodan": bool(SHODAN_API_KEY),
        "azure_openai": bool(AZURE_ENDPOINT and AZURE_API_KEY and AZURE_DEPLOYMENT),
        "auth_users_count": len(AUTH_USERS),
        "bind": f"{BIND_HOST}:{BIND_PORT}",
        "daily_budget": DAILY_BUDGET,
        "scan_enabled": SCAN_ENABLED,
        "scan_allowlisted": len(SCAN_ALLOWLIST),
        "alerts_enabled": ALERTS_ENABLED,
        "probe_enabled": PROBE_ENABLED,
    }
