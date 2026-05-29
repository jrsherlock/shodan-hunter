"""Shodan InternetDB: free, keyless, no-credit-cost per-IP enrichment.

Endpoint: https://internetdb.shodan.io/{ip}
Returns: {cpes, hostnames, ip, ports, tags, vulns}  (404 if the IP isn't indexed)

We use this to enrich search results — vulns and tags don't always make it
into a minified search response, but they're free to fetch here. Results are
cached in the existing SQLite cache for 24h.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Iterable

import requests

from . import db

log = logging.getLogger(__name__)

_BASE = "https://internetdb.shodan.io"
_TTL = 86400  # 24h — InternetDB updates daily at most
_TIMEOUT = 4.0
_MAX_WORKERS = 8
_NS = "internetdb"

_session = requests.Session()
_session.headers["User-Agent"] = "shodan-hunter/0.2 (+internal recon)"


def _empty() -> dict[str, Any]:
    return {"tags": [], "vulns": [], "cpes": [], "hostnames": [], "ports": []}


def lookup(ip: str) -> dict[str, Any]:
    """Look up one IP. Returns enrichment dict (empty if not indexed)."""
    ip = (ip or "").strip()
    if not ip:
        return _empty()
    hit = db.cache_get(_NS, ip)
    if hit is not None:
        return hit
    try:
        r = _session.get(f"{_BASE}/{ip}", timeout=_TIMEOUT)
    except requests.RequestException as e:
        log.warning("internetdb lookup failed for %s: %s", ip, e)
        return _empty()
    if r.status_code == 404:
        data = _empty()
    elif r.ok:
        try:
            payload = r.json()
        except ValueError:
            return _empty()
        data = {
            "tags": payload.get("tags") or [],
            "vulns": payload.get("vulns") or [],
            "cpes": payload.get("cpes") or [],
            "hostnames": payload.get("hostnames") or [],
            "ports": payload.get("ports") or [],
        }
    else:
        log.warning("internetdb HTTP %s for %s", r.status_code, ip)
        return _empty()
    db.cache_put(_NS, ip, data, _TTL)
    return data


def lookup_many(ips: Iterable[str]) -> dict[str, dict[str, Any]]:
    """Concurrent batch lookup. Returns {ip: enrichment}."""
    unique = [ip for ip in dict.fromkeys(ips) if ip]
    if not unique:
        return {}
    out: dict[str, dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
        future_to_ip = {pool.submit(lookup, ip): ip for ip in unique}
        for fut in as_completed(future_to_ip):
            ip = future_to_ip[fut]
            try:
                out[ip] = fut.result()
            except Exception as e:
                log.warning("internetdb worker failed for %s: %s", ip, e)
                out[ip] = _empty()
    return out
