"""Thin Shodan client: search, count, host, DNS, scan, alerts, labs.

Every paid endpoint goes through the shared budget (db.spend) and SQLite cache;
free endpoints (count, honeyscore, dns/resolve, dns/reverse, community queries)
skip the budget. The official `shodan` library lacks dns/resolve + dns/reverse,
so those two are issued as raw REST against the same base URL and key.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Iterable

import requests
import shodan

from . import config, db

_API_INFO_TTL = 300.0  # 5 minutes; remaining credits change with every paid call
_api_info_cache: dict[str, Any] = {"data": None, "ts": 0.0}

_BASE_URL = "https://api.shodan.io"
_REST_TIMEOUT = 10.0
_rest = requests.Session()
_rest.headers["User-Agent"] = "shodan-hunter/0.3 (+internal recon)"


class ShodanNotConfigured(RuntimeError):
    pass


class ShodanError(RuntimeError):
    pass


_client: shodan.Shodan | None = None


def _api() -> shodan.Shodan:
    global _client
    if not config.SHODAN_API_KEY:
        raise ShodanNotConfigured(
            "SHODAN_API_KEY is not set. Add it to .env and restart."
        )
    if _client is None:
        _client = shodan.Shodan(config.SHODAN_API_KEY)
    return _client


def _rest_get(path: str, params: dict[str, Any]) -> Any:
    """Raw REST GET against api.shodan.io for endpoints the lib doesn't wrap.

    Adds the key automatically and normalizes errors to ShodanError so callers
    handle one exception type regardless of whether they hit the lib or REST.
    """
    if not config.SHODAN_API_KEY:
        raise ShodanNotConfigured("SHODAN_API_KEY is not set. Add it to .env and restart.")
    p = dict(params)
    p["key"] = config.SHODAN_API_KEY
    try:
        r = _rest.get(f"{_BASE_URL}{path}", params=p, timeout=_REST_TIMEOUT)
    except requests.RequestException as e:
        raise ShodanError(f"{path} request failed: {e}") from e
    if r.status_code == 401:
        raise ShodanError("Invalid API key")
    if not r.ok:
        try:
            msg = r.json().get("error") or f"HTTP {r.status_code}"
        except ValueError:
            msg = f"HTTP {r.status_code}"
        raise ShodanError(f"{path}: {msg}")
    try:
        return r.json()
    except ValueError as e:
        raise ShodanError(f"{path}: response was not JSON") from e


def _qkey(q: str) -> str:
    return " ".join(q.strip().split())


def _facet_key(facets: Iterable[str] | None) -> str:
    if not facets:
        return ""
    return ",".join(sorted(str(f) for f in facets))


def _chunks(items: list[Any], size: int) -> Iterable[list[Any]]:
    for i in range(0, len(items), size):
        yield items[i:i + size]


# ── search (1 credit / page, cache-backed) ───────────────────────────────


def search(query: str, page: int = 1, *, facets: list[str] | None = None,
           use_cache: bool = True) -> dict[str, Any]:
    q = _qkey(query)
    key = f"{q}|p={page}|f={_facet_key(facets)}"
    if use_cache:
        hit = db.cache_get("search", key)
        if hit is not None:
            hit["_cache"] = "hit"
            return hit

    db.spend(1)  # raises BudgetExceeded on cap
    try:
        data = _api().search(q, page=page, minify=True, facets=facets or None)
    except shodan.APIError as e:
        raise ShodanError(f"search({q!r}) failed: {e}") from e
    db.cache_put("search", key, data, config.SEARCH_CACHE_TTL)
    bust_api_info_cache()
    data["_cache"] = "miss"
    return data


# ── count (FREE) — handy for previewing volume + facet aggregates ─────────


def count(query: str, *, facets: list[str] | None = None,
          use_cache: bool = True) -> dict[str, Any]:
    """Result count + optional facet aggregates. FREE (no query credit)."""
    q = _qkey(query)
    cache_key = f"{q}|f={_facet_key(facets)}"
    if facets and use_cache:
        hit = db.cache_get("count", cache_key)
        if hit is not None:
            hit["_cache"] = "hit"
            return hit
    try:
        data = _api().count(q, facets=facets or None)
    except shodan.APIError as e:
        raise ShodanError(f"count({q!r}) failed: {e}") from e
    if facets:
        db.cache_put("count", cache_key, data, config.SEARCH_CACHE_TTL)
    data["_cache"] = "miss"
    return data


def facet_summary(query: str, facets: list[str]) -> dict[str, list[dict]]:
    """Return just the {facet_name: [{value, count}, ...]} map for a query.

    Uses the free count endpoint so the results page can show aggregate charts
    without spending a credit — even when the search itself was a cache hit.
    """
    if not facets:
        return {}
    data = count(query, facets=facets)
    return data.get("facets") or {}


# ── host detail (1 credit, cached) ───────────────────────────────────────


NO_DATA_MARKERS = ("No information available", "Unable to fetch information")


def host(ip: str, *, use_cache: bool = True) -> dict[str, Any]:
    ip = ip.strip()
    if use_cache:
        hit = db.cache_get("host", ip)
        if hit is not None:
            hit["_cache"] = "hit"
            return hit

    db.spend(1)
    try:
        data = _api().host(ip, history=False, minify=False)
    except shodan.APIError as e:
        msg = str(e)
        if any(m in msg for m in NO_DATA_MARKERS):
            payload = {"ip_str": ip, "no_data": True, "message": msg, "data": [], "ports": [], "hostnames": []}
            db.cache_put("host", ip, payload, config.HOST_CACHE_TTL)
            payload["_cache"] = "miss"
            return payload
        raise ShodanError(f"host({ip}) failed: {e}") from e

    db.cache_put("host", ip, data, config.HOST_CACHE_TTL)
    bust_api_info_cache()
    data["_cache"] = "miss"
    return data


# ── honeyscore (FREE) — ICS-honeypot probability 0.0–1.0 ──────────────────

# Shodan retired the standalone honeyscore lab in favour of a `honeypot` tag
# baked into normal results ("integrated into the regular crawlers"). We treat
# that message as "no score" and rely on tag-based detection (see recon.py).
_HONEYSCORE_RETIRED = "integrated into the regular crawlers"


def honeyscore(ip: str, *, use_cache: bool = True) -> float | None:
    """Legacy per-IP honeypot probability (0.0–1.0), or None.

    Shodan has retired this lab endpoint, so in practice this now returns None;
    honeypot detection rides on the `honeypot` tag instead. Kept as a thin,
    fail-soft wrapper. Free — no query credit. Cached 24h."""
    ip = (ip or "").strip()
    if not ip:
        return None
    if use_cache:
        hit = db.cache_get("honeyscore", ip)
        if hit is not None:
            return hit.get("score")
    try:
        raw = _api().labs.honeyscore(ip)
    except shodan.APIError as e:
        msg = str(e)
        if "404" in msg or _HONEYSCORE_RETIRED in msg.lower() \
                or any(m in msg for m in NO_DATA_MARKERS):
            db.cache_put("honeyscore", ip, {"score": None}, config.HONEYSCORE_CACHE_TTL)
            return None
        raise ShodanError(f"honeyscore({ip}) failed: {e}") from e
    try:
        score = float(raw) if raw is not None else None
    except (TypeError, ValueError):
        score = None
    db.cache_put("honeyscore", ip, {"score": score}, config.HONEYSCORE_CACHE_TTL)
    return score


def honeyscore_many(ips: Iterable[str], *, cap: int | None = None) -> dict[str, float | None]:
    """Concurrent honeyscore lookups, capped (each is a free round-trip)."""
    cap = config.HONEYSCORE_ROW_CAP if cap is None else cap
    unique = [ip for ip in dict.fromkeys(i.strip() for i in ips if i) if ip][:cap]
    out: dict[str, float | None] = {}
    if not unique:
        return out
    with ThreadPoolExecutor(max_workers=8) as pool:
        futs = {pool.submit(honeyscore, ip): ip for ip in unique}
        for fut in as_completed(futs):
            ip = futs[fut]
            try:
                out[ip] = fut.result()
            except ShodanError:
                out[ip] = None
    return out


# ── DNS: domain info (1 credit), resolve + reverse (FREE) ─────────────────


def domain_info(domain: str, *, page: int = 1, use_cache: bool = True) -> dict[str, Any]:
    """Passive DNS for a domain: subdomains + records. Costs 1 query credit."""
    domain = (domain or "").strip().lower().lstrip("*.")
    if not domain:
        raise ShodanError("empty domain")
    key = f"{domain}|p={page}"
    if use_cache:
        hit = db.cache_get("domain", key)
        if hit is not None:
            hit["_cache"] = "hit"
            return hit
    db.spend(1)
    try:
        data = _api().dns.domain_info(domain, page=page)
    except shodan.APIError as e:
        msg = str(e)
        if any(m in msg for m in NO_DATA_MARKERS):
            payload = {"domain": domain, "no_data": True, "message": msg,
                       "subdomains": [], "data": []}
            db.cache_put("domain", key, payload, config.DOMAIN_CACHE_TTL)
            payload["_cache"] = "miss"
            return payload
        raise ShodanError(f"domain_info({domain!r}) failed: {e}") from e
    db.cache_put("domain", key, data, config.DOMAIN_CACHE_TTL)
    bust_api_info_cache()
    data["_cache"] = "miss"
    return data


def dns_resolve(hostnames: Iterable[str]) -> dict[str, str | None]:
    """Forward DNS for many hostnames -> {hostname: ip}. FREE. Batched (<=100)."""
    hosts = [h.strip() for h in dict.fromkeys(hostnames) if h and h.strip()]
    out: dict[str, str | None] = {}
    missing: list[str] = []
    for h in hosts:
        cached = db.cache_get("dns_resolve", h)
        if cached is not None:
            out[h] = cached.get("ip")
        else:
            missing.append(h)
    for chunk in _chunks(missing, 100):
        data = _rest_get("/dns/resolve", {"hostnames": ",".join(chunk)})
        for h in chunk:
            ip = data.get(h) if isinstance(data, dict) else None
            out[h] = ip
            db.cache_put("dns_resolve", h, {"ip": ip}, config.DNS_CACHE_TTL)
    return out


def dns_reverse(ips: Iterable[str]) -> dict[str, list[str]]:
    """Reverse DNS for many IPs -> {ip: [hostnames]}. FREE. Batched (<=100)."""
    addrs = [i.strip() for i in dict.fromkeys(ips) if i and i.strip()]
    out: dict[str, list[str]] = {}
    missing: list[str] = []
    for ip in addrs:
        cached = db.cache_get("dns_reverse", ip)
        if cached is not None:
            out[ip] = cached.get("hostnames") or []
        else:
            missing.append(ip)
    for chunk in _chunks(missing, 100):
        data = _rest_get("/dns/reverse", {"ips": ",".join(chunk)})
        for ip in chunk:
            names = (data.get(ip) if isinstance(data, dict) else None) or []
            out[ip] = names
            db.cache_put("dns_reverse", ip, {"hostnames": names}, config.DNS_CACHE_TTL)
    return out


# ── on-demand scanning (uses SCAN credits, not the query budget) ──────────


def submit_scan(targets: str | list[str], *, force: bool = False) -> dict[str, Any]:
    """Request a fresh Shodan crawl of IP(s)/CIDR(s). Returns {id, count, credits_left}.
    Spends scan credits — caller is responsible for authorization."""
    try:
        res = _api().scan(targets, force=force)
    except shodan.APIError as e:
        raise ShodanError(f"scan submit failed: {e}") from e
    bust_api_info_cache()  # scan credits changed
    return res


def scan_status(scan_id: str) -> dict[str, Any]:
    """Status of a previously-submitted scan. Free."""
    try:
        return _api().scan_status(scan_id)
    except shodan.APIError as e:
        raise ShodanError(f"scan_status({scan_id}) failed: {e}") from e


def list_scans(page: int = 1) -> dict[str, Any]:
    try:
        return _api().scans(page=page)
    except shodan.APIError as e:
        raise ShodanError(f"scans list failed: {e}") from e


# ── network alerts / monitoring (management is FREE of query credits) ─────


def list_alerts(include_expired: bool = True) -> list[dict[str, Any]]:
    try:
        res = _api().alerts(include_expired=include_expired)
    except shodan.APIError as e:
        raise ShodanError(f"alerts list failed: {e}") from e
    return res if isinstance(res, list) else []


def get_alert(aid: str) -> dict[str, Any]:
    try:
        return _api().alerts(aid=aid)
    except shodan.APIError as e:
        raise ShodanError(f"alert {aid} fetch failed: {e}") from e


def create_alert(name: str, ip: str | list[str], expires: int = 0) -> dict[str, Any]:
    try:
        return _api().create_alert(name, ip, expires=expires)
    except shodan.APIError as e:
        raise ShodanError(f"create alert failed: {e}") from e


def delete_alert(aid: str) -> Any:
    try:
        return _api().delete_alert(aid)
    except shodan.APIError as e:
        raise ShodanError(f"delete alert {aid} failed: {e}") from e


def edit_alert(aid: str, ip: str | list[str]) -> dict[str, Any]:
    try:
        return _api().edit_alert(aid, ip)
    except shodan.APIError as e:
        raise ShodanError(f"edit alert {aid} failed: {e}") from e


def alert_triggers() -> list[dict[str, Any]]:
    try:
        res = _api().alert_triggers()
    except shodan.APIError as e:
        raise ShodanError(f"alert triggers fetch failed: {e}") from e
    return res if isinstance(res, list) else []


def enable_alert_trigger(aid: str, trigger: str) -> Any:
    try:
        return _api().enable_alert_trigger(aid, trigger)
    except shodan.APIError as e:
        raise ShodanError(f"enable trigger {trigger} failed: {e}") from e


def disable_alert_trigger(aid: str, trigger: str) -> Any:
    try:
        return _api().disable_alert_trigger(aid, trigger)
    except shodan.APIError as e:
        raise ShodanError(f"disable trigger {trigger} failed: {e}") from e


# ── community-curated saved queries (FREE) ────────────────────────────────


def community_queries(page: int = 1, sort: str = "votes", order: str = "desc",
                      *, use_cache: bool = True) -> dict[str, Any]:
    """Directory of search queries shared by the Shodan community."""
    key = f"p={page}|s={sort}|o={order}"
    if use_cache:
        hit = db.cache_get("queries", key)
        if hit is not None:
            return hit
    try:
        data = _api().queries(page=page, sort=sort, order=order)
    except shodan.APIError as e:
        raise ShodanError(f"community queries failed: {e}") from e
    db.cache_put("queries", key, data, config.QUERIES_CACHE_TTL)
    return data


def query_search(query: str, page: int = 1, *, use_cache: bool = True) -> dict[str, Any]:
    """Search the community query directory."""
    q = _qkey(query)
    key = f"{q}|p={page}"
    if use_cache:
        hit = db.cache_get("query_search", key)
        if hit is not None:
            return hit
    try:
        data = _api().queries_search(q, page=page)
    except shodan.APIError as e:
        raise ShodanError(f"query search failed: {e}") from e
    db.cache_put("query_search", key, data, config.QUERIES_CACHE_TTL)
    return data


# ── api info ─────────────────────────────────────────────────────────────


def api_info(*, force_refresh: bool = False) -> dict[str, Any]:
    """Live Shodan account info. Cached 5 min to avoid per-render round-trips."""
    now = time.time()
    if not force_refresh and _api_info_cache["data"] is not None \
            and now - _api_info_cache["ts"] < _API_INFO_TTL:
        return _api_info_cache["data"]
    try:
        info = _api().info()
    except shodan.APIError as e:
        raise ShodanError(f"info failed: {e}") from e
    data = {
        "plan": info.get("plan"),
        "query_credits": info.get("query_credits"),
        "scan_credits": info.get("scan_credits"),
        "monitored_ips": info.get("monitored_ips"),
        "https": info.get("https"),
        "unlocked": info.get("unlocked"),
    }
    _api_info_cache.update({"data": data, "ts": now})
    return data


def bust_api_info_cache() -> None:
    """Force the next api_info() call to refetch. Call after a credit-spending op."""
    _api_info_cache["data"] = None
    _api_info_cache["ts"] = 0.0
