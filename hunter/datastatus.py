"""Shodan "Data Status" snapshot — the global picture of what Shodan's crawlers
are seeing across the whole Internet (https://data-status.shodan.io/).

That page has no JSON API: it's a 200 KB server-rendered HTML page that embeds
its datasets as ``var x = [...]`` literals (for the charts) and a few HTML
tables (the CVE spotlight). We fetch it once, parse those out into clean Python
structures, and cache the result — it only refreshes ~daily. Keyless and free:
no Shodan API key, no query credits.

``parse_html`` is pure (HTML in → dict out) so it's unit-tested against a small
fixture. ``build_view`` turns that raw snapshot into the percentages, conic-
gradient strings, flags and severities the dashboard template renders — also
pure. ``snapshot`` is the cached fetch+parse the route actually calls.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

import requests

from . import config, db
from .recon import country_flag, severity_from_cvss

log = logging.getLogger(__name__)

URL = "https://data-status.shodan.io/"
_NS = "datastatus"
_TIMEOUT = 15.0

_session = requests.Session()
_session.headers["User-Agent"] = "shodan-hunter/0.3 (+internal team dashboard)"

# Shodan's own chart palette — reads well on the app's dark theme, and keeps the
# category colours stable across refreshes.
PALETTE = [
    "#3B82F6", "#10B981", "#F59E0B", "#8B5CF6", "#EC4899", "#14B8A6", "#6366F1",
    "#F97316", "#06B6D4", "#84CC16", "#EF4444", "#0EA5E9", "#D946EF", "#A855F7",
    "#22D3EE", "#4ADE80", "#FB923C", "#818CF8", "#FBBF24", "#78716C",
]


class DataStatusError(RuntimeError):
    """Fetch or parse of the data-status page failed."""


# ── fetch + parse ────────────────────────────────────────────────────────────


def fetch_raw() -> str:
    try:
        r = _session.get(URL, timeout=_TIMEOUT)
    except requests.RequestException as e:
        raise DataStatusError(f"could not reach {URL}: {e}") from e
    if not r.ok:
        raise DataStatusError(f"{URL} returned HTTP {r.status_code}")
    return r.text


def _js_array(html: str, name: str) -> list[dict]:
    """Pull a ``var name = [ {...}, ... ]`` JSON array out of an inline script.

    The arrays hold flat objects (no nested brackets), so a non-greedy match up
    to the first ``]`` is safe. Also matches ``const name = [...]`` inside the
    choropleth IIFE. Returns [] if absent/unparseable — each dataset is optional.
    """
    m = re.search(rf"(?:var|const|let)\s+{re.escape(name)}\s*=\s*(\[[^\]]*\])", html)
    if not m:
        return []
    try:
        data = json.loads(m.group(1))
        return data if isinstance(data, list) else []
    except json.JSONDecodeError:
        log.warning("data-status: could not parse array %r", name)
        return []


def _parse_cve_tables(html: str) -> list[dict]:
    """Every CVE row across all spotlight tables, deduped by CVE id (keeping the
    highest prevalence count). Each row: ``{id, count, epss, cvss}``."""
    by_id: dict[str, dict] = {}
    for table in re.findall(r"<table.*?</table>", html, re.S):
        header = " ".join(re.findall(r"<th[^>]*>(.*?)</th>", table, re.S))
        if "CVE" not in header:
            continue
        for tr in re.findall(r"<tr[^>]*>(.*?)</tr>", table, re.S):
            cells = [re.sub(r"<[^>]+>", "", c).strip()
                     for c in re.findall(r"<td[^>]*>(.*?)</td>", tr, re.S)]
            if len(cells) < 4 or not cells[0].startswith("CVE-"):
                continue
            cve = cells[0]
            count = _to_int(cells[1])
            row = {"id": cve, "count": count,
                   "epss": _to_float(cells[2]), "cvss": _to_float(cells[3])}
            if cve not in by_id or count > by_id[cve]["count"]:
                by_id[cve] = row
    return list(by_id.values())


def _to_int(s: str) -> int:
    try:
        return int(re.sub(r"[,\s]", "", s))
    except (ValueError, TypeError):
        return 0


def _to_float(s: str) -> float | None:
    try:
        return float(str(s).strip())
    except (ValueError, TypeError):
        return None


def parse_html(html: str) -> dict[str, Any]:
    """Pure parse of the data-status page into raw datasets."""
    updated_m = re.search(r"Updated at\s*([0-9]{4}-[0-9]{2}-[0-9]{2})", html)
    scanned_m = re.search(r"(?:var|const|let)\s+scanned\s*=\s*(\d+)", html)
    return {
        "updated": updated_m.group(1) if updated_m else None,
        "categories": _js_array(html, "categories"),
        "ports": _js_array(html, "topPorts"),
        "protocols": _js_array(html, "services"),
        "orgs": _js_array(html, "orgs"),
        "products": _js_array(html, "products"),
        "countries": _js_array(html, "topCountries"),
        "hostname_scanned": int(scanned_m.group(1)) if scanned_m else 0,
        "cves": _parse_cve_tables(html),
    }


# ── presentation: percentages, doughnut gradients, flags, severities ─────────


def _conic_segments(items: list[dict], total: float, limit: int = 14) -> tuple[list[dict], str]:
    """Build legend segments + a CSS ``conic-gradient(...)`` for a doughnut ring.

    Each segment gets a colour and its share of ``total``; slices past ``limit``
    are folded into a trailing grey "Other" wedge so the ring always closes."""
    segs: list[dict] = []
    acc = 0.0
    stops: list[str] = []
    head = items[:limit]
    for i, it in enumerate(head):
        count = it.get("count", 0) or 0
        pct = (100.0 * count / total) if total else 0.0
        color = PALETTE[i % len(PALETTE)]
        start, acc = acc, acc + pct
        stops.append(f"{color} {start:.3f}% {acc:.3f}%")
        segs.append({"name": it.get("name", "?"), "count": count,
                     "pct": round(pct, 1), "color": color})
    if acc < 99.95:  # remainder (the long tail beyond `limit`)
        stops.append(f"#30363d {acc:.3f}% 100%")
    gradient = "conic-gradient(" + ", ".join(stops) + ")"
    return segs, gradient


def _bars(items: list[dict], total: float, *, key: str = "name", limit: int = 12) -> list[dict]:
    """Horizontal-bar rows: each scaled both to the page total (share) and to the
    largest item in the list (bar width)."""
    rows = items[:limit]
    mx = max((r.get("count", 0) or 0 for r in rows), default=0) or 1
    out = []
    for r in rows:
        count = r.get("count", 0) or 0
        out.append({
            "label": r.get(key),
            "count": count,
            "pct": round(100.0 * count / total, 2) if total else 0.0,
            "barpct": round(100.0 * count / mx, 1),
            "raw": r,
        })
    return out


def build_view(snap: dict[str, Any]) -> dict[str, Any]:
    """Turn a raw snapshot into everything the dashboard template needs."""
    categories = snap.get("categories") or []
    protocols = snap.get("protocols") or []
    ports = snap.get("ports") or []
    orgs = snap.get("orgs") or []
    products = snap.get("products") or []
    countries = snap.get("countries") or []
    cves = snap.get("cves") or []

    total = float(sum((c.get("count", 0) or 0) for c in categories)) or \
        float(sum((p.get("count", 0) or 0) for p in protocols))

    cat_segs, cat_grad = _conic_segments(categories, total)
    proto_total = float(sum((p.get("count", 0) or 0) for p in protocols)) or total
    proto_segs, proto_grad = _conic_segments(protocols, proto_total, limit=6)

    tcp = next((p.get("count", 0) for p in protocols if str(p.get("name")).lower() == "tcp"), 0)
    udp = next((p.get("count", 0) for p in protocols if str(p.get("name")).lower() == "udp"), 0)

    scanned = snap.get("hostname_scanned", 0) or 0
    host_pct = round(100.0 * scanned / total, 1) if total else 0.0
    host_grad = (
        f"conic-gradient(var(--accent) 0% {host_pct:.2f}%, "
        f"#30363d {host_pct:.2f}% 100%)"
    )

    # Country bars carry a flag (reusing the search-side helper).
    country_bars = _bars(countries, total, key="name", limit=12)
    for cb in country_bars:
        cb["flag"] = country_flag((cb["raw"] or {}).get("code"))
        cb["code"] = (cb["raw"] or {}).get("code")

    # CVE threat board: tag each row with a severity + EPSS-as-percent, then
    # derive two curated views from the same master list.
    for v in cves:
        v["severity"] = severity_from_cvss(v.get("cvss"))
        v["epss_pct"] = round((v.get("epss") or 0.0) * 100, 1)
    critical = sorted([v for v in cves if (v.get("cvss") or 0) >= 9.0],
                      key=lambda v: v["count"], reverse=True)[:12]
    high_epss = sorted([v for v in cves if (v.get("epss") or 0) >= 0.5],
                       key=lambda v: (v.get("epss") or 0), reverse=True)[:12]

    return {
        "updated": snap.get("updated"),
        "total": int(total),
        "hero": {
            "total": int(total),
            "tcp": tcp, "udp": udp,
            "tcp_pct": round(100.0 * tcp / (tcp + udp), 1) if (tcp + udp) else 0,
            "udp_pct": round(100.0 * udp / (tcp + udp), 1) if (tcp + udp) else 0,
            "country_count": len(countries),
            "category_count": len(categories),
            "hostname_scanned": scanned,
            "hostname_pct": host_pct,
            "top_port": ports[0].get("port") if ports else None,
            "cve_count": len(cves),
        },
        "categories": {"segments": cat_segs, "gradient": cat_grad},
        "protocols": {"segments": proto_segs, "gradient": proto_grad},
        "hostname": {"scanned": scanned, "pct": host_pct, "gradient": host_grad},
        "ports": _bars(ports, total, key="port", limit=15),
        "orgs": _bars(orgs, total, key="name", limit=10),
        "products": _bars(products, total, key="name", limit=10),
        "countries": country_bars,
        "cve_critical": critical,
        "cve_high_epss": high_epss,
    }


# ── cached snapshot the route calls ──────────────────────────────────────────


def snapshot(*, use_cache: bool = True) -> dict[str, Any]:
    """Cached raw snapshot of the data-status page (TTL ~6h by default)."""
    if use_cache:
        hit = db.cache_get(_NS, "page")
        if hit is not None:
            hit["_cache"] = "hit"
            return hit
    data = parse_html(fetch_raw())
    if not data.get("categories") and not data.get("protocols"):
        raise DataStatusError("data-status page parsed but contained no datasets "
                              "(the page layout may have changed)")
    db.cache_put(_NS, "page", data, config.DATASTATUS_CACHE_TTL)
    data["_cache"] = "miss"
    return data
