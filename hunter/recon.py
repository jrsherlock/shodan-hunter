"""Pure-ish recon helpers: input parsing, DNS orchestration, facet shaping.

Everything here is easy to unit-test: the functions either transform data
structures or call the thin shodan_api wrappers. No HTTP/templating concerns.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from . import shodan_api

# Facets shown as the chart strip above search results. Pulled via the FREE
# count endpoint, so this costs no query credit. `vuln` is intentionally
# omitted — the vuln facet requires a paid plan and would error on free keys;
# the route still degrades gracefully if any facet is rejected.
DEFAULT_FACETS = ["country", "port", "org", "product", "asn", "os"]

FACET_LABELS = {
    "country": "Top countries",
    "port": "Top ports",
    "org": "Top orgs",
    "product": "Top products",
    "asn": "Top ASNs",
    "os": "Top OS",
    "vuln": "Top CVEs",
    "domain": "Top domains",
    "isp": "Top ISPs",
}

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9_](-?[a-zA-Z0-9_])*\.)+[a-zA-Z]{2,}$"
)


# ── input parsing ──────────────────────────────────────────────────────────


def split_blob(raw: str) -> list[str]:
    """Split a pasted blob into tokens on commas, semicolons, and whitespace."""
    if not raw:
        return []
    return [t for t in re.split(r"[\s,;]+", raw.strip()) if t]


def parse_ip_targets(raw: str) -> tuple[list[str], list[str]]:
    """Parse IPs/CIDRs from a blob. Returns (normalized_targets, invalid_tokens).

    Single addresses come back bare (1.2.3.4); CIDRs come back normalized
    (1.2.3.0/24). Anything that isn't a valid IP/CIDR lands in invalid_tokens.
    """
    targets: list[str] = []
    invalid: list[str] = []
    for tok in split_blob(raw):
        try:
            net = ipaddress.ip_network(tok, strict=False)
        except ValueError:
            invalid.append(tok)
            continue
        targets.append(str(net) if "/" in tok else str(net.network_address))
    return list(dict.fromkeys(targets)), list(dict.fromkeys(invalid))


def count_hosts(targets: list[str]) -> int:
    """Total addressable hosts across a list of IPs/CIDRs."""
    total = 0
    for t in targets:
        try:
            total += ipaddress.ip_network(t, strict=False).num_addresses
        except ValueError:
            total += 1
    return total


def classify_dns_inputs(raw: str) -> dict[str, list[str]]:
    """Split a blob into hostnames (for forward DNS) and IPs (for reverse DNS).

    Tolerates pasted URLs (strips scheme/path/port) and trailing dots.
    """
    hostnames: list[str] = []
    ips: list[str] = []
    invalid: list[str] = []
    for tok in split_blob(raw):
        t = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", "", tok.strip())
        t = t.split("/")[0].split("\\")[0].rstrip(".")
        # strip a :port suffix only when it doesn't look like an IPv6 literal
        if t.count(":") == 1:
            t = t.split(":")[0]
        if not t:
            continue
        try:
            ipaddress.ip_address(t)
            ips.append(t)
            continue
        except ValueError:
            pass
        if _HOSTNAME_RE.match(t):
            hostnames.append(t)
        else:
            invalid.append(tok)
    return {
        "hostnames": list(dict.fromkeys(hostnames)),
        "ips": list(dict.fromkeys(ips)),
        "invalid": list(dict.fromkeys(invalid)),
    }


# ── DNS orchestration (free) ────────────────────────────────────────────────


def bulk_dns(raw: str) -> dict[str, Any]:
    """Classify a blob then resolve hostnames + reverse IPs. All free."""
    cls = classify_dns_inputs(raw)
    resolve = shodan_api.dns_resolve(cls["hostnames"]) if cls["hostnames"] else {}
    reverse = shodan_api.dns_reverse(cls["ips"]) if cls["ips"] else {}
    return {**cls, "resolve": resolve, "reverse": reverse}


# ── result-table enrichment ──────────────────────────────────────────────────


def honeypot_from_tags(tags) -> bool:
    """True if any tag marks this as a honeypot/decoy.

    Shodan retired the standalone honeyscore lab and now bakes honeypot
    detection into the `honeypot` tag on normal results, so tags are the
    current free signal."""
    return any("honeypot" in str(t).lower() for t in (tags or []))


def annotate_matches(
    matches: list[dict] | None,
    idb: dict[str, dict] | None,
    honey: dict[str, float | None] | None,
    threshold: float,
) -> list[dict]:
    """Merge InternetDB enrichment + honeypot flag into each search match in place.

    is_honeypot is driven by the `honeypot` tag (from InternetDB or the match's
    own tags); a legacy honeyscore >= threshold still counts if one is present."""
    for m in matches or []:
        ip = m.get("ip_str") or ""
        enrich = (idb or {}).get(ip, {})
        m["idb_tags"] = enrich.get("tags", [])
        m["idb_vulns"] = enrich.get("vulns", [])
        m["idb_ports"] = enrich.get("ports", [])
        score = (honey or {}).get(ip)
        m["honeyscore"] = score
        all_tags = list(m["idb_tags"]) + list(m.get("tags") or [])
        m["is_honeypot"] = honeypot_from_tags(all_tags) or (score is not None and score >= threshold)
    return matches or []


def honeypot_flag(score: float | None, threshold: float) -> bool:
    """Legacy numeric-score check (Shodan retired honeyscore; usually None now)."""
    return score is not None and score >= threshold


# ── presentation: severity, flags, semantic tags, host grouping ──────────────
#
# Pure helpers that turn raw Shodan banners into the richer, colour-coded shapes
# the SOC-console UI renders. Kept here (not in templates) so they're unit-tested
# and the Jinja stays declarative.


def severity_from_cvss(cvss: Any) -> str:
    """Bucket a CVSS score into critical/high/medium/low, else 'unknown'.

    Mirrors the usual CVSS v3 bands. A missing/unparseable score (common for
    InternetDB CVE lists, which carry no score) becomes 'unknown' so the UI can
    still show the CVE without implying a severity it doesn't know."""
    try:
        score = float(cvss)
    except (TypeError, ValueError):
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "unknown"


def merge_vulns(*sources: Any) -> list[dict]:
    """Fold any number of vuln sources into one ordered ``[{id, cvss, severity,
    verified}]`` list, highest CVSS first.

    A source may be Shodan's ``{CVE: {cvss, verified, …}}`` dict (host/service
    banners on a paid plan) or a bare ``[CVE, …]`` list (InternetDB). The same
    CVE seen in several services keeps the highest score and a sticky 'verified'.
    """
    merged: dict[str, dict] = {}

    def _touch(cve: str) -> dict:
        return merged.setdefault(cve, {"id": cve, "cvss": None, "verified": False})

    for src in sources:
        if isinstance(src, dict):
            for cve, meta in src.items():
                if not isinstance(cve, str):
                    continue
                row = _touch(cve)
                if isinstance(meta, dict):
                    try:
                        score = float(meta.get("cvss"))
                    except (TypeError, ValueError):
                        score = None
                    if score is not None:
                        row["cvss"] = max(row["cvss"], score) if row["cvss"] is not None else score
                    row["verified"] = row["verified"] or bool(meta.get("verified"))
        elif isinstance(src, list):
            for cve in src:
                if isinstance(cve, str):
                    _touch(cve)

    vulns = list(merged.values())
    for v in vulns:
        v["severity"] = severity_from_cvss(v["cvss"])
    # Highest CVSS first; scoreless CVEs sink to the bottom but stay visible.
    vulns.sort(key=lambda v: (v["cvss"] if v["cvss"] is not None else -1.0), reverse=True)
    return vulns


def country_flag(code: Any) -> str:
    """ISO 3166-1 alpha-2 → the regional-indicator emoji flag (e.g. 'DE' → 🇩🇪).

    Returns '' for anything that isn't a 2-letter code, so the template can
    treat the result as optional."""
    if not isinstance(code, str):
        return ""
    code = code.strip().upper()
    if len(code) != 2 or not code.isalpha():
        return ""
    return "".join(chr(0x1F1E6 + ord(ch) - ord("A")) for ch in code)


# Known Shodan tags → (emoji, css-kind). 'kind' selects a colour class in the
# stylesheet so a honeypot, a database, and an ICS device read at a glance.
# Unknown tags fall through to the neutral 'generic' chip.
_TAG_META: dict[str, tuple[str, str]] = {
    "honeypot": ("🍯", "honeypot"),
    "cloud": ("☁️", "cloud"),
    "cdn": ("🌐", "network"),
    "proxy": ("🛰️", "network"),
    "vpn": ("🔒", "security"),
    "tor": ("🧅", "security"),
    "ics": ("⚙️", "ics"),
    "scada": ("⚙️", "ics"),
    "database": ("🗄️", "database"),
    "iot": ("📟", "generic"),
    "router": ("📡", "network"),
    "self-signed": ("📜", "warn"),
    "expired": ("⌛", "warn"),
    "eol-product": ("🚫", "warn"),
    "eol-os": ("🚫", "warn"),
    "compromised": ("☠️", "bad"),
    "malware": ("☠️", "bad"),
    "c2": ("☠️", "bad"),
    "doublepulsar": ("☠️", "bad"),
    "videogame": ("🎮", "generic"),
    "ssl": ("🔑", "generic"),
    "starttls": ("✉️", "generic"),
}


def tag_meta(tag: Any) -> dict:
    """Return ``{label, icon, kind}`` for a Shodan tag for colour-coded chips."""
    icon, kind = _TAG_META.get(str(tag).strip().lower(), ("", "generic"))
    return {"label": str(tag), "icon": icon, "kind": kind}


def match_screenshot(banner: Any) -> dict | None:
    """Extract a renderable screenshot ``{data, mime}`` from a search match or
    a host service banner, else None.

    Shodan stashes the base64 image under ``opts.screenshot`` (most common) or a
    top-level ``screenshot`` key. Only present when the crawler captured one
    (RDP/VNC/RTSP/X11/webcam services)."""
    if not isinstance(banner, dict):
        return None
    opts = banner.get("opts") if isinstance(banner.get("opts"), dict) else {}
    shot = opts.get("screenshot") or banner.get("screenshot")
    if isinstance(shot, dict) and shot.get("data"):
        return {"data": shot["data"], "mime": shot.get("mime") or "image/jpeg"}
    return None


def group_by_host(matches: list[dict] | None) -> list[dict]:
    """Collapse per-service Shodan matches into one card per host.

    Shodan returns a separate match for every open port, so a host exposing six
    services becomes six near-identical rows. We fold them by ``ip_str`` —
    unioning ports, hostnames, products, tags and vulns, taking the most recent
    ``last_seen`` and the first available screenshot — into the host dicts the
    card grid renders. Order of first appearance is preserved (Shodan's relevance
    order). Expects ``annotate_matches`` to have already run (uses idb_* fields).
    """
    hosts: dict[str, dict] = {}
    order: list[str] = []

    for m in matches or []:
        ip = m.get("ip_str")
        if not ip:
            continue
        h = hosts.get(ip)
        if h is None:
            h = {
                "ip_str": ip, "org": None, "isp": None, "asn": None, "os": None,
                "country_code": None, "country_name": None, "city": None,
                "hostnames": [], "ports": [], "products": [], "tags": [],
                "is_honeypot": False, "screenshot": None, "last_seen": None,
                "_vuln_sources": [],
            }
            hosts[ip] = h
            order.append(ip)

        loc = m.get("location") if isinstance(m.get("location"), dict) else {}
        for field, value in (
            ("org", m.get("org")), ("isp", m.get("isp")),
            ("asn", m.get("asn")), ("os", m.get("os")),
            ("country_code", loc.get("country_code") or m.get("country_code")),
            ("country_name", loc.get("country_name") or m.get("country_name")),
            ("city", loc.get("city") or m.get("city")),
        ):
            if not h[field] and value:
                h[field] = value

        port = m.get("port")
        if isinstance(port, int) and port not in h["ports"]:
            h["ports"].append(port)
        for hn in (m.get("hostnames") or []):
            if hn not in h["hostnames"]:
                h["hostnames"].append(hn)
        product = m.get("product")
        if product:
            label = f"{product} {m.get('version')}".strip() if m.get("version") else product
            if label not in h["products"]:
                h["products"].append(label)
        for t in list(m.get("idb_tags") or []) + list(m.get("tags") or []):
            if t not in h["tags"]:
                h["tags"].append(t)
        h["is_honeypot"] = h["is_honeypot"] or bool(m.get("is_honeypot"))

        ts = m.get("timestamp")
        if ts and (h["last_seen"] is None or str(ts) > str(h["last_seen"])):
            h["last_seen"] = ts
        if h["screenshot"] is None:
            shot = match_screenshot(m)
            if shot:
                h["screenshot"] = shot
        if m.get("vulns"):
            h["_vuln_sources"].append(m["vulns"])
        if m.get("idb_vulns"):
            h["_vuln_sources"].append(m["idb_vulns"])

    out: list[dict] = []
    for ip in order:
        h = hosts[ip]
        h["ports"].sort()
        h["vulns"] = merge_vulns(*h.pop("_vuln_sources"))
        h["flag"] = country_flag(h["country_code"])
        out.append(h)
    return out


def result_summary(hosts: list[dict]) -> dict:
    """At-a-glance stats for the strip above the results: distinct hosts and
    countries, how many are honeypots / carry vulns, and the single most common
    CVE across the page."""
    countries: set[str] = set()
    honeypots = 0
    vuln_hosts = 0
    cve_counts: dict[str, int] = {}
    for h in hosts:
        if h.get("country_code"):
            countries.add(h["country_code"])
        if h.get("is_honeypot"):
            honeypots += 1
        vulns = h.get("vulns") or []
        if vulns:
            vuln_hosts += 1
        for v in vulns:
            cve_counts[v["id"]] = cve_counts.get(v["id"], 0) + 1
    top_cve = None
    if cve_counts:
        cve, n = max(cve_counts.items(), key=lambda kv: kv[1])
        top_cve = {"id": cve, "hosts": n}
    return {
        "host_count": len(hosts),
        "country_count": len(countries),
        "honeypot_count": honeypots,
        "vuln_host_count": vuln_hosts,
        "top_cve": top_cve,
    }


# ── facet chart shaping ──────────────────────────────────────────────────────


def facet_chartdata(facets: dict[str, list[dict]] | None) -> list[dict]:
    """Turn Shodan's {facet: [{value,count}]} into ordered bar-chart rows.

    Each returned group: {name, label, items:[{value, count, pct}]} where pct is
    the count scaled 0–100 against the largest bar in that facet (for bar width).
    """
    out: list[dict] = []
    for name, items in (facets or {}).items():
        items = items or []
        mx = max((it.get("count", 0) for it in items), default=0) or 1
        rows = [
            {
                "value": it.get("value"),
                "count": it.get("count", 0),
                "pct": round(100 * it.get("count", 0) / mx),
            }
            for it in items
        ]
        out.append({"name": name, "label": FACET_LABELS.get(name, name.title()), "items": rows})
    order = {n: i for i, n in enumerate(DEFAULT_FACETS)}
    out.sort(key=lambda d: order.get(d["name"], 99))
    return out
