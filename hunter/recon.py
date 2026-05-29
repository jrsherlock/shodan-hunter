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
