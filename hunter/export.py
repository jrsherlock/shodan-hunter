"""Export result sets to clean CSV / JSON for engagement deliverables.

Pure data-shaping, no HTTP/templating concerns (the app layer wraps these in a
download Response), so everything here unit-tests trivially — same philosophy as
:mod:`recon`. Each ``*_rows`` function flattens one result type into an ordered
column list plus a list of flat row dicts; :func:`csv_bytes` / :func:`json_bytes`
render them.

CSV is for dropping straight into a report appendix or spreadsheet (UTF-8 BOM so
Excel detects the encoding); JSON is ``{meta, columns, rows}`` for jq / tooling.
"""

from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime, timezone
from typing import Any

__all__ = [
    "domain_rows", "search_rows", "dns_rows", "host_rows",
    "csv_bytes", "json_bytes", "filename",
]


def _slug(text: str) -> str:
    """A filename-safe component: lowercase, non-[a-z0-9._-] collapsed to '-'."""
    text = re.sub(r"[^a-z0-9._-]+", "-", (text or "").strip().lower()).strip("-.")
    return text or "export"


def filename(stem: str, kind: str, ext: str) -> str:
    """``<slug>-<kind>-<UTC timestamp>.<ext>`` — e.g. ``acme.com-domain-20260622-180000Z.csv``."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%SZ")
    return f"{_slug(stem)}-{kind}-{ts}.{ext}"


def _join(values: Any, sep: str = "; ") -> str:
    """Flatten a list-ish cell into one string, dropping blanks."""
    if values is None:
        return ""
    if isinstance(values, (str, bytes)):
        return values.decode() if isinstance(values, bytes) else values
    return sep.join(str(v) for v in values if v not in (None, ""))


def csv_bytes(columns: list[str], rows: list[dict]) -> bytes:
    """Render rows as CSV. utf-8-sig BOM so Excel opens UTF-8 cleanly."""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=columns, extrasaction="ignore",
                            lineterminator="\r\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({c: row.get(c, "") for c in columns})
    return buf.getvalue().encode("utf-8-sig")


def json_bytes(meta: dict, columns: list[str], rows: list[dict]) -> bytes:
    """Render a ``{meta, columns, rows}`` document. ``meta`` is stamped with the
    export time and row count."""
    payload = {
        "meta": {
            **meta,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "count": len(rows),
        },
        "columns": columns,
        "rows": rows,
    }
    return json.dumps(payload, indent=2, default=str).encode("utf-8")


# ── row shapers (one per result type) ────────────────────────────────────────


def domain_rows(data: dict | None) -> tuple[list[str], list[dict]]:
    """Domain-recon passive-DNS records → rows. Mirrors the on-screen table."""
    domain = (data or {}).get("domain", "") or ""
    columns = ["fqdn", "subdomain", "type", "value", "ports", "last_seen"]
    rows: list[dict] = []
    for rec in (data or {}).get("data") or []:
        sub = rec.get("subdomain") or ""
        rows.append({
            "fqdn": f"{sub}.{domain}" if sub else domain,
            "subdomain": sub,
            "type": rec.get("type", "") or "",
            "value": rec.get("value", "") or "",
            "ports": _join(rec.get("ports") or [], " "),
            "last_seen": rec.get("last_seen") or "",
        })
    return columns, rows


def search_rows(matches: list[dict] | None) -> tuple[list[str], list[dict]]:
    """Shodan search matches → rows. Includes the free InternetDB enrichment
    (tags/vulns/honeypot) when :func:`recon.annotate_matches` has run."""
    columns = [
        "ip", "port", "transport", "org", "isp", "asn", "country", "city",
        "hostnames", "domains", "product", "version", "os", "tags", "vulns",
        "honeypot", "timestamp",
    ]
    rows: list[dict] = []
    for m in matches or []:
        loc = m.get("location") or {}
        vuln_keys = list((m.get("vulns") or {}).keys())
        vulns = sorted(set(vuln_keys) | set(m.get("idb_vulns") or []))
        tags = m.get("idb_tags") or m.get("tags") or []
        rows.append({
            "ip": m.get("ip_str", "") or "",
            "port": m.get("port", "") if m.get("port") is not None else "",
            "transport": m.get("transport", "") or "",
            "org": m.get("org") or "",
            "isp": m.get("isp") or "",
            "asn": m.get("asn") or "",
            "country": loc.get("country_code") or "",
            "city": loc.get("city") or "",
            "hostnames": _join(m.get("hostnames") or []),
            "domains": _join(m.get("domains") or []),
            "product": m.get("product") or "",
            "version": m.get("version") or "",
            "os": m.get("os") or "",
            "tags": _join(tags),
            "vulns": _join(vulns),
            "honeypot": "yes" if m.get("is_honeypot") else "",
            "timestamp": m.get("timestamp") or "",
        })
    return columns, rows


def dns_rows(result: dict | None) -> tuple[list[str], list[dict]]:
    """Bulk-DNS forward + reverse results → rows."""
    columns = ["input", "direction", "result"]
    rows: list[dict] = []
    for host, ip in ((result or {}).get("resolve") or {}).items():
        rows.append({"input": host, "direction": "forward", "result": ip or ""})
    for ip, names in ((result or {}).get("reverse") or {}).items():
        res = _join(names) if isinstance(names, (list, tuple)) else (names or "")
        rows.append({"input": ip, "direction": "reverse", "result": res})
    return columns, rows


def _ssl_cn(ssl: dict | None) -> str:
    """Pull the cert subject CN out of a service's ssl block (subject is a dict)."""
    subject = ((ssl or {}).get("cert") or {}).get("subject")
    if isinstance(subject, dict):
        return subject.get("CN", "") or ""
    return str(subject) if subject else ""


def host_rows(data: dict | None, idb: dict | None = None) -> tuple[list[str], list[dict]]:
    """A Shodan host record → one row per exposed service, with host context
    (org/country/tags) repeated on each row so the CSV stands alone. Host- and
    InternetDB-level CVEs are merged into each row's ``vulns``. Falls back to a
    single summary row when the host has no per-service banners."""
    data = data or {}
    idb = idb or {}
    columns = [
        "ip", "port", "transport", "product", "version", "module", "cpe",
        "org", "country", "hostnames", "ssl_cn", "http_title", "http_server",
        "vulns", "tags", "timestamp",
    ]
    ip = data.get("ip_str", "") or ""
    org = data.get("org") or ""
    country = (data.get("country_code")
               or (data.get("location") or {}).get("country_code") or "")
    host_hostnames = _join(data.get("hostnames") or [])
    host_vulns = list(data.get("vulns") or [])  # dict-or-list of CVE ids
    idb_vulns = list(idb.get("vulns") or [])
    tags = _join(list(data.get("tags") or []) + list(idb.get("tags") or []))

    rows: list[dict] = []
    for s in data.get("data") or []:
        svc = s.get("vulns")
        svc_vulns = list(svc.keys()) if isinstance(svc, dict) else list(svc or [])
        vulns = sorted(set(svc_vulns) | set(host_vulns) | set(idb_vulns))
        rows.append({
            "ip": ip,
            "port": s.get("port", "") if s.get("port") is not None else "",
            "transport": s.get("transport", "") or "",
            "product": s.get("product") or "",
            "version": s.get("version") or "",
            "module": (s.get("_shodan") or {}).get("module") or "",
            "cpe": _join(s.get("cpe23") or s.get("cpe") or [], " "),
            "org": org,
            "country": country,
            "hostnames": _join(s.get("hostnames") or []) or host_hostnames,
            "ssl_cn": _ssl_cn(s.get("ssl")),
            "http_title": (s.get("http") or {}).get("title") or "",
            "http_server": (s.get("http") or {}).get("server") or "",
            "vulns": _join(vulns),
            "tags": tags,
            "timestamp": s.get("timestamp") or "",
        })

    if not rows and ip:
        # Host is known but carries no per-service banners (InternetDB-only or
        # no_data) — still emit one row so the export isn't empty.
        rows.append({
            "ip": ip, "port": "", "transport": "", "product": "", "version": "",
            "module": "", "cpe": _join(idb.get("cpes") or [], " "),
            "org": org, "country": country, "hostnames": host_hostnames,
            "ssl_cn": "", "http_title": "", "http_server": "",
            "vulns": _join(sorted(set(host_vulns) | set(idb_vulns))),
            "tags": tags, "timestamp": data.get("last_update") or "",
        })
    return columns, rows
