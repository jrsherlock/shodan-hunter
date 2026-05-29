"""Derive "next step" actions from a Shodan host record.

Two kinds, both consumed by ``templates/host.html``:

* :func:`host_pivots` — the "yeah, but what about other hosts like this?" move:
  one-click Shodan queries built from the host's own attributes (org, ASN,
  /24, product+version, TLS cert CN, favicon hash, CVE…). Each is rendered as a
  submit button that POSTs to ``/ask`` as an ``override_query`` (no LLM, no
  CSRF exposure — same-origin form).

* :func:`service_url` — the "let me click to see if it's responding" move for
  web services: a plain ``http(s)://ip:port`` the operator's *own* browser
  opens, so the tool itself never makes the outbound request.

Everything here is pure (dict in, data out) and defensive about missing/oddly
typed fields — Shodan records are sparse and inconsistent.
"""

from __future__ import annotations

import ipaddress
from typing import Any

# Keep the UI tidy: at most this many pivots, and bound the per-category fan-out
# (a host can expose dozens of services — we don't want 30 product pivots).
_MAX_PIVOTS = 14
_MAX_PER_KIND = 4


def _clean(value: Any) -> str:
    """Stringify and strip embedded double-quotes so the value can't break out
    of a quoted Shodan filter (``org:"a"b"`` is a malformed query). None/missing
    becomes the empty string so callers can treat it as "no value"."""
    if value is None:
        return ""
    return str(value).replace('"', "").strip()


def _quoted(field: str, value: Any) -> str | None:
    v = _clean(value)
    return f'{field}:"{v}"' if v else None


def _slash24(ip: str) -> str | None:
    """The host's containing /24 (IPv4) or /64 (IPv6) as a ``net:`` filter."""
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return None
    prefix = 24 if addr.version == 4 else 64
    net = ipaddress.ip_network(f"{addr}/{prefix}", strict=False)
    return f"net:{net}"


def _services(host: dict) -> list[dict]:
    data = host.get("data")
    return [s for s in data if isinstance(s, dict)] if isinstance(data, list) else []


def host_pivots(host: dict[str, Any] | None, idb: dict[str, Any] | None = None) -> list[dict]:
    """Return ordered, de-duplicated pivot suggestions: ``{label, query, why}``."""
    host = host or {}
    idb = idb or {}
    ip = host.get("ip_str") or ""
    out: list[dict] = []
    seen: set[str] = set()

    def add(label: str, query: str | None, why: str) -> None:
        if not query or query in seen:
            return
        seen.add(query)
        out.append({"label": label, "query": query, "why": why})

    # Ownership / network neighbourhood.
    if host.get("org"):
        add(f"Org: {host['org']}", _quoted("org", host["org"]),
            "Everything else this organisation exposes.")
    asn = _clean(host.get("asn"))
    if asn:
        asn = asn if asn.upper().startswith("AS") else f"AS{asn}"
        add(f"ASN: {asn}", f"asn:{asn}", "Other hosts announced by this ASN.")
    add(f"Same /24 as {ip}", _slash24(ip), "Neighbouring hosts in the same subnet.")

    for h in (host.get("hostnames") or [])[:1]:
        add(f"Hostname: {h}", _quoted("hostname", h),
            "Hosts whose banner mentions this hostname.")

    # Service fingerprints — products, certs, favicons. Also gather CVEs from
    # every service banner as we go (they aren't always lifted to host.vulns).
    prods = 0
    cns = 0
    favs = 0
    svc_vulns: list[str] = []
    for svc in _services(host):
        sv = svc.get("vulns")
        if isinstance(sv, dict):
            svc_vulns += list(sv.keys())
        elif isinstance(sv, list):
            svc_vulns += sv
        product = _clean(svc.get("product"))
        version = _clean(svc.get("version"))
        if product and prods < _MAX_PER_KIND:
            if version:
                add(f"{product} {version}",
                    f'{_quoted("product", product)} {_quoted("version", version)}',
                    "Same product AND version anywhere (the patch-level cohort).")
            else:
                add(f"Product: {product}", _quoted("product", product),
                    "Every host running this product.")
            prods += 1

        ssl = svc.get("ssl") if isinstance(svc.get("ssl"), dict) else {}
        cert = ssl.get("cert") if isinstance(ssl.get("cert"), dict) else {}
        subject = cert.get("subject") if isinstance(cert.get("subject"), dict) else {}
        cn = subject.get("CN")
        if cn and cns < _MAX_PER_KIND:
            add(f"Cert CN: {cn}", _quoted("ssl.cert.subject.cn", cn),
                "Hosts presenting a cert with this common name.")
            cns += 1

        http = svc.get("http") if isinstance(svc.get("http"), dict) else {}
        favicon = http.get("favicon") if isinstance(http.get("favicon"), dict) else {}
        fhash = favicon.get("hash")
        if fhash is not None and favs < _MAX_PER_KIND:
            add(f"Favicon hash {fhash}", f"http.favicon.hash:{fhash}",
                "The classic 'find the rest of the fleet' pivot — exact favicon match.")
            favs += 1

    # Shared vulnerabilities (vuln: needs a paid plan; the host page only shows
    # these when present, and the operator's plan is surfaced in the header).
    vulns = host.get("vulns") or idb.get("vulns") or []
    if isinstance(vulns, dict):
        vulns = list(vulns.keys())
    elif not isinstance(vulns, list):
        vulns = []
    # De-dupe host- and service-level CVEs, preserving order.
    all_cves = list(dict.fromkeys(v for v in (list(vulns) + svc_vulns) if isinstance(v, str)))
    for cve in all_cves[:_MAX_PER_KIND]:
        add(f"CVE: {cve}", f"vuln:{cve}", "Other hosts exposed to the same CVE.")

    return out[:_MAX_PIVOTS]


def service_url(ip: str, svc: dict[str, Any]) -> str | None:
    """A browsable ``http(s)://ip:port`` for a web service, else None.

    TLS → https; a plain HTTP module → http; otherwise this isn't a web service
    and there's nothing for a browser to open."""
    if not isinstance(svc, dict):
        return None
    port = svc.get("port")
    if not isinstance(port, int):
        return None
    if svc.get("ssl"):
        scheme = "https"
    elif svc.get("http"):
        scheme = "http"
    else:
        return None
    return f"{scheme}://{ip}:{port}"
