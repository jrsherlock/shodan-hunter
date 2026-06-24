"""FastAPI app: chat-style NL → Shodan UI."""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import ipaddress

from . import (config, db, export, internetdb, llm, monitor, pivots, probe,
               recon, scans, shodan_api)
from .auth import current_user, require_same_origin

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

HERE = Path(__file__).parent
templates = Jinja2Templates(directory=str(HERE / "templates"))


def _epoch_local(ts) -> str:
    """Format an int epoch as 'YYYY-MM-DD HH:MM' in local time."""
    from datetime import datetime
    try:
        return datetime.fromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M")
    except (TypeError, ValueError):
        return str(ts)


templates.env.filters["epoch_local"] = _epoch_local
templates.env.globals["service_url"] = pivots.service_url


def _valid_ip(ip: str) -> str:
    """Validate an IP path param. Returns the trimmed IP, or 422s.

    Guards the routes that fan a path param straight out to InternetDB/Shodan
    (``/idb/{ip}``, ``/host/{ip}``, ``/api/honeyscore/{ip}``) so an authed user
    can't drive arbitrary strings at the upstream endpoints."""
    ip = (ip or "").strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(422, f"Not a valid IP address: {ip!r}")
    return ip

app = FastAPI(title="shodan-hunter", version="0.3.0")
app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")


# Engagement-oriented starting points. Each is scoped to a customer the way a
# red team works in practice — by org, netblock (net:), or cert/hostname for the
# client's domain — so the query stays inside the rules of engagement. Swap
# "Client Corp" / clientcorp.com / the documentation netblock for the real scope.
EXAMPLES = [
    "Map the external attack surface for org \"Client Corp\"",
    "Internet-facing RDP and SSH on net 203.0.113.0/24",
    "Fortinet and Ivanti SSL-VPN gateways exposed by org \"Client Corp\"",
    "Citrix NetScaler hosts affected by Citrix Bleed CVE-2023-4966",
    "Forgotten assets: hosts presenting TLS certificates for clientcorp.com",
    "Exposed login portals on subdomains of clientcorp.com",
    "Unauthenticated Elasticsearch, MongoDB, or Redis owned by org \"Client Corp\"",
    "Internet-exposed ICS: Veeder-Root tank gauges on port 10001",
]


def _ctx(request: Request, user: str, **extra) -> dict:
    try:
        shodan_info = shodan_api.api_info()
    except Exception:
        shodan_info = None
    return {
        "request": request,
        "user": user,
        "status": config.status(),
        "shodan_info": shodan_info,
        "examples": EXAMPLES,
        **extra,
    }


# ── error pages ──────────────────────────────────────────────────────────


@app.exception_handler(shodan_api.ShodanNotConfigured)
async def _h_no_shodan(request: Request, exc: shodan_api.ShodanNotConfigured):
    return _err(request, "Shodan not configured", str(exc), 503)


@app.exception_handler(shodan_api.ShodanError)
async def _h_shodan(request: Request, exc: shodan_api.ShodanError):
    return _err(request, "Shodan lookup failed", str(exc), 502)


@app.exception_handler(llm.LLMNotConfigured)
async def _h_no_llm(request: Request, exc: llm.LLMNotConfigured):
    return _err(request, "Azure OpenAI not configured", str(exc), 503)


@app.exception_handler(llm.LLMError)
async def _h_llm(request: Request, exc: llm.LLMError):
    return _err(request, "LLM error", str(exc), 502)


def _err(request: Request, title: str, detail: str, code: int):
    if request.url.path.startswith("/api/"):
        return JSONResponse({"error": title, "detail": detail}, status_code=code)
    # No auth on error pages so they always render
    return templates.TemplateResponse(
        request, "error.html",
        {"request": request, "user": None, "status": config.status(),
         "examples": EXAMPLES, "title": title, "detail": detail},
        status_code=code,
    )


# ── pages ────────────────────────────────────────────────────────────────


@app.get("/", response_class=HTMLResponse)
async def home(request: Request, user: str = Depends(current_user)):
    return templates.TemplateResponse(
        request, "chat.html",
        _ctx(request, user, prompt="", llm_result=None, search=None, override_query=None,
             recent=db.recent_audit(limit=5, username=user)),
    )


@app.post("/ask", response_class=HTMLResponse, dependencies=[Depends(require_same_origin)])
async def ask(
    request: Request,
    user: str = Depends(current_user),
    prompt: str = Form(...),
    page: int = Form(1),
    override_query: str = Form(""),
):
    """The main chat handler. Either translate prompt → query → search, or
    if the user supplied `override_query`, skip the LLM and search directly."""
    prompt = (prompt or "").strip()
    override = (override_query or "").strip()
    llm_result = None
    search_result = None
    error_msg = None

    if override:
        query_to_run = override
        llm_result = {
            "query": override,
            "rationale": "(user-supplied query — LLM bypassed)",
            "warnings": [],
            "prompt": prompt,
        }
    else:
        try:
            llm_result = llm.prompt_to_query(prompt)
            query_to_run = llm_result["query"]
        except (llm.LLMError, llm.LLMNotConfigured) as e:
            db.log_audit(username=user, prompt=prompt, query=None,
                         rationale=None, result_total=None, error=str(e))
            raise

    try:
        search_result = shodan_api.search(query_to_run, page=page)
        total = search_result.get("total", 0)
    except (shodan_api.ShodanError, shodan_api.ShodanNotConfigured) as e:
        db.log_audit(username=user, prompt=prompt, query=query_to_run,
                     rationale=(llm_result or {}).get("rationale"),
                     result_total=None, error=str(e))
        raise

    # Free enrichment (no query credits): InternetDB vulns/tags/ports, honeypot
    # scores, and facet aggregates. Each block is best-effort — a failure here
    # must never blank out the result table the user already paid for.
    matches = search_result.get("matches") or []
    if matches:
        ips = [m.get("ip_str") for m in matches if m.get("ip_str")]
        try:
            idb = internetdb.lookup_many(ips)
        except Exception:
            idb = {}
        # Honeypot flag comes from the free `honeypot` tag (InternetDB / banner),
        # not per-IP honeyscore — Shodan retired that lab endpoint.
        recon.annotate_matches(matches, idb, {}, config.HONEYPOT_THRESHOLD)

    try:
        facet_groups = recon.facet_chartdata(
            shodan_api.facet_summary(query_to_run, recon.DEFAULT_FACETS)
        )
    except Exception:
        facet_groups = []

    spent = 0 if search_result.get("_cache") == "hit" else 1
    db.log_audit(
        username=user, prompt=prompt, query=query_to_run,
        rationale=(llm_result or {}).get("rationale"),
        result_total=total, error=error_msg, action="search", credits=spent,
    )

    return templates.TemplateResponse(
        request, "chat.html",
        _ctx(request, user, prompt=prompt, llm_result=llm_result,
             search=search_result, page=page, facets=facet_groups,
             override_query=override,
             recent=db.recent_audit(limit=5, username=user)),
    )


@app.get("/host/{ip}", response_class=HTMLResponse)
async def host_page(request: Request, ip: str, user: str = Depends(current_user),
                    refresh: bool = False):
    ip = _valid_ip(ip)
    data = shodan_api.host(ip, use_cache=not refresh)
    # Free side-channel context: InternetDB costs no query credits.
    try:
        idb = internetdb.lookup(ip)
    except Exception:
        idb = None
    host_tags = list(data.get("tags") or []) + list((idb or {}).get("tags") or [])
    db.log_audit(
        username=user, prompt=f"host {ip}", query=None, rationale=None,
        result_total=len(data.get("ports") or []),
        error=data.get("message") if data.get("no_data") else None,
        action="host", credits=0 if data.get("_cache") == "hit" else 1,
    )
    return templates.TemplateResponse(
        request, "host.html",
        _ctx(request, user, ip=ip, host=data, idb=idb,
             is_honeypot=recon.honeypot_from_tags(host_tags),
             pivots=pivots.host_pivots(data, idb),
             probe_enabled=config.PROBE_ENABLED),
    )


@app.get("/log", response_class=HTMLResponse)
async def audit_log_page(request: Request, user: str = Depends(current_user),
                         mine: bool = False, limit: int = 100):
    rows = db.recent_audit(limit=limit, username=user if mine else None)
    return templates.TemplateResponse(
        request, "log.html",
        _ctx(request, user, rows=rows, mine=mine),
    )


# ── domain recon (1 credit) ─────────────────────────────────────────────────


def _domain_page(request: Request, user: str, domain: str):
    domain = (domain or "").strip()
    data = None
    if domain:
        data = shodan_api.domain_info(domain)
        subs = data.get("subdomains") or []
        db.log_audit(
            username=user, prompt=f"domain {domain}", query=domain, rationale=None,
            result_total=len(subs),
            error=data.get("message") if data.get("no_data") else None,
            action="domain", credits=0 if data.get("_cache") == "hit" else 1,
        )
    return templates.TemplateResponse(
        request, "domain.html",
        _ctx(request, user, domain=domain, domain_data=data),
    )


@app.get("/domain", response_class=HTMLResponse)
async def domain_form(request: Request, user: str = Depends(current_user),
                      q: str = Query("")):
    return _domain_page(request, user, q)


@app.get("/domain/{name}", response_class=HTMLResponse)
async def domain_named(request: Request, name: str, user: str = Depends(current_user)):
    return _domain_page(request, user, name)


# ── bulk DNS resolve / reverse (free) ────────────────────────────────────────


@app.get("/dns", response_class=HTMLResponse)
async def dns_form(request: Request, user: str = Depends(current_user)):
    return templates.TemplateResponse(
        request, "dns.html", _ctx(request, user, blob="", result=None),
    )


@app.post("/dns", response_class=HTMLResponse, dependencies=[Depends(require_same_origin)])
async def dns_run(request: Request, user: str = Depends(current_user),
                  blob: str = Form("")):
    result = recon.bulk_dns(blob)
    n = len(result.get("resolve") or {}) + len(result.get("reverse") or {})
    db.log_audit(
        username=user, prompt=f"dns lookup ({n} items)", query=None, rationale=None,
        result_total=n, error=None, action="dns", credits=0,
    )
    return templates.TemplateResponse(
        request, "dns.html", _ctx(request, user, blob=blob, result=result),
    )


# ── result export (CSV / JSON, free; re-fetches via cache) ───────────────────


def _download(stem: str, kind: str, fmt: str, columns: list[str],
              rows: list[dict], meta: dict) -> Response:
    """Build a downloadable CSV or JSON attachment from shaped rows."""
    fmt = (fmt or "csv").strip().lower()
    if fmt == "csv":
        body, media = export.csv_bytes(columns, rows), "text/csv; charset=utf-8"
    elif fmt == "json":
        body, media = export.json_bytes(meta, columns, rows), "application/json"
    else:
        raise HTTPException(422, "format must be 'csv' or 'json'")
    fname = export.filename(stem, kind, fmt)
    return Response(content=body, media_type=media,
                    headers={"Content-Disposition": f'attachment; filename="{fname}"'})


@app.get("/export/domain")
async def export_domain(user: str = Depends(current_user),
                        q: str = Query(...), format: str = Query("csv")):
    """Export domain-recon records. Served from the 6 h domain cache, so an
    export right after viewing the page spends no credit."""
    domain = (q or "").strip()
    if not domain:
        raise HTTPException(422, "missing domain (?q=)")
    data = shodan_api.domain_info(domain)
    columns, rows = export.domain_rows(data)
    db.log_audit(username=user, prompt=f"export domain {domain} ({format})",
                 query=domain, rationale=None, result_total=len(rows), error=None,
                 action="export", credits=0 if data.get("_cache") == "hit" else 1)
    return _download(domain, "domain", format, columns, rows,
                     {"type": "domain", "domain": domain})


@app.get("/export/search")
async def export_search(user: str = Depends(current_user),
                        q: str = Query(...), page: int = Query(1),
                        format: str = Query("csv")):
    """Export the current page of search results (Shodan returns 100/page). Served
    from the short-lived search cache, so exporting what you're viewing is free."""
    query = (q or "").strip()
    if not query:
        raise HTTPException(422, "missing query (?q=)")
    result = shodan_api.search(query, page=page)
    matches = result.get("matches") or []
    # Re-apply the free InternetDB enrichment so exported tags/vulns/honeypot
    # match the on-screen table. Best-effort — never block the download.
    try:
        ips = [m.get("ip_str") for m in matches if m.get("ip_str")]
        recon.annotate_matches(matches, internetdb.lookup_many(ips), {},
                               config.HONEYPOT_THRESHOLD)
    except Exception:
        pass
    columns, rows = export.search_rows(matches)
    db.log_audit(username=user, prompt=f"export search ({format})", query=query,
                 rationale=None, result_total=len(rows), error=None,
                 action="export", credits=0 if result.get("_cache") == "hit" else 1)
    return _download(query, "search", format, columns, rows,
                     {"type": "search", "query": query, "page": page,
                      "total": result.get("total")})


@app.get("/export/host/{ip}")
async def export_host(ip: str, user: str = Depends(current_user),
                      format: str = Query("csv")):
    """Export a host's exposed services (one row per service). Served from the
    1 h host cache, so an export right after viewing the host page is free."""
    ip = _valid_ip(ip)
    data = shodan_api.host(ip, use_cache=True)
    try:
        idb = internetdb.lookup(ip)
    except Exception:
        idb = None
    columns, rows = export.host_rows(data, idb)
    db.log_audit(username=user, prompt=f"export host {ip} ({format})", query=None,
                 rationale=None, result_total=len(rows), error=None,
                 action="export", credits=0 if data.get("_cache") == "hit" else 1)
    return _download(ip, "host", format, columns, rows, {"type": "host", "ip": ip})


@app.get("/export/dns")
async def export_dns(user: str = Depends(current_user),
                     blob: str = Query(""), format: str = Query("csv")):
    """Export bulk-DNS forward/reverse results. Always free."""
    result = recon.bulk_dns(blob)
    columns, rows = export.dns_rows(result)
    db.log_audit(username=user, prompt=f"export dns ({format})", query=None,
                 rationale=None, result_total=len(rows), error=None,
                 action="export", credits=0)
    return _download("dns", "dns", format, columns, rows, {"type": "dns"})


# ── on-demand scan (scan credits; authorization-gated) ───────────────────────


def _scan_ctx(request: Request, user: str, **extra):
    return _ctx(request, user, enabled=config.SCAN_ENABLED,
                allowlist=config.SCAN_ALLOWLIST, recent=db.recent_scans(limit=25),
                **extra)


@app.get("/scan", response_class=HTMLResponse)
async def scan_form(request: Request, user: str = Depends(current_user)):
    return templates.TemplateResponse(
        request, "scan.html",
        _scan_ctx(request, user, submitted=None, error=None, status_detail=None),
    )


@app.post("/scan", response_class=HTMLResponse, dependencies=[Depends(require_same_origin)])
async def scan_submit(request: Request, user: str = Depends(current_user),
                      targets: str = Form(""), confirm: str = Form("")):
    if not config.SCAN_ENABLED:
        raise HTTPException(403, "On-demand scanning is disabled (set SH_ENABLE_SCAN=1).")
    submitted = error = None
    try:
        submitted = scans.submit(targets, user=user,
                                 user_confirmed=config.truthy(confirm))
        db.log_audit(username=user, prompt=f"scan {targets}", query=None,
                     rationale=submitted.get("authorization"),
                     result_total=recon.count_hosts(submitted["targets"]),
                     error=None, action="scan", credits=0)
    except (scans.ScanInputError, scans.ScanNotAuthorized, shodan_api.ShodanError) as e:
        error = str(e)
        db.log_audit(username=user, prompt=f"scan {targets}", query=None,
                     rationale=None, result_total=None, error=error,
                     action="scan", credits=0)
    return templates.TemplateResponse(
        request, "scan.html",
        _scan_ctx(request, user, submitted=submitted, error=error, status_detail=None),
    )


@app.get("/scan/{scan_id}", response_class=HTMLResponse)
async def scan_status_page(request: Request, scan_id: str,
                           user: str = Depends(current_user)):
    detail = error = None
    try:
        detail = scans.refresh(scan_id)
    except shodan_api.ShodanError as e:
        error = str(e)
    return templates.TemplateResponse(
        request, "scan.html",
        _scan_ctx(request, user, submitted=None, error=error, status_detail=detail),
    )


# ── network alerts (management; no query credits) ────────────────────────────


def _alerts_ctx(request: Request, user: str, **extra):
    alerts: list = []
    triggers: list = []
    err = None
    if config.ALERTS_ENABLED:
        try:
            alerts = monitor.list_with_meta()
            triggers = monitor.triggers_catalog()
        except shodan_api.ShodanError as e:
            err = str(e)
    return _ctx(request, user, enabled=config.ALERTS_ENABLED,
                alerts=alerts, triggers=triggers, alerts_error=err, **extra)


@app.get("/alerts", response_class=HTMLResponse)
async def alerts_page(request: Request, user: str = Depends(current_user)):
    return templates.TemplateResponse(request, "alerts.html",
                                      _alerts_ctx(request, user))


@app.post("/alerts", dependencies=[Depends(require_same_origin)])
async def alerts_create(request: Request, user: str = Depends(current_user),
                        name: str = Form(...), ips: str = Form(...),
                        triggers: list[str] = Form([])):
    if not config.ALERTS_ENABLED:
        raise HTTPException(403, "Alerts are disabled (set SH_ENABLE_ALERTS=1).")
    try:
        res = monitor.create(name, ips, user=user, triggers=triggers)
        db.log_audit(username=user, prompt=f"create alert {name!r} on {ips}",
                     query=None, rationale=None,
                     result_total=len(res.get("targets") or []), error=None,
                     action="alert", credits=0)
    except (ValueError, shodan_api.ShodanError) as e:
        db.log_audit(username=user, prompt=f"create alert {name!r}", query=None,
                     rationale=None, result_total=None, error=str(e),
                     action="alert", credits=0)
    return RedirectResponse("/alerts", status_code=303)


@app.post("/alerts/{aid}/delete", dependencies=[Depends(require_same_origin)])
async def alerts_delete(aid: str, user: str = Depends(current_user)):
    if not config.ALERTS_ENABLED:
        raise HTTPException(403, "Alerts are disabled.")
    try:
        monitor.delete(aid)
        db.log_audit(username=user, prompt=f"delete alert {aid}", query=None,
                     rationale=None, result_total=None, error=None,
                     action="alert", credits=0)
    except shodan_api.ShodanError as e:
        db.log_audit(username=user, prompt=f"delete alert {aid}", query=None,
                     rationale=None, result_total=None, error=str(e),
                     action="alert", credits=0)
    return RedirectResponse("/alerts", status_code=303)


@app.post("/alerts/{aid}/trigger", dependencies=[Depends(require_same_origin)])
async def alerts_trigger(aid: str, user: str = Depends(current_user),
                         trigger: str = Form(...), enabled: str = Form("")):
    if not config.ALERTS_ENABLED:
        raise HTTPException(403, "Alerts are disabled.")
    try:
        monitor.set_trigger(aid, trigger, config.truthy(enabled))
    except shodan_api.ShodanError:
        pass
    return RedirectResponse("/alerts", status_code=303)


# ── community query library (free) ───────────────────────────────────────────


@app.get("/library", response_class=HTMLResponse)
async def library_page(request: Request, user: str = Depends(current_user),
                       q: str = Query(""), page: int = Query(1),
                       sort: str = Query("votes")):
    q = (q or "").strip()
    # "votes" → Top Voted, "timestamp" → Recently Added (directory listing only)
    sort = sort if sort in ("votes", "timestamp") else "votes"
    library_error = None
    items: list = []
    tags: list = []
    # Popular tags are the Explore "categories"; decorative, so never fatal.
    try:
        tags = (shodan_api.community_tags().get("matches")) or []
    except shodan_api.ShodanError:
        tags = []
    try:
        data = shodan_api.query_search(q, page=page) if q else shodan_api.community_queries(page=page, sort=sort)
        items = (data.get("matches") if isinstance(data, dict) else data) or []
    except shodan_api.ShodanError as e:
        library_error = str(e)
    return templates.TemplateResponse(
        request, "library.html",
        _ctx(request, user, q=q, page=page, sort=sort, items=items, tags=tags,
             library_error=library_error),
    )


# ── small JSON helpers ────────────────────────────────────────────────────


@app.get("/api/count")
async def api_count(q: str = Query(..., min_length=1),
                    user: str = Depends(current_user)):
    return shodan_api.count(q)


@app.get("/api/info")
async def api_info(user: str = Depends(current_user)):
    return {
        **shodan_api.api_info(),
        "config": config.status(),
    }


@app.get("/idb/{ip}")
async def idb_json(ip: str, user: str = Depends(current_user)):
    """Free InternetDB lookup — what Shodan already knows about an IP, 0 credits."""
    ip = _valid_ip(ip)
    return {"ip": ip, **internetdb.lookup(ip)}


@app.get("/api/honeyscore/{ip}")
async def honeyscore_json(ip: str, user: str = Depends(current_user)):
    """Free honeypot probability (0.0–1.0) for an IP, 0 credits."""
    ip = _valid_ip(ip)
    return {"ip": ip, "honeyscore": shodan_api.honeyscore(ip)}


@app.post("/probe", dependencies=[Depends(require_same_origin)])
async def probe_run(request: Request, user: str = Depends(current_user),
                    ip: str = Form(...), port: int = Form(...)):
    """Liveness TCP-connect to ip:port. Gated by SH_ENABLE_PROBE, audit-logged.
    Returns {status, ms, detail} as JSON for the host page's inline probe UI."""
    if not config.PROBE_ENABLED:
        raise HTTPException(403, "Probing is disabled (set SH_ENABLE_PROBE=1).")
    ip = _valid_ip(ip)
    try:
        result = probe.probe(ip, port)
    except probe.ProbeNotAllowed as e:
        raise HTTPException(403, str(e))
    except ValueError as e:
        raise HTTPException(422, str(e))
    db.log_audit(
        username=user, prompt=f"probe {ip}:{port}", query=None,
        rationale=result["detail"], result_total=None,
        error=None if result["status"] == "up" else result["status"],
        action="probe", credits=0,
    )
    return result


@app.post("/atg", dependencies=[Depends(require_same_origin)])
async def atg_probe(request: Request, user: str = Depends(current_user),
                    ip: str = Form(...), port: int = Form(10001)):
    """Active Veeder-Root ATG check: send the read-only In-Tank Inventory
    command (<SOH>I20100) and parse the reply. Same gate (SH_ENABLE_PROBE),
    same-origin guard, and audit log as /probe. No setup/write commands are
    ever sent — strictly reconnaissance equivalent to the Shodan banner."""
    if not config.PROBE_ENABLED:
        raise HTTPException(403, "Probing is disabled (set SH_ENABLE_PROBE=1).")
    ip = _valid_ip(ip)
    try:
        result = probe.veeder_root_atg(ip, port)
    except probe.ProbeNotAllowed as e:
        raise HTTPException(403, str(e))
    except ValueError as e:
        raise HTTPException(422, str(e))
    tanks = result.get("atg", {}).get("tanks", [])
    db.log_audit(
        username=user, prompt=f"atg {ip}:{port}", query=None,
        rationale=f"is_atg={result['is_atg']} bytes={result.get('bytes')}",
        result_total=len(tanks) or None,
        error=None if result["status"] == "up" else result["status"],
        action="atg", credits=0,
    )
    return result


@app.get("/healthz")
async def healthz():
    # Intentionally minimal: this endpoint is unauthenticated, so it must not
    # disclose config (bind address, enabled features, user count).
    # The full picture is available to authed callers via /api/info.
    return {"ok": True}
