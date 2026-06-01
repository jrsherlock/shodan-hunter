"""FastAPI app: chat-style NL → Shodan UI."""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import ipaddress

from . import config, datastatus, db, internetdb, llm, monitor, pivots, probe, recon, scans, shodan_api
from .auth import current_user, require_same_origin
from .db import BudgetExceeded

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


def _ago(iso) -> str:
    """Compact 'time since' for a Shodan ISO timestamp: '3d', '5h', '2w', '4mo'.

    Shodan stamps banners in UTC without a tz suffix; we assume UTC. Returns ''
    for anything unparseable so the template can treat it as optional."""
    from datetime import datetime, timezone
    if not iso:
        return ""
    try:
        dt = datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
    except ValueError:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    secs = max(0.0, (datetime.now(timezone.utc) - dt).total_seconds())
    mins, hours, days = secs / 60, secs / 3600, secs / 86400
    if days >= 30:
        return f"{int(days // 30)}mo"
    if days >= 14:
        return f"{int(days // 7)}w"
    if days >= 1:
        return f"{int(days)}d"
    if hours >= 1:
        return f"{int(hours)}h"
    if mins >= 1:
        return f"{int(mins)}m"
    return "just now"


def _human(n) -> str:
    """Compact big-number formatting for hero tiles: 211717047 → '211.7M'."""
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "—"
    for unit, size in (("B", 1e9), ("M", 1e6), ("K", 1e3)):
        if abs(n) >= size:
            return f"{n / size:.1f}{unit}".replace(".0", "")
    return f"{int(n)}"


def _commas(n) -> str:
    """Thousands-separated integer, e.g. 16359262 → '16,359,262'."""
    try:
        return f"{int(n):,}"
    except (TypeError, ValueError):
        return str(n)


templates.env.filters["epoch_local"] = _epoch_local
templates.env.filters["ago"] = _ago
templates.env.filters["human"] = _human
templates.env.filters["commas"] = _commas
templates.env.globals["service_url"] = pivots.service_url
templates.env.globals["tag_meta"] = recon.tag_meta
templates.env.globals["country_flag"] = recon.country_flag
templates.env.globals["screenshot_of"] = recon.match_screenshot
templates.env.globals["recon_severity"] = recon.severity_from_cvss


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


EXAMPLES = [
    "Find exposed RDP on hosts owned by org \"Acme Industries\"",
    "Show me Apache servers in Germany running version 2.4.49",
    "Hosts with Log4Shell CVE-2021-44228",
    "Open Elasticsearch instances with no authentication",
    "Servers presenting SSL certificates for *.example.com",
    "Unpatched Exchange servers in the US",
    "Webcams indexed in Iowa",
    "MongoDB databases on port 27017 in Canada",
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
        "budget": db.budget_status(),
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


@app.exception_handler(BudgetExceeded)
async def _h_budget(request: Request, exc: BudgetExceeded):
    return _err(request, "Daily budget exceeded", str(exc), 429)


def _err(request: Request, title: str, detail: str, code: int):
    if request.url.path.startswith("/api/"):
        return JSONResponse({"error": title, "detail": detail}, status_code=code)
    # No auth on error pages so they always render
    return templates.TemplateResponse(
        request, "error.html",
        {"request": request, "user": None, "status": config.status(),
         "budget": db.budget_status(), "examples": EXAMPLES,
         "title": title, "detail": detail},
        status_code=code,
    )


# ── pages ────────────────────────────────────────────────────────────────


@app.get("/", response_class=HTMLResponse)
async def home(request: Request, user: str = Depends(current_user)):
    return templates.TemplateResponse(
        request, "chat.html",
        _ctx(request, user, prompt="", llm_result=None, search=None, override_query=None,
             recent=db.recent_audit(limit=10, username=user)),
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

    # Collapse the per-service matches into one card per host, then summarise the
    # page for the at-a-glance strip above the results.
    hosts = recon.group_by_host(matches)
    summary = recon.result_summary(hosts)

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
             search=search_result, hosts=hosts, summary=summary,
             page=page, facets=facet_groups, override_query=override,
             recent=db.recent_audit(limit=10, username=user)),
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
    # Severity-graded CVE list merged across host-level, per-service, and free
    # InternetDB sources (each may be a {CVE: {cvss}} dict or a bare CVE list).
    services = data.get("data") if isinstance(data.get("data"), list) else []
    host_vulns = recon.merge_vulns(
        data.get("vulns"),
        *[s.get("vulns") for s in services if isinstance(s, dict)],
        (idb or {}).get("vulns"),
    )
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
             host_vulns=host_vulns,
             host_flag=recon.country_flag(data.get("country_code")),
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
                       q: str = Query(""), page: int = Query(1)):
    q = (q or "").strip()
    library_error = None
    items: list = []
    try:
        data = shodan_api.query_search(q, page=page) if q else shodan_api.community_queries(page=page)
        items = (data.get("matches") if isinstance(data, dict) else data) or []
    except shodan_api.ShodanError as e:
        library_error = str(e)
    return templates.TemplateResponse(
        request, "library.html",
        _ctx(request, user, q=q, page=page, items=items, library_error=library_error),
    )


# ── internet pulse (global data-status dashboard; free, no credits) ──────────


@app.get("/pulse", response_class=HTMLResponse)
async def pulse_page(request: Request, user: str = Depends(current_user),
                     refresh: bool = False):
    """Shodan's global "Data Status" snapshot, re-rendered as a richer dashboard.
    Keyless and free — no Shodan API key, no query credits."""
    view = None
    pulse_error = None
    cache_state = None
    try:
        snap = datastatus.snapshot(use_cache=not refresh)
        cache_state = snap.get("_cache")
        view = datastatus.build_view(snap)
    except datastatus.DataStatusError as e:
        pulse_error = str(e)
    return templates.TemplateResponse(
        request, "pulse.html",
        _ctx(request, user, view=view, pulse_error=pulse_error, cache_state=cache_state),
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
        "budget": db.budget_status(),
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


@app.get("/healthz")
async def healthz():
    # Intentionally minimal: this endpoint is unauthenticated, so it must not
    # disclose config (bind address, budget, enabled features, user count).
    # The full picture is available to authed callers via /api/info.
    return {"ok": True}
