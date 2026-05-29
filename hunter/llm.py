"""Azure OpenAI bridge: natural language → Shodan query.

The model is asked to return strict JSON: {query, rationale, warnings}.
We parse it; the UI shows the generated query (editable) and the rationale.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any

from . import config, countries, shodan_api

# Tokens the model hallucinates when a prompt says "our/your …" — they match
# zero hosts and silently burn a credit. Stripped defensively below.
_PLACEHOLDER_BITS = ("your_", "your-", "<", "country_code", "org_name",
                     "company_name", "your.org", "example_org")


_COUNTRY_FILTER_RE = re.compile(
    r'(?P<sign>-?)country:(?:"(?P<q>[^"]+)"|(?P<u>[^\s"]+))', re.I
)


def _fix_country_names(query: str) -> tuple[str, list[str]]:
    """Rewrite ``country:`` filters whose value is a country *name* (e.g.
    ``country:"Germany"`` or ``country:USA``) into the ISO code Shodan needs
    (``country:DE`` / ``country:US``).

    Runs before the token loop so multi-word quoted names survive intact.
    Values that are already a code — or an unresolvable string like
    ``YOUR_COUNTRY_CODE`` — are left untouched for the token loop to validate.
    """
    warnings: list[str] = []

    def _sub(m: re.Match[str]) -> str:
        sign = m.group("sign")
        value = m.group("q") if m.group("q") is not None else m.group("u")
        # Already a valid code (or comma-list of codes)? Leave it alone.
        if re.fullmatch(r"[A-Za-z]{2}(,[A-Za-z]{2})*", value):
            return m.group(0)
        code = countries.resolve(value)
        if code is None:
            return m.group(0)  # let the token loop drop/flag it
        warnings.append(f"Mapped country “{value}” → {code} (Shodan needs the ISO code).")
        return f"{sign}country:{code}"

    return _COUNTRY_FILTER_RE.sub(_sub, query), warnings


def _sanitize_query(query: str) -> tuple[str, list[str]]:
    """Normalise/drop the query defects we've actually observed from the model:
    full-name ``country:`` values (mapped to their ISO code when we recognise
    them, else dropped), and literal placeholder stand-ins.

    Returns (clean_query, warnings). Quoted multi-word values survive because
    the country pass rewrites them in place and the token loop only ever drops
    whole tokens, rejoining with single spaces.
    """
    query, warnings = _fix_country_names(query)
    kept: list[str] = []
    for tok in query.split():
        low = tok.lower()
        m = re.match(r'^-?country:"?([^"]*)"?$', tok, re.I)
        if m and not re.fullmatch(r"[A-Za-z]{2}(,[A-Za-z]{2})*", m.group(1)):
            warnings.append(
                f"Removed invalid filter “{tok}” — Shodan country codes are "
                "2-letter ISO (US, GB, DE, CA…). Re-ask naming a specific country."
            )
            continue
        if any(bit in low for bit in _PLACEHOLDER_BITS):
            warnings.append(
                f"Removed placeholder “{tok}” — name the value explicitly; "
                "the tool can't resolve “our/your …”."
            )
            continue
        kept.append(tok)
    return " ".join(kept).strip(), warnings

# Shodan plans that include vuln:/has_vuln: filter access. Free/Membership do not.
_VULN_CAPABLE_PLANS = {
    "plus", "freelancer", "small business", "corporate", "enterprise", "dev",
}
_PLAN_CACHE: dict[str, Any] = {"plan": None, "vuln_ok": None, "ts": 0.0}
_PLAN_CACHE_TTL = 3600.0


def _plan_capability() -> tuple[str | None, bool | None]:
    """Return (plan_name, vuln_filter_available). Cached ~1h. (None, None) on failure."""
    now = time.time()
    if now - _PLAN_CACHE["ts"] < _PLAN_CACHE_TTL and _PLAN_CACHE["plan"] is not None:
        return _PLAN_CACHE["plan"], _PLAN_CACHE["vuln_ok"]
    try:
        info = shodan_api.api_info()
    except Exception:
        return None, None
    plan = (info.get("plan") or "").strip().lower() or None
    vuln_ok = plan in _VULN_CAPABLE_PLANS if plan else None
    _PLAN_CACHE.update({"plan": plan, "vuln_ok": vuln_ok, "ts": now})
    return plan, vuln_ok


class LLMNotConfigured(RuntimeError):
    pass


class LLMError(RuntimeError):
    pass


SYSTEM_PROMPT = """You translate plain-English security-recon requests into Shodan
search queries. Return STRICT JSON only — no markdown, no commentary outside JSON.

Schema:
{
  "query":     "the Shodan query string",
  "rationale": "one short sentence explaining what this query searches for",
  "warnings":  ["optional notes for the user, e.g. 'has_vuln requires a paid plan'"]
}

Shodan query syntax cheatsheet:
- Free text matches banners. Combine terms with spaces (implicit AND).
- Quote multi-word values:  org:"Acme Industries"
- Common filters (use COLON, not equals):
    hostname:example.com           # banner mentions hostname
    ssl.cert.subject.cn:example.com
    org:"Acme Industries"          # ISP/org name
    asn:AS15169                    # AS number
    net:203.0.113.0/24             # CIDR
    ip:203.0.113.5                 # single IP (rarely useful in search; use host page)
    port:3389                      # exposed TCP/UDP port
    country:US                     # 2-letter ISO code ONLY (US, GB, DE, CA, FR, JP) — never "USA"/"UK"/a full name
    city:"Des Moines"
    product:"Apache httpd"
    version:"2.4.49"
    os:"Windows 10"
    http.title:"login"
    http.html:"set-cookie"
    http.status:200
    http.component:"WordPress"
    http.favicon.hash:-247388890   # exact mmh3 favicon hash
    ssl:"Acme Industries"          # search within TLS cert text
    ssl.cert.expired:true
    ssl.cert.issuer.cn:"Let's Encrypt"
    has_vuln:true                  # paid plan required
    vuln:CVE-2021-44228            # paid plan required for vuln: search
    tag:vpn                        # tag:cdn, tag:honeypot, tag:cloud, tag:database
    device:"webcam"
    after:"2024-01-01"  before:"2024-12-31"
- Negate with a leading minus:  -port:80
- A query is a SPACE-SEPARATED list of filters and free-text terms.

Guidance:
- Prefer specific filters over free text. If the user mentions a company name,
  use org:"..." (quoted). If they mention a domain, use hostname:.
- If the user asks for vulnerabilities/CVEs, prefer vuln:<CVE-ID> when they
  named one; otherwise use has_vuln:true. Only emit a plan-related warning
  for these filters if the runtime context below says vuln access is
  unavailable on the current key.
- Never invent specific values (do not guess an org name the user didn't
  give). If the request is too vague to express, return a best-effort query
  and add a warning explaining what you assumed.
- country: takes a 2-letter ISO 3166-1 code (US, GB, DE, CA, FR, JP) — NEVER
  "USA", "UK", or a full country name; those match zero hosts.
- If the user says "our/my/your company/org/country/network" WITHOUT naming it,
  you do not know the value. OMIT that filter entirely and add a warning asking
  them to name it. NEVER emit a placeholder like YOUR_COUNTRY_CODE, <org>,
  YOUR_ORG, or YOUR_COMPANY — a literal placeholder matches nothing and wastes
  a query credit.
- Never include credentials, links, or commentary outside the JSON object.
"""


_aoai_client = None


def _client():
    """Lazy import + lazy construction. Raises LLMNotConfigured if missing env."""
    global _aoai_client
    if _aoai_client is not None:
        return _aoai_client
    if not (config.AZURE_ENDPOINT and config.AZURE_API_KEY and config.AZURE_DEPLOYMENT):
        raise LLMNotConfigured(
            "Azure OpenAI is not configured. Set AZURE_OPENAI_ENDPOINT, "
            "AZURE_OPENAI_API_KEY, and AZURE_OPENAI_DEPLOYMENT in .env."
        )
    from openai import AzureOpenAI  # noqa: PLC0415 — keep startup cheap

    _aoai_client = AzureOpenAI(
        api_key=config.AZURE_API_KEY,
        azure_endpoint=config.AZURE_ENDPOINT,
        api_version=config.AZURE_API_VERSION,
    )
    return _aoai_client


def prompt_to_query(prompt: str) -> dict[str, Any]:
    """Turn a user prompt into {query, rationale, warnings}."""
    prompt = prompt.strip()
    if not prompt:
        raise LLMError("empty prompt")

    client = _client()
    plan, vuln_ok = _plan_capability()
    if plan is None:
        runtime_ctx = (
            "Runtime context: current Shodan plan is UNKNOWN (api/info call failed). "
            "Assume default behavior."
        )
    else:
        vuln_line = (
            "vuln: and has_vuln: filters ARE available on this key — do NOT emit a "
            "paid-plan warning for them."
            if vuln_ok else
            f"vuln: and has_vuln: filters are NOT available on the '{plan}' plan — "
            "emit a warning if the query uses them."
        )
        runtime_ctx = f"Runtime context: current Shodan plan = '{plan}'. {vuln_line}"
    system_prompt = f"{SYSTEM_PROMPT}\n\n{runtime_ctx}"
    try:
        resp = client.chat.completions.create(
            model=config.AZURE_DEPLOYMENT,
            response_format={"type": "json_object"},
            temperature=0.1,
            max_tokens=400,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
        )
    except Exception as e:  # surface the SDK's specific exception text to the UI
        raise LLMError(f"Azure OpenAI call failed: {type(e).__name__}: {e}") from e

    choice = resp.choices[0] if resp.choices else None
    content = (choice.message.content if choice and choice.message else "") or ""
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError as e:
        raise LLMError(f"model did not return valid JSON: {e}; content={content!r}") from e

    query = (parsed.get("query") or "").strip()
    if not query:
        raise LLMError(f"model returned no query; full response={parsed!r}")

    query, sani_warnings = _sanitize_query(query)
    if not query:
        raise LLMError(
            "The generated query was only invalid/placeholder filters, so nothing "
            "was left to run — name the country/org explicitly. "
            + " ".join(sani_warnings)
        )

    warnings = list(parsed.get("warnings") or []) + sani_warnings
    if vuln_ok:
        warnings = [
            w for w in warnings
            if not ("paid plan" in w.lower() or "plan required" in w.lower())
        ]

    return {
        "query": query,
        "rationale": (parsed.get("rationale") or "").strip(),
        "warnings": warnings,
        "model": config.AZURE_DEPLOYMENT,
        "prompt": prompt,
    }
