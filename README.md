# shodan-hunter

[![Repo](https://img.shields.io/badge/GitHub-jrsherlock%2Fshodan--hunter-181717?logo=github)](https://github.com/jrsherlock/shodan-hunter)

A friendly team UI in front of Shodan. Teammates type plain English; an
Azure OpenAI deployment translates the prompt into Shodan query syntax;
the app runs the search and renders the results. Click any IP for a host
detail page. Every prompt and generated query is logged so the team can
see what's been asked.

## What it is, what it isn't

It is:
- A chat-style web UI that converts natural language → Shodan query.
- Multi-user behind HTTP basic auth (each teammate has their own username
  so the audit log attributes queries).
- A thin wrapper around the Shodan REST API with short-lived result caching
  and a soft daily query-credit budget across the team.
- v0.3.0: eight additional capabilities covering free enrichment, DNS,
  domain recon, on-demand scanning, network alerts, and more (see below).

It isn't (yet):
- An agentic investigator. The LLM generates one query at a time. It does
  not chain calls or summarize results.
- An Azure AD SSO solution — basic auth keeps it simple. Put it on the
  internal network or behind a reverse proxy that does SSO if you need more.

## Setup

```bash
cd /Users/sherlock/Projects/shodan-hunter
uv venv          # if you haven't already
source .venv/bin/activate
uv pip install -r requirements.txt
cp .env.example .env
# Edit .env: paste SHODAN_API_KEY, your AZURE_OPENAI_*, and set SH_AUTH_USERS.
python run.py
```

Then open http://localhost:8000/ (or whatever IP you bound to).

## Features (v0.3)

Eight capabilities added on top of the existing NL→Shodan search. Credit
costs are noted per feature; "free" means no Shodan query credits are
consumed.

| # | Feature | Route(s) | Credit cost |
|---|---------|----------|-------------|
| 1 | **InternetDB enrichment** — ports, vulns, tags, CPEs from `internetdb.shodan.io` shown on search rows and the host page | `GET /idb/{ip}` (JSON) | Free (0 credits) |
| 2 | **Honeypot flagging** — a 🍯 badge on search rows and the host page when Shodan tags a host as a honeypot (free, tag-based). Shodan **retired** the per-IP honeyscore lab, so detection now uses the `honeypot` tag. | 🍯 badge inline; `GET /api/honeyscore/{ip}` (legacy shim → `null`) | Free (0 credits) |
| 3 | **Bulk DNS** — paste hostnames and/or IPs; forward-resolves hostnames and reverse-resolves IPs (Shodan `/dns/resolve` + `/dns/reverse`, batched ≤ 100) | `GET /dns`, `POST /dns` | Free (0 credits) |
| 4 | **Domain recon** — subdomains and passive DNS records via Shodan's DNS domain endpoint; results cached 6 h | `GET /domain?q=acme.com`, `GET /domain/{name}` | 1 query credit (cached 6 h) |
| 5 | **On-demand scan** — submit a fresh crawl of authorized IPs/CIDRs and poll status; **off by default**; gated by allowlist or per-request confirmation; every submission logged | `GET /scan`, `POST /scan`, `GET /scan/{id}` | Scan credits (not query credits) |
| 6 | **Network alerts / monitoring** — register IP ranges, enable triggers (new service, expired cert, matching CVE, etc.); a local mirror records which teammate created each alert | `GET /alerts`, `POST /alerts`, `POST /alerts/{id}/delete`, `POST /alerts/{id}/trigger` | Free to manage; consumes plan's monitored-IP pool |
| 7 | **Facet chart strip** — top countries/ports/orgs/products/ASNs/OS aggregates for the current query shown on the search results page at no credit cost (uses the free count endpoint) | `/` (search results page) | Free (0 credits) |
| 8 | **Community query library** — browse and search Shodan community-shared saved queries; click Run to execute one | `GET /library` | Free (0 credits) |

> Note: The audit log now records an `action` field (search/host/domain/dns/scan/alert) and the `credits` spent per row. On-demand scan uses scan credits, which are separate from query credits. Live event delivery via Shodan's alert stream is a future step; v0.3 covers alert registration, trigger management, and inspection.

## Routes

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Search home (NL→Shodan, facet strip) |
| `POST` | `/ask` | Run a search (LLM or override query) |
| `GET` | `/host/{ip}` | Host detail (InternetDB enriched + honeypot tag, pivot suggestions, liveness) |
| `POST` | `/probe` | Liveness TCP-connect to ip:port (requires `SH_ENABLE_PROBE=1`) |
| `GET` | `/log` | Audit log |
| `GET` | `/domain` | Domain recon form (`?q=acme.com`) |
| `GET` | `/domain/{name}` | Domain recon for a specific name |
| `GET` | `/dns` | Bulk DNS form |
| `POST` | `/dns` | Run bulk DNS resolve/reverse |
| `GET` | `/scan` | On-demand scan form / recent scans |
| `POST` | `/scan` | Submit a scan (requires `SH_ENABLE_SCAN=1`) |
| `GET` | `/scan/{id}` | Poll scan status |
| `GET` | `/alerts` | Network alerts list |
| `POST` | `/alerts` | Create a new alert |
| `POST` | `/alerts/{id}/delete` | Delete an alert |
| `POST` | `/alerts/{id}/trigger` | Enable/disable a trigger on an alert |
| `GET` | `/library` | Community query library |
| `GET` | `/idb/{ip}` | InternetDB JSON (free, 0 credits) |
| `GET` | `/api/honeyscore/{ip}` | Legacy honeyscore shim — Shodan retired it, returns `null`; honeypot status shows inline as a 🍯 tag badge |
| `GET` | `/api/count` | Shodan result count (free) |
| `GET` | `/api/info` | API/plan info + budget status |
| `GET` | `/healthz` | Health check (no auth) |

## Configuration

All via `.env`. See `.env.example` for every option. The important ones:

| Key | Purpose |
|---|---|
| `SHODAN_API_KEY` | Shared key. Every team query counts against this. |
| `AZURE_OPENAI_ENDPOINT` | e.g. `https://my-resource.openai.azure.com` |
| `AZURE_OPENAI_API_KEY` | Azure OpenAI resource key. |
| `AZURE_OPENAI_DEPLOYMENT` | The *deployment name* in your Azure resource (not the model name). |
| `AZURE_OPENAI_API_VERSION` | Default `2024-10-21`. |
| `SH_AUTH_USERS` | `user1:pw1,user2:pw2`. Each user logs in with their own credentials so the audit log identifies them. |
| `SH_DAILY_BUDGET` | Total query credits the team can spend per UTC day. |

### New configuration (v0.3)

| Key | Default | Purpose |
|-----|---------|---------|
| `SH_HONEYPOT_THRESHOLD` | `0.5` | Legacy honeyscore threshold. Shodan retired the per-IP score, so the 🍯 badge is now driven by the `honeypot` **tag**; this only affects the rarely-hit legacy numeric path. |
| `SH_HONEYSCORE_ROW_CAP` | `25` | Legacy cap for per-row honeyscore lookups. The search page no longer fans these out (detection is tag-based), so this is currently unused. |
| `SH_DOMAIN_CACHE_TTL` | `21600` | Seconds to cache domain recon results (6 h; passive DNS is slow-moving). |
| `SH_HONEYSCORE_CACHE_TTL` | `86400` | Seconds to cache the legacy honeyscore shim's (negative) results (24 h). |
| `SH_DNS_CACHE_TTL` | `3600` | Seconds to cache bulk DNS resolve/reverse results (1 h). |
| `SH_QUERIES_CACHE_TTL` | `3600` | Seconds to cache community query library results (1 h). |
| `SH_ENABLE_ALERTS` | `true` | Enable the `/alerts` network monitoring UI. Disable to hide the feature entirely. |
| `SH_ENABLE_SCAN` | `false` | Enable the `/scan` on-demand scanning UI. **Off by default** — scanning uses scan credits and must only target ranges you are authorized to scan. |
| `SH_SCAN_ALLOWLIST` | *(empty)* | Comma-separated CIDRs/IPs authorized for scanning. When set, scan requests are rejected unless every target falls inside the allowlist. When empty, the UI requires an explicit per-request "I am authorized" confirmation (still logged). |
| `SH_SCAN_MAX_HOSTS` | `4096` | Hard ceiling on the number of hosts per scan submission, regardless of allowlist. |
| `SH_ENABLE_PROBE` | `false` | Enable the host-page liveness probe (server-side TCP connect to a service). **Off by default** — it's the only feature that opens an outbound socket to a target. Browser-side "open https://ip:port" links are always shown and need no flag. |
| `SH_PROBE_ALLOW_PRIVATE` | `false` | Allow probing private/loopback/reserved addresses. Off by default so the probe can't be used as an internal port scanner. |
| `SH_PROBE_TIMEOUT` | `3` | Per-probe TCP connect timeout, in seconds. |

### Host-page next steps (pivots + liveness)

The host detail page surfaces two kinds of follow-up:

- **Pivot queries** — one-click Shodan searches derived from the host's own
  attributes (org, ASN, /24, product+version, TLS cert CN, favicon hash, CVE).
  Each runs as an `override_query` against `/ask` (no LLM). The "find the rest
  of the fleet" move.
- **Liveness** — every web service gets a browser-side `open https://ip:port`
  link (your browser connects, not the tool). With `SH_ENABLE_PROBE=1`, each
  service also gets a **probe** button that does a server-side TCP connect and
  reports up / down / timeout inline; every probe is audit-logged.

## What a session looks like

1. User opens the page, browser prompts for HTTP basic auth.
2. User types: *"Find exposed RDP on hosts in our org Acme Industries"*
3. The LLM is asked to produce a Shodan query and returns:
   `org:"Acme Industries" port:3389`
4. The app shows the generated query *(editable)* and the result table,
   with InternetDB enrichment and 🍯 honeypot badges on flagged rows, and
   country/port/org facet charts above the table.
5. Clicking a row drills into the full host record (`/host/{ip}`), which
   shows full Shodan data plus InternetDB ports/vulns/CPEs and a honeypot
   badge when the host is tagged as one.
6. The prompt + generated query + result count + user + action + credits
   are appended to the audit log (`/log`).

## Liability note

Every Shodan call is attributed to your shared API key. The daily budget is
a soft cap — set it. The basic-auth wall is not an audit boundary; assume
anyone with the credentials can drain your credits. Don't put this on the
public internet without a reverse proxy / SSO in front.

On-demand scanning (`/scan`) uses scan credits, which are separate from
query credits and billed differently. Only enable `SH_ENABLE_SCAN` if you
have confirmed authorization to scan the target ranges. The `SH_SCAN_ALLOWLIST`
is a hard safeguard; every submission is logged regardless.
