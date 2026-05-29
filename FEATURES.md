# shodan-hunter v0.3 — Feature Reference

Quick reference for every capability added in v0.3. One section per feature.

## Credit cost summary

| Operation | Cost |
|-----------|------|
| Search (`/ask`) | 1 query credit per page (cached results: 0) |
| Host detail (`/host/{ip}`) | 1 query credit (cached: 0) |
| Domain recon (`/domain`) | 1 query credit (cached 6 h: 0) |
| InternetDB enrichment (`/idb/{ip}`) | **Free — 0 credits, no API key needed** |
| Honeypot flag (tag-based) | **Free — 0 credits** |
| Bulk DNS (`/dns`) | **Free — 0 credits** |
| Facet chart strip (embedded in `/`) | **Free — uses the free count endpoint** |
| Community query library (`/library`) | **Free — 0 credits** |
| On-demand scan (`/scan`) | **Scan credits** (separate pool from query credits) |
| Network alerts management (`/alerts`) | **Free to manage**; consumes plan's monitored-IP pool |

---

## 1. InternetDB Enrichment

**What it does:** Fetches pre-computed data about an IP from Shodan's free
`https://internetdb.shodan.io` service: open ports, known vulnerabilities
(CVE IDs), hostnames, CPEs, and tags. This data is shown inline on search
result rows and on the host detail page. No query credits are spent; the
endpoint does not require an API key.

**Underlying Shodan endpoint:** `GET https://internetdb.shodan.io/{ip}`

**Credit cost:** Free — 0 Shodan query credits.

**Routes:**
- `GET /idb/{ip}` — raw JSON response for a single IP (useful for scripting).
- Enrichment is also automatically applied to every IP on the search results
  page and on `GET /host/{ip}`.

**Usage example:**
```
curl -u team:changeme http://localhost:8000/idb/1.2.3.4
```

---

## 2. Honeypot flagging

**What it does:** Flags likely honeypots/decoys so the team doesn't waste time
on them. A 🍯 badge appears on a search result row and on the host page when
the host carries Shodan's `honeypot` tag (surfaced for free via InternetDB and
the search banner).

> **Note on honeyscore.** Shodan has **retired** the standalone per-IP
> honeyscore lab — it now responds *"Honeyscore has been integrated into the
> regular crawlers."* Honeypot detection therefore rides on the `honeypot`
> **tag** rather than a 0.0–1.0 score. The `honeyscore()` wrapper and the
> `/api/honeyscore/{ip}` endpoint remain as fail-soft shims that return `null`;
> the live signal is the tag-based badge. `SH_HONEYPOT_THRESHOLD` only affects
> the legacy numeric path (rarely exercised now).

**Underlying signal:** the `honeypot` tag in InternetDB / search results
(`https://internetdb.shodan.io/{ip}` and the banner `tags`).

**Credit cost:** Free — 0 Shodan query credits.

**Routes:**
- The 🍯 badge is shown automatically on search rows and the host page.
- `GET /api/honeyscore/{ip}` — JSON `{"ip": "...", "honeyscore": null}` (legacy
  shim; Shodan retired the score).

**Usage example:**
```
# Honeypot status is visible inline; the free InternetDB tags drive it:
curl -u team:changeme http://localhost:8000/idb/1.2.3.4   # look for "honeypot" in tags
```

---

## 3. Bulk DNS

**What it does:** Accepts a free-form paste of hostnames and/or IP addresses
(one per line, or comma-separated) and resolves them in bulk. Hostnames are
forward-resolved to IPs via Shodan's `/dns/resolve` endpoint; IPs are
reverse-resolved to hostnames via `/dns/reverse`. Both calls are batched in
groups of up to 100 to stay within the Shodan API limit. Results are cached
for `SH_DNS_CACHE_TTL` seconds (default `3600`, i.e. 1 h). Every lookup is
recorded in the audit log with `action=dns` and `credits=0`.

**Underlying Shodan endpoints:**
- `GET https://api.shodan.io/dns/resolve?hostnames=...`
- `GET https://api.shodan.io/dns/reverse?ips=...`

**Credit cost:** Free — 0 Shodan query credits.

**Routes:**
- `GET /dns` — form page.
- `POST /dns` — submit hostnames/IPs; renders results inline.

**Usage example:** Navigate to `/dns`, paste a list such as:
```
scanme.shodan.io
google.com
1.2.3.4
```
The page returns a table of resolved IPs and reverse-PTR hostnames.

---

## 4. Domain Recon

**What it does:** Queries Shodan's passive DNS database for a domain: returns
known subdomains and recent DNS records (A, AAAA, CNAME, MX, etc.) observed
by Shodan's crawlers. Results are cached for `SH_DOMAIN_CACHE_TTL` seconds
(default `21600`, i.e. 6 h), so a cache hit on a repeat lookup costs 0
additional credits. Every lookup is recorded in the audit log with
`action=domain` and `credits=1` (or `0` on a cache hit).

**Underlying Shodan endpoint:** `GET https://api.shodan.io/dns/domain/{domain}`

**Credit cost:** 1 query credit per uncached lookup.

**Routes:**
- `GET /domain?q=acme.com` — domain recon with a query-string parameter.
- `GET /domain/{name}` — domain recon with the domain in the URL path.

**Usage example:**
```
http://localhost:8000/domain/acme.com
http://localhost:8000/domain?q=acme.com
```

---

## 5. On-Demand Scan

**What it does:** Submits a fresh Shodan crawl of specified IPs or CIDR
ranges and allows polling the resulting scan status. Because submitting a
scan is a write action that consumes scan credits (separate from query
credits), this feature is **disabled by default** and must be explicitly
enabled by setting `SH_ENABLE_SCAN=true`.

Authorization is enforced in two modes:
- If `SH_SCAN_ALLOWLIST` is set (comma-separated CIDRs/IPs), every target in
  the submission must fall inside the allowlist or the request is rejected.
- If `SH_SCAN_ALLOWLIST` is empty, the form requires an explicit "I am
  authorized to scan these targets" checkbox to proceed.

The per-scan host count is capped at `SH_SCAN_MAX_HOSTS` (default `4096`).
Every submission attempt — successful or not — is recorded in the audit log
with `action=scan`.

**Underlying Shodan endpoints:**
- `POST https://api.shodan.io/shodan/scan` — submit targets.
- `GET https://api.shodan.io/shodan/scan/{id}` — poll status.

**Credit cost:** Scan credits (not query credits). The number of credits
consumed depends on the number of IPs and your Shodan plan.

**Routes:**
- `GET /scan` — scan form and recent scan history.
- `POST /scan` — submit a scan (requires `SH_ENABLE_SCAN=1`; form field
  `targets` = newline/comma-separated IPs or CIDRs; `confirm` = non-empty
  string when no allowlist is configured).
- `GET /scan/{id}` — poll the status of a previously submitted scan.

**Usage example:**
```
# Enable in .env first:
SH_ENABLE_SCAN=true
SH_SCAN_ALLOWLIST=10.10.0.0/16

# Then navigate to:
http://localhost:8000/scan
```

---

## 6. Network Alerts / Monitoring

**What it does:** Provides a UI to register Shodan network alerts (IP-range
monitors) and manage their triggers. Supported triggers include notification
on new open service, expired SSL certificate, matching CVE, and others from
Shodan's trigger catalog. A local database mirror records which teammate
created each alert, since Shodan's own API does not expose that.

Alert management (create, list, delete, toggle triggers) costs no query
credits, but registered alerts consume IP slots from your plan's
monitored-IP pool. The feature can be disabled by setting
`SH_ENABLE_ALERTS=false`.

Note: live event delivery via Shodan's alert notification stream is a future
capability. v0.3 covers alert registration, trigger configuration, and
inspection of registered alerts.

**Underlying Shodan endpoints:**
- `GET https://api.shodan.io/shodan/alert/info` — list alerts.
- `POST https://api.shodan.io/shodan/alert` — create an alert.
- `DELETE https://api.shodan.io/shodan/alert/{id}` — delete an alert.
- `PUT https://api.shodan.io/shodan/alert/{id}/notifier/...` — set triggers.

**Credit cost:** Free to manage. Consumes your plan's monitored-IP pool.

**Routes:**
- `GET /alerts` — list registered alerts with trigger state.
- `POST /alerts` — create a new alert (form fields: `name`, `ips`,
  `triggers` multi-select).
- `POST /alerts/{id}/delete` — delete an alert by ID.
- `POST /alerts/{id}/trigger` — enable or disable a specific trigger on an
  alert (form fields: `trigger` = trigger name, `enabled` = non-empty to
  enable).

**Usage example:**
```
http://localhost:8000/alerts
```
Fill in an alert name, paste IP ranges (e.g. `10.0.0.0/8`), and choose
triggers from the catalog. The creator's username is stored locally.

---

## 7. Facet Chart Strip

**What it does:** After a search is run, the results page shows a row of
aggregate charts summarizing the current query across six dimensions:
countries, ports, organizations, products, ASNs, and operating systems.
These aggregates are fetched using Shodan's `/shodan/host/count` endpoint,
which accepts facet parameters and is free (no query credits). The charts
give an at-a-glance breakdown of the result set without spending additional
credits.

**Underlying Shodan endpoint:** `GET https://api.shodan.io/shodan/host/count?query=...&facets=...`

**Credit cost:** Free — 0 Shodan query credits.

**Routes:** Embedded in `POST /ask` (the search results page at `/`). No
separate route.

**Usage example:** Run any search from the home page. The facet charts appear
below the result table automatically.

---

## 8. Community Query Library

**What it does:** Browses and searches the Shodan community's collection of
shared saved queries. Queries can be filtered by keyword. Clicking "Run"
on any library entry loads it into the search form. Results are cached for
`SH_QUERIES_CACHE_TTL` seconds (default `3600`, i.e. 1 h).

**Underlying Shodan endpoints:**
- `GET https://api.shodan.io/shodan/query` — top community queries.
- `GET https://api.shodan.io/shodan/query/search?query=...` — search by keyword.

**Credit cost:** Free — 0 Shodan query credits.

**Routes:**
- `GET /library` — browse community queries (optional `?q=keyword` and
  `?page=N` parameters).

**Usage example:**
```
http://localhost:8000/library
http://localhost:8000/library?q=webcam
```
