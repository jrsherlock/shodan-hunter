# Shodan Handoff — ASP-Lite → shodan-hunter

Distilled reference of everything Shodan-related in ASP-Lite, so shodan-hunter can be built without re-discovering this work. Source files are pinned with absolute paths so they can be opened directly.

---

## 1. Source files in ASP-Lite

| File | Lines | Role |
|------|-------|------|
| `/Users/sherlock/Projects/asp-lite/shodan/shodan_domain_scanner.py` | 978 | **Phase 1 — Discovery scanner.** Direct `shodan` Python lib + raw REST calls. The richest reference; covers DNS, search, SSL, facets, vuln search, InternetDB, Exploits API. |
| `/Users/sherlock/Projects/asp-lite/collect_shodan.py` | 614 | **Phase 2 — Infra-aware enrichment.** Classifies IPs first, then runs *parallel* `host()` lookups with tier-aware retry. Skips CDN IPs. Builds `infrastructure_profile.json`. |
| `/Users/sherlock/Projects/asp-lite/cloud_ip_classifier.py` | 661 | Classifies IPs as cloud / CDN / dedicated / unknown using AWS+GCP+Azure+Cloudflare CIDR feeds (24h disk cache at `~/.asp-lite/cloud_ranges/`). |
| `/Users/sherlock/Projects/asp-lite/tools/run_shodan.sh` | 145 | Bash wrapper — orchestrates Phase 1 → Phase 2 + emits human-readable summary lines. |
| `/Users/sherlock/Projects/asp-lite/shodan/shodan_scanner.py` | 285 | Older / lighter scanner. Skip unless you want a minimal starting skeleton. |
| `/Users/sherlock/Projects/asp-lite/workflow.yaml` lines 139–147 | — | Tool registration (timeout, env_required, stage). |
| `/Users/sherlock/Projects/asp-lite/.env.example` lines 5–6 | — | `SHODAN_API_KEY=` env var convention. |

---

## 2. Shodan endpoints used (the menu to choose from)

| Endpoint | Cost | Library call | Why we use it |
|---|---|---|---|
| `GET /api-info` | free | `api.info()` | Plan name, query/scan credits left, monitored IPs. |
| `GET /dns/domain/{domain}` | 1 credit | raw REST | Subdomains + recent DNS records from Shodan's passive DB. |
| `GET /dns/resolve?hostnames=...` | free | raw REST (batch ≤100) | Forward DNS in bulk. |
| `GET /dns/reverse?ips=...` | free | raw REST (batch ≤100) | Reverse DNS in bulk. |
| `GET /shodan/host/{ip}` | 1 credit | `api.host(ip, history=True)` | Full host record — ports, services, banners, SSL, vulns. **Tier-2 retry without `history=True` for cloud IPs that return empty.** |
| `GET /shodan/host/search?query=...` | 1 credit/page | `api.search(query)` or `api.search_cursor(query)` (paginates free of extra credits after the first) | Banner search. Key filters used: `hostname:`, `ssl.cert.subject.cn:`, `org:"..."`, `has_vuln:true`, `ssl.cert.expired:true`, `port:`. |
| `GET /shodan/host/count?query=...&facets=...` | **free** | `api.count(query, facets=[...])` | **Always use this for previews / stats.** Same filters as search but no credit charge. Facets we pull: `port, org, asn, country, product, version, os, vuln, domain, isp, http.component, ssl.version, ssl.cipher.name, tag`. |
| `https://internetdb.shodan.io/{ip}` | **free, no key** | raw REST | Bulk pre-enrichment: ports, hostnames, CPEs, vulns, tags. Use this to *prioritize* before spending credits on `host()`. |
| `https://exploits.shodan.io/api/search?query=CVE-...` | free w/ key | raw REST | Maps CVE → known exploits (ExploitDB, Metasploit, etc.). Different host from `api.shodan.io`. |

**Critical**: `host()` returns a 404-equivalent APIError with the string `"No information available"` *or* `"Unable to fetch information"` — both mean empty. See `collect_shodan.py:254` (`no_data_markers`).

---

## 3. Patterns worth lifting verbatim

### 3a. Parallel `host()` lookups with stagger + tier-aware retry
`collect_shodan.py:275-385` — `ThreadPoolExecutor(max_workers=3)`, 0.5s submission stagger, retry without `history=True` for cloud IPs, batch-logs "no data" results grouped by infra type instead of spamming.

### 3b. Smart query construction — skip org search if org is a cloud provider
`collect_shodan.py:188-228` + `cloud_ip_classifier.py:68-87` (`CLOUD_PROVIDER_ORGS` + `is_cloud_provider_org()`). If the detected org is "Amazon Technologies Inc.", an `org:"Amazon..."` search returns *all of AWS's customers* and pollutes results.

### 3c. InternetDB pre-enrichment before paid lookups
`shodan_domain_scanner.py:763-770` — query InternetDB free, then sort IPs by `vulns*10 + ports` count so paid `host()` credits hit the highest-signal IPs first.

### 3d. Rate-limit handling
`shodan_domain_scanner.py:80-83` — on HTTP 429, sleep 5s and retry. Otherwise a baseline 1s `rate_limit_delay` between calls. Note: the official `shodan` lib does some of this internally; the raw-REST calls don't.

### 3e. Cursor pagination fallback
`shodan_domain_scanner.py:329-367` — try `search_cursor()` (deeper paging on higher plans), fall back to one-page `search()` on APIError.

### 3f. CVE → Exploit correlation
`shodan_domain_scanner.py:550-598` — after collecting all CVEs from hosts + vuln-searches, batch-query `exploits.shodan.io` to flag which CVEs have public exploits.

---

## 4. Output data shape (what we save to disk)

```
data/<domain>/raw/shodan/
  discovery.json                  # Phase 1: comprehensive scan from shodan_domain_scanner.py
  search_results.json             # Phase 2: deduplicated search matches from collect_shodan.py
  host_<ip-with-underscores>.json # One file per IP enriched
  infrastructure_profile.json     # Phase 2: classification + cloud breakdown + interesting IPs
```

`infrastructure_profile.json` schema (built in `collect_shodan.py:388-519`) — useful even outside ASP-Lite:
```json
{
  "profile_generated": "ISO-8601",
  "ip_classifications": [{"ip", "infra_type", "provider", "service", "region", "enrichment_tier"}],
  "ip_classification": {"total", "cloud", "cdn", "dedicated", "unknown"},
  "enrichment_summary": {"total", "success", "success_retry", "no_data", "errors", "cdn_skipped", "duration_seconds"},
  "cloud_breakdown": {"aws": {"count", "services": {...}, "regions": {...}}, ...},
  "dedicated_assets": [{"ip", "org", "asn", "hostnames", "ports"}],
  "interesting_cloud_ips": [{"ip", "reason", "ports", "notable_ports", "vulns"}],
  "primary_hosting": "aws",
  "regions": ["us-east-1", ...],
  "cdn_detected": "cloudflare"
}
```

---

## 5. Filters / dorks we found useful

| Use case | Query |
|---|---|
| All exposed hosts for a domain | `hostname:example.com` |
| SSL certs naming a domain | `ssl.cert.subject.cn:example.com` |
| Hosts owned by an org | `org:"Some Org Name"` (skip if org is a cloud provider) |
| Vulnerable hosts (Small Biz+) | `hostname:example.com has_vuln:true` |
| Expired certs | `hostname:example.com ssl.cert.expired:true` |
| Critical exposed ports | `hostname:example.com port:3389,445,23,21,161,1433,3306,5432,27017,6379,11211` |
| Favicon pivot (find shadow infra) | `http.favicon.hash:<mmh3-hash>` — **but check `count` first**; default favicons return thousands of unrelated hosts (see ASP-Lite memory `feedback_favicon_pivot_false_positives.md`). |
| SSL-cert pivot (better than favicon) | `ssl:"<unique cn or org name>"` |

---

## 6. Operational lessons from ASP-Lite

- **The key is *your* liability.** Every query is attributed to your account. Plan abuse controls before you expose this to anyone — per-user quotas, query allowlisting, audit log. See our prior conversation.
- **InternetDB first, `host()` second.** Free pre-enrichment of N IPs costs nothing; spending 100 query credits on cold IPs is wasteful. Sort by InternetDB signal before paying.
- **Always classify before enriching.** Querying `host()` on a CloudFront edge IP returns useless edge-network metadata, not customer infra. CDN IPs should be *skipped*, not just deprioritized.
- **`-tags` does not exist in Shodan API** (that's a Nuclei trap). The Shodan query DSL uses `tag:` as a *filter*, e.g. `tag:vpn`.
- **Cache aggressively.** A `host()` response is mostly stable over hours. We do *not* cache in ASP-Lite (every scan re-queries), but for an interactive tool, cache `host()` and InternetDB responses by IP with a short TTL (~1–24h). Pattern to copy: `cvedb_enrichment.py` uses disk-cached `requests.get()` with TTL.
- **Plan capabilities differ.** `search_cursor` requires Small Business+. `has_vuln:` requires Small Business+. Detect plan via `api.info()` at startup and feature-flag accordingly.
- **HackNotice agreement is separate** — Shodan ToS only. Re-read Shodan's commercial ToS before letting external users hit *your* key; reselling/proxying API access is restricted.

---

## 7. Dependencies

```
shodan        # official python client — wraps host/search/count/info
requests      # for direct REST (InternetDB, Exploits API, Azure ranges discovery)
ipaddress     # stdlib, for CIDR matching in classifier
```

---

## 8. Suggested copy-list for shodan-hunter v0

Minimum viable lift from ASP-Lite, in priority order:

1. **`shodan_domain_scanner.py` whole-file** as a starting library — strip the file-output bits, keep the API methods. Each method is independently useful.
2. **`cloud_ip_classifier.py`** — drop-in, no ASP-Lite coupling. Just change `CACHE_DIR` from `~/.asp-lite/` to `~/.shodan-hunter/`.
3. **The parallel `host()` pattern** from `collect_shodan.py:275-385`.
4. **The CDN-skip / cloud-provider-org-skip logic** from `collect_shodan.py:188-228` — this alone has saved us thousands of wasted credits.
5. **InternetDB pre-enrichment loop** from `shodan_domain_scanner.py:600-634`.

Things to leave behind:
- ASP-Lite's `data/<domain>/raw/...` path convention — shodan-hunter should pick its own.
- The `tools/common.sh` Bash wrapper machinery (logging, arg parsing) — only relevant to ASP-Lite's orchestrator.
- The `infrastructure_profile.json` schema is useful, but you'll likely want a different output shape for a standalone tool.
