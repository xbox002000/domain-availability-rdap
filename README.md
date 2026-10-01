# Domain Availability Checker — RDAP Batch

**Batch domain availability verdicts (`available` | `registered` | `unknown`) via public RDAP, with DNS and WHOIS fallbacks — light memory, failed/unknown free by default.**

Paste a list of domains. Each name is checked with RDAP first (MIT `asyncwhois` / `whodap`). If RDAP is inconclusive, optional DNS (NXDOMAIN vs NS/A) and WHOIS fill in. Default memory: **256 MB**. Separate product from WHOIS/DNS/SSL enrichment — this Actor answers *is it taken?*, not full enrichment.

## What you get

- ✅ **Verdict** — `available` | `registered` | `unknown` per domain
- 🔎 **Method** — which source decided: `RDAP` | `DNS` | `WHOIS`
- 🏷 **Registrar** — when RDAP/WHOIS returns one
- 📦 **Structured JSON** — one dataset row per domain + overview table
- 🧾 **SUMMARY / OUTPUT** — counts, duration, peak memory
- 📄 **Optional Markdown table** — `TABLE.md` in the key-value store
- 💸 **Unknown/failed free by default** — only clear verdicts are charged unless `chargeFailedDomains` is on
- 🪶 **Light** — no browser; RDAP/DNS/WHOIS only; **256 MB** default

## Positioning

- **This Actor:** batch **availability** for inventory / reclaim / naming checks.
- **Sibling `whois-dns-ssl-lookup`:** domain **enrichment** (WHOIS dates, DNS records, SSL days-left).
- **Not** spam, lead-gen, or mass cold-outreach tooling.

## Measured results

Local + private cloud benches (see **Measured results** above after cloud runs).

| Test | Result |
|---|---|
| Local smoke: example.com + unused `.com` | registered (RDAP) + available (RDAP) |
| Cloud smoke 2 + bench-50 @ 256 MB | ~$0.000024 / domain platform cost; ~97.5% margin @ $0.0012 list ×0.8 share |

## Use cases

- **Inventory checks** — confirm which names in a list are free vs taken
- **Reclaim / expiry follow-up** — pair with enrichment Actors for dates
- **Naming shortlists** — batch-screen candidate domains before registering
- **Dataset hygiene** — flag dead or still-registered hosts in an archive list

## How to use

1. Paste domains in **Domains** (or URLs — the host is used).
2. Keep RDAP on; leave DNS/WHOIS fallbacks on unless you need RDAP-only.
3. Click **Start**. Results are in the **Dataset**; `SUMMARY` / `OUTPUT` in the **Key-value store**.

### Input example

```json
{
  "domains": [
    "example.com",
    "this-domain-definitely-not-registered-xyzzy-99999.com"
  ],
  "maxDomains": 100,
  "useRdap": true,
  "useDns": true,
  "useWhois": true,
  "maxConcurrency": 4,
  "queryDelayMs": 100,
  "writeMarkdownTable": false,
  "chargeFailedDomains": false
}
```

### Output example (one dataset item)

```json
{
  "domain": "example.com",
  "verdict": "registered",
  "method": "RDAP",
  "registrar": "RESERVED-Internet Assigned Numbers Authority",
  "status": "ok",
  "detail": {
    "rdap": {
      "queriedDomain": "example.com",
      "domainName": "EXAMPLE.COM",
      "expires": "2027-08-13T04:00:00"
    }
  },
  "errors": [],
  "durationMs": 450
}
```

### Key-value store records

| Key | Content |
|---|---|
| `SUMMARY` | Counts by verdict/method, charged, duration, peak memory |
| `OUTPUT` | Same summary (sibling Actors consistency) |
| `TABLE.md` | Optional Markdown table when `writeMarkdownTable` is true |

## Pricing

Pay per event (locked from measured cloud cost — see **Measured results** above):

| Event | Target / locked |
|---|---|
| Domain availability verdict (primary) | **~$0.0012** per clear verdict (= $1.20 / 1,000) |
| Actor start (Apify synthetic) | **~$0.001** / GB (1 GB minimum) |

By default, `unknown` / `error` rows are **not** charged. Invalid inputs never become a row. See **Measured results** above for measured platform cost.

## Integrations

```python
from apify_client import ApifyClient
client = ApifyClient("<token>")
run = client.actor("YOUR_USERNAME/domain-availability-rdap").call(run_input={
    "domains": ["example.com", "example.org"],
    "maxConcurrency": 4,
})
for item in client.dataset(run["defaultDatasetId"]).iterate_items():
    print(item["domain"], item["verdict"], item["method"])
```

## Related Actors

- [Bulk WHOIS DNS SSL Lookup](https://apify.com/YOUR_USERNAME/whois-dns-ssl-lookup) — enrichment (registrar dates, DNS, SSL), not availability
- [Bulk URL Status Checker](https://apify.com/YOUR_USERNAME/url-status-checker) — HTTP status / redirects

## Limitations

- Public RDAP/WHOIS servers rate-limit; keep concurrency polite.
- Some TLDs are thin or RDAP-incomplete — those may fall through to DNS/WHOIS or `unknown`.
- DNS NXDOMAIN is a strong hint but not a registrar guarantee for every TLD.
- Not a substitute for a registrar's official availability API at checkout time.

## License & source code

This Actor is open source under the **GNU Affero General Public License v3.0 (AGPL-3.0)** — see `LICENSE`. Runtime deps: asyncwhois/whodap (MIT), dnspython (ISC). Public GitHub link will be added when the repository is pushed.
