# Changelog

## 0.1.2 — 2026-10-02

- RDAP `available` cross-checked with DNS: if NS/A exist, override to `registered` (fixes false-available on some TLDs e.g. `.ac.uk`)
- Private cloud smoke + bench-50; PPE locked; margin notes in `docs/PRICING.md`

## 0.1 (2026-10-02)

- First private scaffold (D047 #5): batch domain availability via RDAP + DNS/WHOIS fallback.
- Verdicts: available | registered | unknown; method + registrar; optional Markdown table.
- Default memory 256 MB; unknown/failed free by default (`chargeFailedDomains=false`).
- PPE draft targets: actor-start ~$0.001 / GB; domain-verdict ~$0.0012.
