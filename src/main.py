"""Apify Actor: batch domain availability via RDAP / DNS / WHOIS."""
from __future__ import annotations

import asyncio
import datetime as dt
import resource
import time
from collections import Counter

from apify import Actor

from availability import VERDICT_AVAILABLE, VERDICT_REGISTERED, check_domain
from charging import Charger
from inputs import collect_domains

EVENT = "domain-verdict"
PUSH_BATCH = 50


def _md_table(rows: list[dict]) -> str:
    lines = [
        "| Domain | Verdict | Method | Registrar | ms |",
        "|---|---|---|---|---|",
    ]
    for r in rows:
        reg = (r.get("registrar") or "").replace("|", "/")
        lines.append(
            f"| {r.get('domain','')} | {r.get('verdict','')} | {r.get('method') or '-'} | "
            f"{reg or '-'} | {r.get('durationMs', 0)} |"
        )
    return "\n".join(lines) + "\n"


async def main() -> None:
    async with Actor:
        t0 = time.time()
        inp = await Actor.get_input() or {}
        charger = Charger(EVENT)

        domains, warns = collect_domains(inp.get("domains"))
        for w in warns:
            Actor.log.warning(w)
        if not domains:
            raise ValueError("Provide at least one domain in `domains`.")

        max_domains = int(inp.get("maxDomains", 500) or 0) or None
        budget = charger.budget(EVENT)
        if budget is not None and (max_domains is None or budget < max_domains):
            Actor.log.info(f"Spending limit allows about {budget} domain(s); capping maxDomains.")
            max_domains = budget
        if max_domains is not None:
            domains = domains[:max_domains]

        use_rdap = bool(inp.get("useRdap", True))
        use_dns = bool(inp.get("useDns", True))
        use_whois = bool(inp.get("useWhois", True))
        if not (use_rdap or use_dns or use_whois):
            raise ValueError("Enable at least one of useRdap, useDns, useWhois.")

        conc = max(1, min(int(inp.get("maxConcurrency", 4)), 20))
        delay_ms = int(inp.get("queryDelayMs", 100) or 0)
        timeout = float(inp.get("requestTimeoutSecs", 20))
        charge_failed = bool(inp.get("chargeFailedDomains", False))
        write_md = bool(inp.get("writeMarkdownTable", False))

        sem = asyncio.Semaphore(conc)
        delay_lock = asyncio.Lock()
        last_query = 0.0
        verdict_counts: Counter = Counter()
        status_counts: Counter = Counter()
        method_counts: Counter = Counter()
        looked_up = 0
        charged_n = 0
        free_n = 0
        lock = asyncio.Lock()
        pending_charge: list[dict] = []
        pending_free: list[dict] = []
        all_rows: list[dict] = []

        async def flush(force: bool = False) -> None:
            nonlocal charged_n, free_n, pending_charge, pending_free
            if pending_charge and (force or len(pending_charge) >= PUSH_BATCH):
                batch = pending_charge
                pending_charge = []
                n = await charger.push_and_charge(batch, EVENT)
                charged_n += n
                if n < len(batch):
                    charger.limit_reached = True
            if pending_free and (force or len(pending_free) >= PUSH_BATCH):
                batch = pending_free
                pending_free = []
                await charger.push_free(batch)
                free_n += len(batch)

        async def one(domain: str) -> None:
            nonlocal looked_up, last_query
            if charger.limit_reached:
                return
            async with sem:
                if charger.limit_reached:
                    return
                if delay_ms > 0 and (use_rdap or use_whois):
                    async with delay_lock:
                        now = time.monotonic()
                        wait = (last_query + delay_ms / 1000.0) - now
                        if wait > 0:
                            await asyncio.sleep(wait)
                        last_query = time.monotonic()
                try:
                    item = await asyncio.wait_for(
                        check_domain(
                            domain,
                            use_rdap=use_rdap,
                            use_dns=use_dns,
                            use_whois=use_whois,
                            timeout=timeout,
                        ),
                        timeout=timeout + 5,
                    )
                except Exception as e:  # noqa: BLE001
                    item = {
                        "domain": domain,
                        "verdict": "unknown",
                        "method": None,
                        "registrar": None,
                        "status": "error",
                        "detail": None,
                        "errors": [f"{type(e).__name__}: {str(e)[:240]}"],
                        "durationMs": 0,
                    }
                billable = item["verdict"] in (VERDICT_AVAILABLE, VERDICT_REGISTERED) or charge_failed
                async with lock:
                    looked_up += 1
                    verdict_counts[item["verdict"]] += 1
                    status_counts[item["status"]] += 1
                    if item.get("method"):
                        method_counts[item["method"]] += 1
                    all_rows.append(item)
                    if billable:
                        pending_charge.append(item)
                    else:
                        pending_free.append(item)
                    await flush()
                    if looked_up % 10 == 0 or looked_up == len(domains):
                        await Actor.set_status_message(
                            f"Checked {looked_up}/{len(domains)} — "
                            f"available {verdict_counts['available']}, "
                            f"registered {verdict_counts['registered']}, "
                            f"unknown {verdict_counts['unknown']}"
                        )

        Actor.log.info(
            f"{len(domains)} domain(s); concurrency={conc}; "
            f"rdap={use_rdap} dns={use_dns} whois={use_whois}; chargeFailed={charge_failed}"
        )
        await Actor.set_status_message(f"Checking {len(domains)} domain(s)…")
        await asyncio.gather(*(one(d) for d in domains))
        async with lock:
            await flush(force=True)

        peak_mb = round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024)
        summary = {
            "totalChecked": looked_up,
            "charged": charged_n,
            "freeUnknownOrError": free_n,
            "available": verdict_counts["available"],
            "registered": verdict_counts["registered"],
            "unknown": verdict_counts["unknown"],
            "byVerdict": dict(verdict_counts),
            "byStatus": dict(status_counts),
            "byMethod": dict(method_counts),
            "useRdap": use_rdap,
            "useDns": use_dns,
            "useWhois": use_whois,
            "chargeFailedDomains": charge_failed,
            "inputDomains": len(domains),
            "maxDomainsReached": max_domains is not None and looked_up >= max_domains,
            "chargedEvents": dict(charger.counts),
            "durationSecs": round(time.time() - t0, 1),
            "peakMemoryMb": peak_mb,
            "finishedAt": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
        }
        store = await Actor.open_key_value_store()
        await store.set_value("SUMMARY", summary)
        await store.set_value("OUTPUT", summary)
        if write_md:
            await store.set_value("TABLE.md", _md_table(all_rows), content_type="text/markdown; charset=utf-8")
        msg = (
            f"Done: checked {looked_up}, charged {charged_n}, free {free_n}; "
            f"available {verdict_counts['available']}, registered {verdict_counts['registered']}, "
            f"unknown {verdict_counts['unknown']}. "
            f"Charged events: {charger.counts or 'nothing'}."
        )
        Actor.log.info(msg + f" Peak memory {peak_mb} MB, {summary['durationSecs']} s.")
        await Actor.set_status_message(msg, is_terminal=True)


if __name__ == "__main__":
    asyncio.run(main())
