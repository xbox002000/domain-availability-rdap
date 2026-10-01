"""Domain availability verdicts via RDAP (preferred), DNS, then WHOIS.

Stack: asyncwhois (MIT) + whodap (MIT) for RDAP/WHOIS; dnspython (ISC) for DNS.
openrdap is Go/MIT — not used in this Python Actor image; same protocol family.
"""
from __future__ import annotations

import time
from typing import Any

import asyncwhois
import dns.exception
import dns.resolver
from asyncwhois.errors import NotFoundError as WhoisNotFoundError
from whodap.errors import NotFoundError as RdapNotFoundError

from inputs import apex_domain

VERDICT_AVAILABLE = "available"
VERDICT_REGISTERED = "registered"
VERDICT_UNKNOWN = "unknown"
METHOD_RDAP = "RDAP"
METHOD_DNS = "DNS"
METHOD_WHOIS = "WHOIS"


def _first_str(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, list):
        for v in value:
            s = _first_str(v)
            if s:
                return s
        return None
    s = str(value).strip()
    return s or None


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, list):
        for v in value:
            s = _iso(v)
            if s:
                return s
        return None
    if hasattr(value, "isoformat"):
        try:
            return value.isoformat()
        except Exception:  # noqa: BLE001
            pass
    s = str(value).strip()
    return s or None


def _registrar_from_parsed(parsed: dict | None) -> str | None:
    if not parsed:
        return None
    for key in ("registrar", "registrar_name", "sponsoring_registrar"):
        s = _first_str(parsed.get(key))
        if s:
            return s
    return None


def _has_registration_signal(parsed: dict | None) -> bool:
    if not parsed:
        return False
    if _registrar_from_parsed(parsed):
        return True
    if _first_str(parsed.get("domain_name")) or _first_str(parsed.get("name")):
        return True
    if parsed.get("status") or parsed.get("name_servers") or parsed.get("created") or parsed.get("expires"):
        return True
    return False


async def check_rdap(domain: str, timeout: float) -> tuple[str | None, str | None, dict | None, str | None]:
    """Return (verdict, registrar, detail, error). verdict None = inconclusive."""
    target = apex_domain(domain)
    try:
        _raw, parsed = await asyncwhois.aio_rdap(target)
    except (RdapNotFoundError, WhoisNotFoundError) as e:
        msg = str(e).lower()
        if "not found" in msg or "404" in msg or "negative" in msg:
            return VERDICT_AVAILABLE, None, {"queriedDomain": target, "signal": "rdap_not_found"}, None
        return None, None, None, f"rdap: {type(e).__name__}: {str(e)[:200]}"
    except Exception as e:  # noqa: BLE001
        return None, None, None, f"rdap: {type(e).__name__}: {str(e)[:200]}"

    if not isinstance(parsed, dict):
        return None, None, None, "rdap: empty/unparsed response"
    registrar = _registrar_from_parsed(parsed)
    if _has_registration_signal(parsed):
        detail = {
            "queriedDomain": target,
            "domainName": _first_str(parsed.get("domain_name")),
            "status": parsed.get("status") if isinstance(parsed.get("status"), list) else _first_str(parsed.get("status")),
            "created": _iso(parsed.get("created")),
            "expires": _iso(parsed.get("expires")),
            "nameServers": parsed.get("name_servers") if isinstance(parsed.get("name_servers"), list) else None,
        }
        return VERDICT_REGISTERED, registrar, detail, None
    return None, None, {"queriedDomain": target}, "rdap: no registration fields"


def check_dns(domain: str, timeout: float) -> tuple[str | None, dict | None, str | None]:
    """DNS heuristic. NXDOMAIN → available; NS/A → registered. Blocking."""
    target = apex_domain(domain)
    resolver = dns.resolver.Resolver(configure=True)
    resolver.lifetime = timeout
    resolver.timeout = min(timeout, 5.0)
    detail: dict[str, Any] = {"queriedDomain": target, "A": [], "NS": []}

    try:
        ns = resolver.resolve(target, "NS")
        detail["NS"] = [str(r).rstrip(".") for r in ns]
        if detail["NS"]:
            return VERDICT_REGISTERED, detail, None
    except dns.resolver.NXDOMAIN:
        return VERDICT_AVAILABLE, {**detail, "nxdomain": True}, None
    except dns.resolver.NoAnswer:
        pass
    except dns.resolver.NoNameservers as e:
        return None, detail, f"dns: NoNameservers: {str(e)[:120]}"
    except dns.exception.Timeout:
        return None, detail, "dns: timeout"
    except Exception as e:  # noqa: BLE001
        return None, detail, f"dns: {type(e).__name__}: {str(e)[:120]}"

    try:
        ans = resolver.resolve(target, "A")
        detail["A"] = [str(r) for r in ans]
        if detail["A"]:
            return VERDICT_REGISTERED, detail, None
    except dns.resolver.NXDOMAIN:
        return VERDICT_AVAILABLE, {**detail, "nxdomain": True}, None
    except dns.resolver.NoAnswer:
        pass
    except dns.exception.Timeout:
        return None, detail, "dns: timeout"
    except Exception as e:  # noqa: BLE001
        return None, detail, f"dns: {type(e).__name__}: {str(e)[:120]}"

    return None, detail, "dns: inconclusive"


async def check_whois(domain: str, timeout: float) -> tuple[str | None, str | None, dict | None, str | None]:
    """WHOIS fallback. Return (verdict, registrar, detail, error)."""
    target = apex_domain(domain)
    try:
        _raw, parsed = await asyncwhois.aio_whois(target)
    except (WhoisNotFoundError, RdapNotFoundError) as e:
        msg = str(e).lower()
        if "not found" in msg or "no match" in msg or "available" in msg:
            return VERDICT_AVAILABLE, None, {"queriedDomain": target, "signal": "whois_not_found"}, None
        return None, None, None, f"whois: {type(e).__name__}: {str(e)[:200]}"
    except Exception as e:  # noqa: BLE001
        return None, None, None, f"whois: {type(e).__name__}: {str(e)[:200]}"

    if not isinstance(parsed, dict):
        return None, None, None, "whois: empty/unparsed response"
    registrar = _registrar_from_parsed(parsed)
    if _has_registration_signal(parsed):
        detail = {
            "queriedDomain": target,
            "domainName": _first_str(parsed.get("domain_name")),
            "created": _iso(parsed.get("created") or parsed.get("creation_date")),
            "expires": _iso(parsed.get("expires") or parsed.get("expiration_date")),
        }
        return VERDICT_REGISTERED, registrar, detail, None
    return None, None, {"queriedDomain": target}, "whois: no registration fields"


async def check_domain(
    domain: str,
    *,
    use_rdap: bool = True,
    use_dns: bool = True,
    use_whois: bool = True,
    timeout: float = 20.0,
) -> dict[str, Any]:
    """Async availability check for one domain."""
    t0 = time.time()
    errors: list[str] = []
    detail: dict[str, Any] | None = None
    verdict: str | None = None
    method: str | None = None
    registrar: str | None = None

    # Split timeout across enabled methods (RDAP gets the largest share).
    enabled = int(use_rdap) + int(use_dns) + int(use_whois)
    if enabled == 0:
        raise ValueError("Enable at least one of useRdap, useDns, useWhois.")
    per = max(5.0, timeout / max(enabled, 1))

    if use_rdap:
        v, reg, det, err = await check_rdap(domain, per)
        if err:
            errors.append(err)
        if det:
            detail = {"rdap": det}
        if v:
            verdict, method, registrar = v, METHOD_RDAP, reg

    # Some TLDs (e.g. .ac.uk) return RDAP 404 for live names — cross-check DNS.
    need_dns = use_dns and (verdict is None or verdict == VERDICT_AVAILABLE)
    if need_dns:
        import asyncio

        v, det, err = await asyncio.to_thread(check_dns, domain, min(per, 8.0))
        if err and verdict is None:
            errors.append(err)
        if det:
            detail = {**(detail or {}), "dns": det}
        if v == VERDICT_REGISTERED:
            # Prefer DNS registered over RDAP false-available
            verdict, method = v, METHOD_DNS
            if "rdap: cross-check" not in " ".join(errors):
                if (detail or {}).get("rdap", {}).get("signal") == "rdap_not_found":
                    errors.append("rdap: not_found overridden by DNS NS/A")
        elif verdict is None and v:
            verdict, method = v, METHOD_DNS

    if verdict is None and use_whois:
        v, reg, det, err = await check_whois(domain, per)
        if err:
            errors.append(err)
        if det:
            detail = {**(detail or {}), "whois": det}
        if v:
            verdict, method, registrar = v, METHOD_WHOIS, reg or registrar

    if verdict is None:
        verdict = VERDICT_UNKNOWN
        status = "error" if errors else "unknown"
    elif verdict in (VERDICT_AVAILABLE, VERDICT_REGISTERED):
        status = "ok"
    else:
        status = "unknown"

    return {
        "domain": domain,
        "verdict": verdict,
        "method": method,
        "registrar": registrar,
        "status": status,
        "detail": detail,
        "errors": errors,
        "durationMs": int((time.time() - t0) * 1000),
    }
