"""Normalize domain lists from strings, {domain}, {url}, or mixed arrays."""
from __future__ import annotations

import re
from typing import Any, Iterable
from urllib.parse import urlparse

_HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)
_IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$|^\[?[0-9a-fA-F:]+\]?$")


def normalize_domain(raw: str) -> str | None:
    """Extract a registrable-looking hostname. Returns None for junk / IPs."""
    s = (raw or "").strip().strip("\"'<>").lower()
    if not s or s.startswith("#"):
        return None
    if "://" in s or "/" in s or "?" in s:
        if "://" not in s:
            s = "https://" + s
        try:
            host = urlparse(s).hostname
        except Exception:  # noqa: BLE001
            return None
        if not host:
            return None
        s = host.lower()
    s = s.rstrip(".")
    if s.startswith("www.") and s.count(".") >= 2:
        # Keep www for DNS/SSL accuracy; WHOIS usually wants apex — strip later in whois path.
        pass
    if _IP_RE.match(s):
        return None
    if not _HOST_RE.match(s):
        return None
    return s


def apex_domain(domain: str) -> str:
    """Best-effort apex for WHOIS (strip a single leading www.)."""
    if domain.startswith("www.") and domain.count(".") >= 2:
        return domain[4:]
    return domain


def _split(text: str) -> list[str]:
    return [p for p in re.split(r"[\s,;]+", text) if p]


def collect_domains(values: Iterable[Any] | str | None) -> tuple[list[str], list[str]]:
    """Return (domains, warnings). Deduplicates while preserving order."""
    warnings: list[str] = []
    raw: list[str] = []
    if values is None:
        values = []
    if isinstance(values, str):
        values = _split(values)
    for v in values:
        if isinstance(v, dict):
            if v.get("domain"):
                raw.append(str(v["domain"]))
            elif v.get("url"):
                raw.append(str(v["url"]))
            elif v.get("host"):
                raw.append(str(v["host"]))
            else:
                warnings.append(f"Ignored object without domain/url: {str(v)[:120]}")
        elif isinstance(v, str):
            raw.extend(_split(v))
        else:
            warnings.append(f"Ignored non-string input: {type(v).__name__}")
    seen: set[str] = set()
    out: list[str] = []
    for r in raw:
        d = normalize_domain(r)
        if d is None:
            warnings.append(f"Ignored invalid domain: {r[:200]}")
            continue
        if d not in seen:
            seen.add(d)
            out.append(d)
    return out, warnings
