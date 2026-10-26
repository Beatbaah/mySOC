"""Input validation shared by routes."""

import re
from ipaddress import ip_address

from fastapi import HTTPException

_DOMAIN = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$")
_HASH = re.compile(r"^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$")
_URL = re.compile(r"^https?://[^\s/$.?#].[^\s]{0,2000}$", re.I)


def ip_or_400(value: str) -> str:
    try:
        return str(ip_address(value.strip()))
    except ValueError:
        raise HTTPException(400, f"“{value[:60]}” isn't a valid IP address.") from None


def indicator_kind(value: str) -> tuple[str, str] | None:
    """(kind, normalised value) for an IP, domain, file hash or URL; None if
    it's none of those."""
    v = value.strip()
    try:
        return "ip", str(ip_address(v))
    except ValueError:
        pass
    low = v.lower().rstrip(".")
    if _HASH.match(low):
        return "hash", low
    if _URL.match(v):
        return "url", v
    if _DOMAIN.match(low):
        return "domain", low
    return None
