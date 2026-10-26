"""Reputation lookups: AbuseIPDB, AlienVault OTX and VirusTotal.

Only indicators that passed validation reach these functions, and they're
placed in URLs with percent-encoding, never by string concatenation, so a
crafted value can't redirect the request. Results are cached for an hour
in the database to respect the providers' free-tier rate limits. API keys
come from the encrypted secrets table.
"""

from datetime import timedelta
from urllib.parse import quote

import httpx
from sqlalchemy.orm import Session

from ..db import utcnow
from ..models import IntelCache, Secret
from ..security import vault

CACHE_FOR = timedelta(hours=1)
TIMEOUT = httpx.Timeout(10.0)

PROVIDERS = {
    "abuseipdb": {"name": "AbuseIPDB", "secret": "abuseipdb_api_key", "kinds": {"ip"}},
    "otx": {"name": "AlienVault OTX", "secret": "otx_api_key", "kinds": {"ip", "domain", "hash", "url"}},
    "virustotal": {"name": "VirusTotal", "secret": "virustotal_api_key", "kinds": {"ip", "domain", "hash", "url"}},
}


def _key(s: Session, name: str) -> str:
    row = s.get(Secret, name)
    return vault.decrypt(row.value) if row else ""


def _abuseipdb(client: httpx.Client, key: str, kind: str, value: str) -> dict:
    r = client.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": key, "Accept": "application/json"},
        params={"ipAddress": value, "maxAgeInDays": 90},
    )
    r.raise_for_status()
    d = r.json().get("data", {})
    score = d.get("abuseConfidenceScore", 0)
    return {
        "verdict": "malicious" if score >= 75 else "suspicious" if score >= 25 else "clean",
        "score": score,
        "summary": f"Abuse confidence {score}% from {d.get('totalReports', 0)} reports",
        "details": {k: d.get(k) for k in ("countryCode", "isp", "domain", "usageType", "totalReports", "lastReportedAt", "isTor")},
        "link": f"https://www.abuseipdb.com/check/{quote(value, safe='')}",
    }


_OTX_SECTIONS = {"ip": "IPv4", "domain": "domain", "hash": "file", "url": "url"}


def _otx(client: httpx.Client, key: str, kind: str, value: str) -> dict:
    section = _OTX_SECTIONS[kind]
    if kind == "ip" and ":" in value:
        section = "IPv6"
    r = client.get(
        f"https://otx.alienvault.com/api/v1/indicators/{section}/{quote(value, safe='')}/general",
        headers={"X-OTX-API-KEY": key},
    )
    r.raise_for_status()
    d = r.json()
    pulses = d.get("pulse_info", {}).get("count", 0)
    names = [p.get("name", "") for p in d.get("pulse_info", {}).get("pulses", [])[:5]]
    return {
        "verdict": "malicious" if pulses >= 5 else "suspicious" if pulses else "clean",
        "score": min(100, pulses * 10),
        "summary": f"In {pulses} threat-intel pulse{'s' if pulses != 1 else ''}",
        "details": {"pulses": names},
        "link": f"https://otx.alienvault.com/indicator/{section.lower()}/{quote(value, safe='')}",
    }


def _virustotal(client: httpx.Client, key: str, kind: str, value: str) -> dict:
    import base64

    path = {
        "ip": f"ip_addresses/{quote(value, safe='')}",
        "domain": f"domains/{quote(value, safe='')}",
        "hash": f"files/{quote(value, safe='')}",
        "url": "urls/" + base64.urlsafe_b64encode(value.encode()).decode().rstrip("="),
    }[kind]
    r = client.get(f"https://www.virustotal.com/api/v3/{path}", headers={"x-apikey": key})
    if r.status_code == 404:
        return {"verdict": "unknown", "score": 0, "summary": "Not seen by VirusTotal", "details": {}, "link": ""}
    r.raise_for_status()
    stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    bad = stats.get("malicious", 0)
    total = sum(stats.values()) or 1
    return {
        "verdict": "malicious" if bad >= 3 else "suspicious" if bad else "clean",
        "score": round(100 * bad / total),
        "summary": f"{bad} of {total} security vendors flag this",
        "details": stats,
        "link": "https://www.virustotal.com/gui/search/" + quote(value, safe=""),
    }


_LOOKUPS = {"abuseipdb": _abuseipdb, "otx": _otx, "virustotal": _virustotal}


def lookup(s: Session, kind: str, value: str, refresh: bool = False) -> dict[str, dict]:
    out: dict[str, dict] = {}
    with httpx.Client(timeout=TIMEOUT, follow_redirects=False) as client:
        for pid, meta in PROVIDERS.items():
            if kind not in meta["kinds"]:
                continue
            cache_key = f"{pid}:{kind}:{value}"[:600]
            cached = s.get(IntelCache, cache_key)
            if cached and not refresh and utcnow() - cached.fetched_at < CACHE_FOR:
                out[pid] = {**cached.data, "cached": True, "fetchedAt": cached.fetched_at.isoformat()}
                continue
            key = _key(s, meta["secret"])
            if not key:
                out[pid] = {"verdict": "unconfigured", "summary": f"Add a {meta['name']} API key in Settings to use this source."}
                continue
            try:
                data = _LOOKUPS[pid](client, key, kind, value)
            except httpx.HTTPStatusError as e:
                code = e.response.status_code
                msg = "API key rejected" if code in (401, 403) else "Rate limit reached; try later" if code == 429 else f"Error {code}"
                out[pid] = {"verdict": "error", "summary": msg}
                continue
            except httpx.HTTPError:
                out[pid] = {"verdict": "error", "summary": "Couldn't reach the service"}
                continue
            data["provider"] = meta["name"]
            if cached:
                cached.data, cached.fetched_at = data, utcnow()
            else:
                s.add(IntelCache(key=cache_key, data=data))
            out[pid] = {**data, "cached": False, "fetchedAt": utcnow().isoformat()}
    return out
