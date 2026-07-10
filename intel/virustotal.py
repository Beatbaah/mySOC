"""
intel/virustotal.py — VirusTotal API v3 integration
"""

import hashlib
import requests

import config
from db import database as db
from utils.logger import get_logger

log = get_logger(__name__)


def _headers() -> dict:
    return {"x-apikey": config.VIRUSTOTAL_API_KEY}


def check_ip(ip: str, force_refresh: bool = False) -> dict:
    cached = db.get_threat_intel_cache(ip)
    if not force_refresh and cached and cached.get("source") == "virustotal":
        return cached

    if not config.VIRUSTOTAL_API_KEY:
        return {"error": "VirusTotal API key not configured"}

    try:
        url = f"{config.VIRUSTOTAL_BASE_URL}/ip_addresses/{ip}"
        resp = requests.get(url, headers=_headers(), timeout=10)
        resp.raise_for_status()
        attrs = resp.json().get("data", {}).get("attributes", {})

        last_analysis = attrs.get("last_analysis_stats", {})
        result = {
            "source":        "virustotal",
            "malicious":     last_analysis.get("malicious", 0),
            "suspicious":    last_analysis.get("suspicious", 0),
            "harmless":      last_analysis.get("harmless", 0),
            "undetected":    last_analysis.get("undetected", 0),
            "country":       attrs.get("country", ""),
            "asn":           attrs.get("asn", 0),
            "as_owner":      attrs.get("as_owner", ""),
            "reputation":    attrs.get("reputation", 0),
            "network":       attrs.get("network", ""),
        }
        db.set_threat_intel_cache(ip, result, "virustotal")
        return result

    except Exception as e:
        log.error("VirusTotal IP lookup failed for %s: %s", ip, e)
        return {"error": str(e)}


def check_hash(file_hash: str) -> dict:
    if not config.VIRUSTOTAL_API_KEY:
        return {"error": "VirusTotal API key not configured"}
    try:
        url = f"{config.VIRUSTOTAL_BASE_URL}/files/{file_hash}"
        resp = requests.get(url, headers=_headers(), timeout=10)
        resp.raise_for_status()
        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "source":     "virustotal",
            "name":       attrs.get("meaningful_name", ""),
            "malicious":  stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless":   stats.get("harmless", 0),
            "type":       attrs.get("type_description", ""),
            "size":       attrs.get("size", 0),
        }
    except Exception as e:
        log.error("VirusTotal hash lookup failed: %s", e)
        return {"error": str(e)}
