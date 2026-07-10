"""
intel/abuseipdb.py — AbuseIPDB threat intelligence integration
"""

import time
import requests

import config
from db import database as db
from utils.logger import get_logger

log = get_logger(__name__)


def check_ip(ip: str, force_refresh: bool = False) -> dict:
    """
    Query AbuseIPDB for IP reputation.
    Returns dict with keys: abuseConfidenceScore, totalReports, countryCode,
    isp, domain, usageType, isWhitelisted, lastReportedAt
    """
    if not force_refresh:
        cached = db.get_threat_intel_cache(ip)
        if cached and cached.get("source") == "abuseipdb":
            return cached

    if not config.ABUSEIPDB_API_KEY:
        return {"error": "AbuseIPDB API key not configured"}

    try:
        resp = requests.get(
            f"{config.ABUSEIPDB_BASE_URL}/check",
            headers={"Key": config.ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})
        result = {
            "source":               "abuseipdb",
            "abuseConfidenceScore": data.get("abuseConfidenceScore", 0),
            "totalReports":         data.get("totalReports", 0),
            "countryCode":          data.get("countryCode", "XX"),
            "isp":                  data.get("isp", ""),
            "domain":               data.get("domain", ""),
            "usageType":            data.get("usageType", ""),
            "isWhitelisted":        data.get("isWhitelisted", False),
            "lastReportedAt":       data.get("lastReportedAt", ""),
        }
        db.set_threat_intel_cache(ip, result, "abuseipdb")
        return result

    except Exception as e:
        log.error("AbuseIPDB lookup failed for %s: %s", ip, e)
        return {"error": str(e)}
