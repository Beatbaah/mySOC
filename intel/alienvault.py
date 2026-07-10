"""
intel/alienvault.py — AlienVault OTX threat intelligence integration
"""

import requests

import config
from db import database as db
from utils.logger import get_logger

log = get_logger(__name__)


def check_ip(ip: str, force_refresh: bool = False) -> dict:
    cached = db.get_threat_intel_cache(ip)
    if not force_refresh and cached and cached.get("source") == "alienvault":
        return cached

    if not config.ALIENVAULT_API_KEY:
        return {"error": "AlienVault OTX API key not configured"}

    try:
        headers = {"X-OTX-API-KEY": config.ALIENVAULT_API_KEY}
        url = f"{config.ALIENVAULT_BASE_URL}/indicators/IPv4/{ip}/general"
        resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        data = resp.json()

        result = {
            "source":         "alienvault",
            "pulse_count":    data.get("pulse_info", {}).get("count", 0),
            "reputation":     data.get("reputation", 0),
            "country":        data.get("country_name", ""),
            "asn":            data.get("asn", ""),
            "malware_count":  len(data.get("malware", {}).get("data", [])),
            "sections":       data.get("sections", []),
        }
        db.set_threat_intel_cache(ip, result, "alienvault")
        return result

    except Exception as e:
        log.error("AlienVault lookup failed for %s: %s", ip, e)
        return {"error": str(e)}


def check_domain(domain: str) -> dict:
    if not config.ALIENVAULT_API_KEY:
        return {"error": "AlienVault OTX API key not configured"}

    try:
        headers = {"X-OTX-API-KEY": config.ALIENVAULT_API_KEY}
        url = f"{config.ALIENVAULT_BASE_URL}/indicators/domain/{domain}/general"
        resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        return {
            "source":       "alienvault",
            "pulse_count":  data.get("pulse_info", {}).get("count", 0),
            "alexa":        data.get("alexa", ""),
            "whois":        data.get("whois", ""),
        }
    except Exception as e:
        log.error("AlienVault domain lookup failed for %s: %s", domain, e)
        return {"error": str(e)}
