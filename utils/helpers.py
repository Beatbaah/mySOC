"""
utils/helpers.py — IP validation, geolocation, formatting helpers
"""

import ipaddress
import re
import socket
import struct
from datetime import datetime, timezone
from typing import Optional, Tuple
import requests

import config
from utils.logger import get_logger

log = get_logger(__name__)

# ─── IP Utilities ──────────────────────────────────────────────────────────────

def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def is_whitelisted(ip: str) -> bool:
    return ip in config.WHITELIST_IPS


def ip_in_subnet(ip: str, subnet: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return False


def is_internal(ip: str) -> bool:
    return any(ip_in_subnet(ip, s) for s in config.INTERNAL_SUBNETS)


def reverse_dns(ip: str, timeout: float = 1.0) -> str:
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ip


# ─── GeoIP ─────────────────────────────────────────────────────────────────────

_geo_reader = None

def _get_geo_reader():
    global _geo_reader
    if _geo_reader is None:
        try:
            import geoip2.database
            _geo_reader = geoip2.database.Reader(config.GEOIP_DB_PATH)
        except Exception as e:
            log.warning(f"GeoIP DB not available: {e}")
    return _geo_reader


def geolocate(ip: str) -> dict:
    """
    Return dict with keys: country, country_code, city, lat, lon
    Falls back to empty strings / 0.0 on failure.
    """
    result = {
        "country": "Unknown",
        "country_code": "XX",
        "city": "Unknown",
        "lat": 0.0,
        "lon": 0.0,
    }
    if is_private_ip(ip):
        result["country"] = "Internal"
        result["country_code"] = "INT"
        return result

    reader = _get_geo_reader()
    if reader:
        try:
            resp = reader.city(ip)
            result["country"]      = resp.country.name or "Unknown"
            result["country_code"] = resp.country.iso_code or "XX"
            result["city"]         = resp.city.name or "Unknown"
            result["lat"]          = float(resp.location.latitude or 0.0)
            result["lon"]          = float(resp.location.longitude or 0.0)
        except Exception:
            pass

    return result


# ─── Formatting ────────────────────────────────────────────────────────────────

def bytes_to_human(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024.0:
            return f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} PB"


def ts_now_utc() -> datetime:
    return datetime.now(timezone.utc)


def format_ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def severity_badge(severity: str) -> str:
    colors = {
        "CRITICAL": "#ff2d55",
        "HIGH":     "#ff6b35",
        "MEDIUM":   "#ffd60a",
        "LOW":      "#30d158",
        "INFO":     "#0a84ff",
    }
    color = colors.get(severity.upper(), "#999")
    return f'<span style="background:{color};color:#000;padding:2px 8px;border-radius:4px;font-weight:bold;font-size:0.75rem">{severity}</span>'


def truncate(s: str, n: int = 60) -> str:
    return s if len(s) <= n else s[: n - 3] + "..."


def parse_log_level(syslog_severity: int) -> str:
    """Map syslog severity integer to SOC severity label."""
    mapping = {0: "CRITICAL", 1: "CRITICAL", 2: "CRITICAL",
               3: "HIGH", 4: "MEDIUM", 5: "LOW", 6: "INFO", 7: "INFO"}
    return mapping.get(syslog_severity % 8, "INFO")


# ─── Protocol helpers ──────────────────────────────────────────────────────────

PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE",
               50: "ESP", 51: "AH", 89: "OSPF", 132: "SCTP"}

def proto_name(proto_num: int) -> str:
    return PROTO_NAMES.get(proto_num, str(proto_num))


def port_service(port: int) -> str:
    WELL_KNOWN = {
        20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET",
        25: "SMTP", 53: "DNS", 67: "DHCP", 80: "HTTP",
        110: "POP3", 123: "NTP", 143: "IMAP", 161: "SNMP",
        389: "LDAP", 443: "HTTPS", 445: "SMB", 514: "SYSLOG",
        993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "ORACLE",
        3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
        6379: "REDIS", 8080: "HTTP-ALT", 8443: "HTTPS-ALT", 9200: "ELASTICSEARCH",
    }
    return WELL_KNOWN.get(port, str(port))
