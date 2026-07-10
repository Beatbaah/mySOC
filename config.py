"""
config.py — Centralized configuration & thresholds for MY SOC
"""

import os
from dotenv import load_dotenv

load_dotenv()

# ─── Application ──────────────────────────────────────────────────────────────
APP_NAME        = "MY SOC"
APP_VERSION     = "1.0.0"
APP_DESCRIPTION = "Security Operations Center Dashboard"

# ─── Database ─────────────────────────────────────────────────────────────────
DB_PATH         = os.getenv("DB_PATH", "soc_data.db")
DB_WAL_MODE     = True

# ─── Authentication ────────────────────────────────────────────────────────────
SESSION_TIMEOUT_MINUTES = 60
MAX_LOGIN_ATTEMPTS      = 5
LOCKOUT_MINUTES         = 15
BCRYPT_ROUNDS           = 12

# Default admin credentials (change immediately after first login)
DEFAULT_ADMIN_USER     = "admin"
DEFAULT_ADMIN_PASSWORD = "Admin@SOC2024!"  # Change in production

ROLES = {
    "admin":    {"level": 3, "label": "Administrator"},
    "analyst":  {"level": 2, "label": "SOC Analyst"},
    "viewer":   {"level": 1, "label": "Read-Only Viewer"},
}

# ─── Network Detection ─────────────────────────────────────────────────────────
DETECTION_THRESHOLDS = {
    "port_scan_threshold":      20,    # unique ports in 10s → port scan
    "brute_force_threshold":    10,    # auth failures in 60s → brute force
    "ddos_pps_threshold":       1000,  # packets/sec → DDoS suspected
    "data_exfil_bytes":         10_000_000,  # 10 MB outbound → exfil alert
    "dns_query_threshold":      50,    # DNS queries in 5s → DNS tunnel suspected
    "icmp_flood_threshold":     100,   # ICMP packets in 10s → flood
    "syn_flood_threshold":      500,   # SYN packets in 5s → SYN flood
    "new_connection_threshold": 100,   # new conns/min per IP
}

SEVERITY_LEVELS = {
    "CRITICAL": {"color": "#ff2d55", "priority": 4, "auto_alert": True},
    "HIGH":     {"color": "#ff6b35", "priority": 3, "auto_alert": True},
    "MEDIUM":   {"color": "#ffd60a", "priority": 2, "auto_alert": False},
    "LOW":      {"color": "#30d158", "priority": 1, "auto_alert": False},
    "INFO":     {"color": "#0a84ff", "priority": 0, "auto_alert": False},
}

# ─── Packet Capture ────────────────────────────────────────────────────────────
CAPTURE_INTERFACE   = os.getenv("CAPTURE_INTERFACE", None)  # None = auto
CAPTURE_FILTER      = "ip"
CAPTURE_BUFFER_SIZE = 1000   # max packets in memory ring buffer
CAPTURE_TIMEOUT_MS  = 100

# ─── Syslog ────────────────────────────────────────────────────────────────────
SYSLOG_HOST = os.getenv("SYSLOG_HOST", "0.0.0.0")
SYSLOG_PORT = int(os.getenv("SYSLOG_PORT", 514))
SYSLOG_BUFFER = 4096

# ─── Machine Learning ──────────────────────────────────────────────────────────
ML_CONTAMINATION      = 0.05   # expected anomaly fraction
ML_N_ESTIMATORS       = 100
ML_RANDOM_STATE       = 42
ML_RETRAIN_INTERVAL_S = 3600   # retrain every hour
ML_MIN_SAMPLES        = 50     # minimum samples before training

# ─── Threat Intelligence APIs ──────────────────────────────────────────────────
ABUSEIPDB_API_KEY   = os.getenv("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_BASE_URL  = "https://api.abuseipdb.com/api/v2"
ABUSEIPDB_CACHE_TTL = 3600   # seconds

ALIENVAULT_API_KEY  = os.getenv("ALIENVAULT_API_KEY", "")
ALIENVAULT_BASE_URL = "https://otx.alienvault.com/api/v1"
ALIENVAULT_CACHE_TTL = 3600

VIRUSTOTAL_API_KEY  = os.getenv("VIRUSTOTAL_API_KEY", "")
VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"
VIRUSTOTAL_CACHE_TTL = 3600

# ─── Alert Notifications ───────────────────────────────────────────────────────
SMTP_HOST     = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT     = int(os.getenv("SMTP_PORT", 587))
SMTP_USER     = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM     = os.getenv("SMTP_FROM", "soc-alerts@example.com")
ALERT_EMAIL_TO = os.getenv("ALERT_EMAIL_TO", "").split(",")

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_IDS  = os.getenv("TELEGRAM_CHAT_IDS", "").split(",")

# ─── GeoIP ─────────────────────────────────────────────────────────────────────
GEOIP_DB_PATH = os.getenv("GEOIP_DB_PATH", "GeoLite2-City.mmdb")

# ─── Logging ───────────────────────────────────────────────────────────────────
LOG_DIR         = "logs"
LOG_FILE        = "mysoc.log"
LOG_MAX_BYTES   = 10 * 1024 * 1024   # 10 MB
LOG_BACKUP_COUNT = 5
LOG_LEVEL       = os.getenv("LOG_LEVEL", "INFO")

# ─── Dashboard Refresh ─────────────────────────────────────────────────────────
DASHBOARD_REFRESH_INTERVAL = 5   # seconds
CHART_MAX_POINTS = 200
TOP_TALKERS_LIMIT = 20

# ─── Whitelisted IPs (never alert on these) ────────────────────────────────────
WHITELIST_IPS = set(os.getenv("WHITELIST_IPS", "127.0.0.1,::1").split(","))
INTERNAL_SUBNETS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
