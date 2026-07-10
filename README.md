# 🛡️ MY SOC — Security Operations Center Dashboard

A full-featured, production-ready Security Operations Center built with Python + Streamlit.

---

## 🗂️ Architecture

```
mysoc/
├── soc_dashboard.py          # Main entry point & UI orchestrator
├── config.py                 # Centralized configuration & thresholds
├── requirements.txt          # Python dependencies
├── .env.example              # Environment variable template
├── .streamlit/config.toml    # Streamlit server config
│
├── auth/authenticator.py     # Bcrypt login, lockout, RBAC
├── db/database.py            # Thread-safe SQLite, parameterized queries
│
├── engine/
│   ├── sniffer.py            # Live packet capture (Scapy) + Demo mode
│   ├── detection.py          # Rule-based detection engine
│   ├── ml_anomaly.py         # Isolation Forest anomaly detection
│   └── syslog_listener.py    # UDP syslog receiver
│
├── alerts/
│   ├── alert_manager.py      # Central async alert dispatcher
│   ├── email_alert.py        # SMTP email alerts
│   └── telegram_alert.py     # Telegram bot alerts
│
├── intel/
│   ├── abuseipdb.py          # AbuseIPDB API (with DB caching)
│   ├── alienvault.py         # AlienVault OTX API
│   └── virustotal.py         # VirusTotal API v3
│
├── utils/
│   ├── helpers.py            # IP validation, geolocation, formatting
│   └── logger.py             # Rotating file + colored console logger
│
└── views/
    ├── threat_overview.py    # KPIs, alert timeline, severity distribution
    ├── live_traffic.py       # Real-time packet monitor
    ├── geo_map.py            # Plotly scatter-geo attack map
    ├── analytics.py          # Trends, heatmaps, correlation matrix
    ├── threat_intel.py       # IP/hash lookup (AbuseIPDB+OTX+VT)
    ├── endpoint_monitor.py   # Per-host activity and alerts
    ├── incidents.py          # Incident CRUD with RBAC
    ├── log_management.py     # Syslog viewer, log search, audit trail
    └── reports.py            # Summary, weekly digest, executive report
```

---

## 🚀 Quick Start

### 1. Install dependencies

```bash
cd mysoc
pip install -r requirements.txt
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env with your API keys and SMTP/Telegram credentials
```

### 3. Run

```bash
streamlit run soc_dashboard.py
```

Open **http://localhost:8501** in your browser.

**Default credentials:** `admin` / `Admin@SOC2024!`  
⚠️ Change the password immediately after first login.

---

## 🔑 Features

| Feature | Detail |
|---|---|
| **Authentication** | Bcrypt password hashing, account lockout, session timeout |
| **RBAC** | Admin / Analyst / Viewer roles |
| **Live Capture** | Scapy-based packet capture with ring buffer + demo mode |
| **Detection Rules** | Port scan, SYN flood, brute force, DNS tunnel, data exfil, suspicious ports, external RDP |
| **ML Anomaly** | Isolation Forest on packet feature vectors, auto-retraining |
| **Syslog** | RFC 3164 UDP receiver for firewalls / routers |
| **Threat Intel** | AbuseIPDB, AlienVault OTX, VirusTotal with TTL caching |
| **Geo Map** | Plotly scatter-geo with attack origin clustering |
| **Alerts** | Email (SMTP) + Telegram bot notifications for CRITICAL/HIGH |
| **Incidents** | Full lifecycle: create → assign → update → resolve |
| **Reports** | Date-range summary, weekly digest, executive risk score |
| **Audit Trail** | All user actions logged to `audit_log` table |

---

## ⚙️ Detection Thresholds (config.py)

| Rule | Default |
|---|---|
| Port scan | 20 unique ports in 10s |
| SYN flood | 500 SYN packets in 5s |
| ICMP flood | 100 ICMP packets in 10s |
| Brute force | 10 auth attempts in 60s |
| DNS tunnel | 50 DNS queries in 5s |
| Data exfil | 10 MB outbound in 60s |

All thresholds are tunable in `config.py` or via `DETECTION_THRESHOLDS`.

---

## 🔐 Live Packet Capture

Packet capture requires elevated privileges:

```bash
# Linux
sudo streamlit run soc_dashboard.py

# Or grant capabilities to Python
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
streamlit run soc_dashboard.py
```

If Scapy is unavailable or capture fails, the **DemoSniffer** activates automatically, generating synthetic traffic for dashboard demonstration.

---

## 📡 Syslog Configuration

Point your firewall/router syslog to:
```
UDP  <SOC_HOST_IP>:514
```

Example (Cisco IOS):
```
logging host <SOC_HOST_IP>
logging trap informational
```

---

## 🗃️ Database

SQLite WAL-mode database (`soc_data.db`) with tables:
- `users`, `alerts`, `traffic`, `incidents`
- `syslog_events`, `threat_intel_cache`, `audit_log`

For production, consider migrating to PostgreSQL by replacing `db/database.py`.

---

## 📝 License

MIT — use freely, contribute back.
