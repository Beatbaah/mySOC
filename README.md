# mySOC

A network security monitoring and incident response console. A sensor turns traffic and device logs into
flows, runs detections mapped to MITRE ATT&CK, and folds what it finds into a deduplicated, risk-scored alert
queue. Analysts triage alerts, group them into cases, hunt, and hand over between shifts.

```
 traffic ─┐                                  ┌─────────────── analyst console (React) ───────────────┐
          ├─► sensor ─► flows ─► detections ─┤  overview · alert queue · cases · entity pages · hunt  │
 syslog ──┘    (own process)     + ML + IOCs │  threat intel · logs · assets · reports · handover     │
                    │                        └───────────────────────▲────────────────────────────────┘
                    ▼                                                │ same-origin /api (nginx)
               PostgreSQL ◄──────────────────────── API (FastAPI) ───┘
```

## Run it

**Docker (recommended).** You need Docker with Compose v2.

```bash
cp .env.example .env          # set POSTGRES_PASSWORD and MYSOC_VAULT_KEY (commands are in the file)
docker compose up -d --build
docker compose logs api | grep -A3 "First admin"   # one-time admin password
```

Open http://localhost:8080. You'll be asked to choose a new password and set up an authenticator app.

The default sensor source is **demo**: a 60-host office network with normal traffic, plus an intrusion
replayed every ~40 minutes (internet scanning → RDP and SSH brute force → a workstation beaconing to a command
server → DNS tunnelling → lateral movement → data upload). The first start also generates the previous 24
hours, so there's history to explore. All "internet" addresses are from the ranges reserved for documentation
(RFC 5737), so the demo never points at a real organisation.

**Without Docker** (Python 3.12+, Node 20+):

```bash
cd backend
python3.12 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
cp .env.example .env                       # optional; defaults use SQLite
.venv/bin/uvicorn mysoc.main:app --port 8000      # terminal 1
.venv/bin/python -m mysoc.sensor                  # terminal 2

cd ../frontend && npm ci && npm run dev           # terminal 3 → http://localhost:5173
```

**Live traffic.** Set `MYSOC_SENSOR_SOURCE=capture` and use the capture override, which puts the sensor on the
host network with only the `NET_RAW`/`NET_ADMIN` capabilities:

```bash
docker compose -f docker-compose.yml -f docker-compose.capture.yml up -d
```

Point firewalls and servers at UDP 514 on the host and set `MYSOC_SYSLOG_ENABLED=true` to ingest their logs.
Add a MaxMind GeoLite2-City database (`MYSOC_GEOIP_DB_PATH`) for countries on live traffic.

## What it does

| Area | Details |
|---|---|
| **Detection** | 11 network rules (port scan, SYN/ICMP flood, brute force, DNS tunnelling, large uploads, attack-tool ports, internet-exposed remote access, beaconing, IOC matches, lateral movement), a log rule for failed-login bursts, an Isolation Forest anomaly model, and analyst-written match rules. Each maps to an ATT&CK technique; thresholds are tunable from the console and apply live. |
| **Alert quality** | Repeats fold into one alert with a count. Risk score (0–100) combines severity, repetition, target criticality and IOC hits. Context changes severity: a scan from inside the network is high, from the internet medium. Probes don't count as connections. |
| **Triage** | Queue views (open, new, mine, closed), severity filters, bulk take/close, closing requires a disposition (true positive / benign / false positive), feeding false-positive rates per rule. |
| **Cases** | Group alerts into investigations with owner, status workflow, severity that follows the worst alert, and a timeline of notes and changes. |
| **Investigation** | Entity page per IP: traffic over time, peers, services, alerts, log mentions, asset details, reputation. Seven parameterised hunts (beaconing, rare destinations, large uploads, unusual ports, DNS outliers, internal fan-out, new countries). |
| **Threat intel** | IOC list (IP, domain, URL, hash) with CSV/plain import; AbuseIPDB, AlienVault OTX and VirusTotal lookups with caching. |
| **Operations** | Shift handover with automatic queue snapshot, period reports (MTTC, dispositions, noisy rules, tactics), CSV export, live updates over server-sent events, email/Telegram notifications for high and critical alerts. |

## Security

See [SECURITY.md](SECURITY.md) for the full design. In short: no default passwords; Argon2id hashing; mandatory
TOTP for admins with replay protection; server-side sessions in HttpOnly SameSite=Strict cookies with idle and
absolute timeouts; CSRF tokens on every change; per-IP and per-account login throttling that never reveals
whether an account exists; role-based access (viewer / analyst / admin); encrypted secrets; a full audit log;
strict CSP and hardened, non-root containers. Production mode refuses to start with unsafe settings.

## Development

```bash
cd backend && .venv/bin/pytest && .venv/bin/ruff check mysoc
cd frontend && npx tsc -b && npx eslint src && npm run build
```

Architecture notes are in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). API docs are served at `/api/docs` in
development.

## License

MIT
