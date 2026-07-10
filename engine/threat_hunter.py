"""
engine/threat_hunter.py — Proactive threat hunting.

Capabilities:
  1. IOC matching  — check IPs/ports against a local IOC list
  2. Beaconing detection — find hosts making regular-interval connections (C2 indicator)
  3. Hunt queries — canned SQL-based hunts run against the traffic/alert DB
  4. IOC feed import — load IOCs from CSV or plain text
"""

import csv
import io
import math
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from db import database as db
from utils.logger import get_logger

log = get_logger(__name__)

IOC_FILE = Path("ioc_list.csv")


# ══════════════════════════════════════════════════════════════════════════════
# IOC Management
# ══════════════════════════════════════════════════════════════════════════════

def load_iocs() -> List[Dict]:
    """Load IOCs from the DB table."""
    rows = db.fetchall("SELECT * FROM ioc_list ORDER BY added_at DESC")
    return [dict(r) for r in rows]


def add_ioc(
    ioc_type: str,  # ip, domain, hash, url
    value: str,
    threat_type: str = "",
    source: str = "manual",
    confidence: int = 80,
) -> int:
    return db.insert("ioc_list", {
        "ioc_type":    ioc_type.lower(),
        "value":       value.strip(),
        "threat_type": threat_type,
        "source":      source,
        "confidence":  confidence,
    })


def delete_ioc(ioc_id: int) -> None:
    db.execute("DELETE FROM ioc_list WHERE id=?", (ioc_id,))


def import_iocs_csv(content: str, source: str = "import") -> Tuple[int, int]:
    """
    Import IOCs from CSV text.  Expected columns: type,value,threat_type,confidence
    Returns (added, skipped).
    """
    added = skipped = 0
    reader = csv.DictReader(io.StringIO(content))
    for row in reader:
        try:
            ioc_type = (row.get("type") or row.get("ioc_type") or "ip").strip().lower()
            value    = (row.get("value") or "").strip()
            if not value:
                skipped += 1
                continue
            add_ioc(
                ioc_type=ioc_type,
                value=value,
                threat_type=(row.get("threat_type") or "").strip(),
                source=source,
                confidence=int(row.get("confidence", 80)),
            )
            added += 1
        except Exception as e:
            log.debug("IOC import skip: %s", e)
            skipped += 1
    log.info("IOC import: %d added, %d skipped", added, skipped)
    return added, skipped


def import_iocs_plaintext(content: str, ioc_type: str = "ip",
                           source: str = "import") -> Tuple[int, int]:
    """One IOC per line (comments with # ignored)."""
    added = skipped = 0
    for line in content.splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        try:
            add_ioc(ioc_type=ioc_type, value=value, source=source)
            added += 1
        except Exception:
            skipped += 1
    return added, skipped


def check_ip_ioc(ip: str) -> Optional[Dict]:
    """Return IOC record if the IP is in the IOC list, else None."""
    row = db.fetchone(
        "SELECT * FROM ioc_list WHERE ioc_type='ip' AND value=?", (ip,)
    )
    return dict(row) if row else None


def check_ioc_hits_in_alerts(limit: int = 50) -> List[Dict]:
    """
    Cross-reference recent alert source IPs against the IOC list.
    Returns matches.
    """
    results = []
    alert_ips = db.fetchall(
        "SELECT DISTINCT src_ip FROM alerts WHERE src_ip != '' LIMIT 500"
    )
    ioc_ips = {
        r["value"] for r in db.fetchall("SELECT value FROM ioc_list WHERE ioc_type='ip'")
    }
    for row in alert_ips:
        ip = row["src_ip"]
        if ip in ioc_ips:
            ioc = db.fetchone(
                "SELECT * FROM ioc_list WHERE ioc_type='ip' AND value=?", (ip,)
            )
            alert_count = db.fetchone(
                "SELECT COUNT(*) as cnt FROM alerts WHERE src_ip=?", (ip,)
            )
            results.append({
                "ip":           ip,
                "ioc":          dict(ioc) if ioc else {},
                "alert_count":  alert_count["cnt"] if alert_count else 0,
            })
            if len(results) >= limit:
                break
    return results


# ══════════════════════════════════════════════════════════════════════════════
# Beaconing Detection
# ══════════════════════════════════════════════════════════════════════════════

def detect_beaconing(
    min_connections: int = 10,
    max_jitter_pct:  float = 0.15,
    hours_back:      int   = 6,
) -> List[Dict]:
    """
    Identify hosts making suspiciously regular outbound connections.
    C2 beaconing = nearly uniform inter-packet intervals.

    Returns list of dicts: {src_ip, dst_ip, dst_port, interval_avg, jitter_pct, count}
    """
    # Get connection timestamps grouped by (src, dst, port)
    rows = db.fetchall(
        """SELECT src_ip, dst_ip, dst_port, timestamp
           FROM traffic
           WHERE timestamp >= datetime('now', ?)
             AND dst_port NOT IN (80, 443, 53)
           ORDER BY src_ip, dst_ip, dst_port, timestamp""",
        (f"-{hours_back} hours",),
    )

    # Group by (src, dst, port)
    groups: Dict[tuple, List[float]] = {}
    for row in rows:
        key = (row["src_ip"], row["dst_ip"], row["dst_port"])
        try:
            from datetime import datetime as _dt
            dt = _dt.fromisoformat(row["timestamp"].replace("Z", "+00:00"))
            groups.setdefault(key, []).append(dt.timestamp())
        except Exception:
            pass

    beacons = []
    for (src, dst, port), timestamps in groups.items():
        if len(timestamps) < min_connections:
            continue
        timestamps.sort()
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        if len(intervals) < 2:
            continue
        avg    = statistics.mean(intervals)
        stdev  = statistics.stdev(intervals)
        jitter = stdev / avg if avg > 0 else 1.0

        if jitter <= max_jitter_pct and avg > 5:   # min 5s interval, max 15% jitter
            beacons.append({
                "src_ip":       src,
                "dst_ip":       dst,
                "dst_port":     port,
                "interval_avg": round(avg, 1),
                "interval_std": round(stdev, 2),
                "jitter_pct":   round(jitter * 100, 1),
                "count":        len(timestamps),
                "confidence":   round((1 - jitter) * 100, 1),
            })

    beacons.sort(key=lambda x: x["confidence"], reverse=True)
    return beacons


# ══════════════════════════════════════════════════════════════════════════════
# Canned Hunt Queries
# ══════════════════════════════════════════════════════════════════════════════

HUNT_QUERIES = {
    "long_connections": {
        "label": "🕒 Long-running Connections",
        "description": "Src/dst pairs with sustained traffic over 1h (possible data staging)",
        "sql": """
            SELECT src_ip, dst_ip, dst_port, protocol,
                   COUNT(*) as packets,
                   SUM(length) as total_bytes,
                   MIN(timestamp) as first_seen,
                   MAX(timestamp) as last_seen,
                   ROUND((julianday(MAX(timestamp)) - julianday(MIN(timestamp))) * 24, 2) as duration_hours
            FROM traffic
            WHERE timestamp >= datetime('now', '-24 hours')
            GROUP BY src_ip, dst_ip, dst_port, protocol
            HAVING duration_hours > 1
            ORDER BY total_bytes DESC
            LIMIT 20
        """,
    },
    "new_external_dsts": {
        "label": "🆕 New External Destinations",
        "description": "External IPs seen for the first time in the last hour",
        "sql": """
            SELECT dst_ip, COUNT(*) as packets, GROUP_CONCAT(DISTINCT dst_port) as ports
            FROM traffic
            WHERE timestamp >= datetime('now', '-1 hour')
              AND dst_ip NOT LIKE '10.%'
              AND dst_ip NOT LIKE '192.168.%'
              AND dst_ip NOT LIKE '172.1%.%'
              AND dst_ip NOT LIKE '172.2%.%'
              AND dst_ip NOT LIKE '172.3%.%'
              AND dst_ip NOT LIKE '127.%'
            GROUP BY dst_ip
            ORDER BY packets DESC
            LIMIT 30
        """,
    },
    "high_port_hosts": {
        "label": "🔌 Hosts Using Many Ports",
        "description": "Internal hosts connecting to >20 unique ports (recon indicator)",
        "sql": """
            SELECT src_ip,
                   COUNT(DISTINCT dst_port) as unique_ports,
                   COUNT(DISTINCT dst_ip)   as unique_dsts,
                   COUNT(*) as packets
            FROM traffic
            WHERE timestamp >= datetime('now', '-1 hour')
              AND (src_ip LIKE '10.%' OR src_ip LIKE '192.168.%' OR src_ip LIKE '172.%')
            GROUP BY src_ip
            HAVING unique_ports > 20
            ORDER BY unique_ports DESC
            LIMIT 20
        """,
    },
    "repeated_failures": {
        "label": "🔐 Repeated Alert Sources",
        "description": "IPs generating alerts across multiple attack types (APT indicator)",
        "sql": """
            SELECT src_ip,
                   COUNT(DISTINCT alert_type) as attack_types,
                   COUNT(*) as total_alerts,
                   MAX(severity) as max_severity,
                   GROUP_CONCAT(DISTINCT alert_type) as types
            FROM alerts
            WHERE timestamp >= datetime('now', '-24 hours')
              AND src_ip != ''
            GROUP BY src_ip
            HAVING attack_types >= 2
            ORDER BY attack_types DESC, total_alerts DESC
            LIMIT 20
        """,
    },
    "off_hours_traffic": {
        "label": "🌙 Off-Hours Traffic",
        "description": "Significant traffic between 22:00–06:00 (possible exfil during low-watch periods)",
        "sql": """
            SELECT src_ip, dst_ip, dst_port,
                   COUNT(*) as packets, SUM(length) as bytes,
                   GROUP_CONCAT(DISTINCT strftime('%H', timestamp)) as hours
            FROM traffic
            WHERE strftime('%H', timestamp) >= '22' OR strftime('%H', timestamp) < '06'
              AND timestamp >= datetime('now', '-24 hours')
            GROUP BY src_ip, dst_ip, dst_port
            HAVING packets > 50
            ORDER BY bytes DESC
            LIMIT 20
        """,
    },
    "dns_heavy_hosts": {
        "label": "🔍 DNS-Heavy Hosts",
        "description": "Hosts making excessive DNS queries (DNS tunnel / DGA indicator)",
        "sql": """
            SELECT src_ip,
                   COUNT(*) as dns_queries,
                   COUNT(DISTINCT dst_ip) as unique_resolvers
            FROM traffic
            WHERE dst_port = 53
              AND timestamp >= datetime('now', '-1 hour')
            GROUP BY src_ip
            HAVING dns_queries > 30
            ORDER BY dns_queries DESC
            LIMIT 20
        """,
    },
    "unack_critical": {
        "label": "🚨 Unacknowledged Critical Alerts",
        "description": "CRITICAL alerts older than 15 minutes that haven't been acknowledged",
        "sql": """
            SELECT id, timestamp, alert_type, src_ip, dst_ip, description,
                   ROUND((julianday('now') - julianday(timestamp)) * 24 * 60, 1) as age_minutes
            FROM alerts
            WHERE severity = 'CRITICAL'
              AND acknowledged = 0
            ORDER BY timestamp ASC
            LIMIT 50
        """,
    },
}


def run_hunt(query_key: str) -> Tuple[List[Dict], str]:
    """Run a canned hunt query. Returns (rows, error)."""
    q = HUNT_QUERIES.get(query_key)
    if not q:
        return [], f"Unknown hunt: {query_key}"
    try:
        rows = db.fetchall(q["sql"])
        return [dict(r) for r in rows], ""
    except Exception as e:
        return [], str(e)


def run_custom_hunt(sql: str) -> Tuple[List[Dict], str]:
    """Run analyst-supplied SQL against the DB (read-only SELECT only)."""
    stripped = sql.strip().upper()
    if not stripped.startswith("SELECT"):
        return [], "Only SELECT queries are allowed."
    forbidden = ["DROP", "DELETE", "INSERT", "UPDATE", "ALTER", "CREATE"]
    for kw in forbidden:
        if kw in stripped:
            return [], f"Forbidden keyword: {kw}"
    try:
        rows = db.fetchall(sql)
        return [dict(r) for r in rows], ""
    except Exception as e:
        return [], str(e)
