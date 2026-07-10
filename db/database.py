"""
db/database.py — Thread-safe SQLite with parameterized queries for MY SOC
"""
import sys as _sys
from pathlib import Path as _Path
_PROJECT_ROOT = str(_Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in _sys.path:
    _sys.path.insert(0, _PROJECT_ROOT)


import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import config
from utils.logger import get_logger

log = get_logger(__name__)
_local = threading.local()


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(config.DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    if config.DB_WAL_MODE:
        conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


@contextmanager
def get_conn():
    if not hasattr(_local, "conn") or _local.conn is None:
        _local.conn = _connect()
    try:
        yield _local.conn
    except sqlite3.Error as e:
        _local.conn.rollback()
        log.error(f"DB error: {e}")
        raise


def init_db():
    """Create all tables if they don't exist."""
    with get_conn() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT    UNIQUE NOT NULL,
            password_hash TEXT  NOT NULL,
            role        TEXT    NOT NULL DEFAULT 'viewer',
            failed_attempts INTEGER DEFAULT 0,
            locked_until    REAL    DEFAULT 0,
            last_login      TEXT,
            created_at      TEXT    DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            severity    TEXT    NOT NULL,
            alert_type  TEXT    NOT NULL,
            src_ip      TEXT,
            dst_ip      TEXT,
            src_port    INTEGER,
            dst_port    INTEGER,
            protocol    TEXT,
            description TEXT,
            raw_data    TEXT,
            acknowledged INTEGER DEFAULT 0,
            ack_by      TEXT,
            ack_at      TEXT,
            country     TEXT,
            threat_score INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS traffic (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            src_ip      TEXT,
            dst_ip      TEXT,
            src_port    INTEGER,
            dst_port    INTEGER,
            protocol    TEXT,
            length      INTEGER,
            flags       TEXT,
            ttl         INTEGER,
            country     TEXT
        );

        CREATE TABLE IF NOT EXISTS incidents (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            title       TEXT    NOT NULL,
            description TEXT,
            severity    TEXT    NOT NULL,
            status      TEXT    NOT NULL DEFAULT 'OPEN',
            assigned_to TEXT,
            created_at  TEXT    DEFAULT (datetime('now')),
            updated_at  TEXT    DEFAULT (datetime('now')),
            resolved_at TEXT,
            alert_ids   TEXT,
            notes       TEXT
        );

        CREATE TABLE IF NOT EXISTS syslog_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            source_ip   TEXT,
            facility    INTEGER,
            severity    INTEGER,
            hostname    TEXT,
            program     TEXT,
            message     TEXT
        );

        CREATE TABLE IF NOT EXISTS threat_intel_cache (
            ip          TEXT    PRIMARY KEY,
            data        TEXT,
            source      TEXT,
            cached_at   REAL    NOT NULL
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    DEFAULT (datetime('now')),
            username    TEXT,
            action      TEXT,
            detail      TEXT,
            ip_address  TEXT
        );

        CREATE TABLE IF NOT EXISTS totp_secrets (
            username    TEXT PRIMARY KEY,
            secret      TEXT NOT NULL,
            confirmed   INTEGER DEFAULT 0,
            enrolled_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS vault (
            key         TEXT PRIMARY KEY,
            value       TEXT NOT NULL,
            updated_at  TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS ioc_list (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc_type    TEXT NOT NULL,
            value       TEXT NOT NULL,
            threat_type TEXT,
            source      TEXT DEFAULT 'manual',
            confidence  INTEGER DEFAULT 80,
            added_at    TEXT DEFAULT (datetime('now')),
            UNIQUE(ioc_type, value)
        );

        CREATE TABLE IF NOT EXISTS shift_handovers (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            outgoing_analyst  TEXT NOT NULL,
            incoming_analyst  TEXT NOT NULL,
            shift_type        TEXT,
            report_json       TEXT,
            created_at        TEXT DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_alerts_ts       ON alerts(timestamp);
        CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
        CREATE INDEX IF NOT EXISTS idx_alerts_src_ip   ON alerts(src_ip);
        CREATE INDEX IF NOT EXISTS idx_traffic_ts      ON traffic(timestamp);
        CREATE INDEX IF NOT EXISTS idx_syslog_ts       ON syslog_events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_ioc_value       ON ioc_list(value);
        """)
        conn.commit()
    log.info("Database initialised at %s", config.DB_PATH)


# ─── Generic helpers ───────────────────────────────────────────────────────────

def execute(sql: str, params: Tuple = ()) -> None:
    with get_conn() as conn:
        conn.execute(sql, params)
        conn.commit()


def fetchall(sql: str, params: Tuple = ()) -> List[sqlite3.Row]:
    with get_conn() as conn:
        return conn.execute(sql, params).fetchall()


def fetchone(sql: str, params: Tuple = ()) -> Optional[sqlite3.Row]:
    with get_conn() as conn:
        return conn.execute(sql, params).fetchone()


def insert(table: str, data: Dict[str, Any]) -> int:
    cols = ", ".join(data.keys())
    placeholders = ", ".join(["?" for _ in data])
    sql = f"INSERT INTO {table} ({cols}) VALUES ({placeholders})"
    with get_conn() as conn:
        cur = conn.execute(sql, tuple(data.values()))
        conn.commit()
        return cur.lastrowid


# ─── Domain helpers ────────────────────────────────────────────────────────────

def insert_alert(alert: Dict[str, Any]) -> int:
    alert.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
    return insert("alerts", alert)


def get_recent_alerts(limit: int = 100, severity: str = None) -> List:
    if severity:
        return fetchall(
            "SELECT * FROM alerts WHERE severity=? ORDER BY timestamp DESC LIMIT ?",
            (severity, limit),
        )
    return fetchall(
        "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
    )


def get_alert_counts_by_severity() -> Dict[str, int]:
    rows = fetchall(
        "SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity"
    )
    return {r["severity"]: r["cnt"] for r in rows}


def acknowledge_alert(alert_id: int, username: str) -> None:
    execute(
        "UPDATE alerts SET acknowledged=1, ack_by=?, ack_at=datetime('now') WHERE id=?",
        (username, alert_id),
    )


def insert_traffic(pkt: Dict[str, Any]) -> None:
    pkt.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
    insert("traffic", pkt)


def get_traffic_stats(minutes: int = 10) -> List:
    return fetchall(
        """SELECT strftime('%Y-%m-%dT%H:%M', timestamp) as minute,
                  COUNT(*) as packets, SUM(length) as bytes
           FROM traffic
           WHERE timestamp >= datetime('now', ?)
           GROUP BY minute ORDER BY minute""",
        (f"-{minutes} minutes",),
    )


def insert_syslog(event: Dict[str, Any]) -> None:
    event.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
    insert("syslog_events", event)


def get_incidents(status: str = None) -> List:
    if status:
        return fetchall(
            "SELECT * FROM incidents WHERE status=? ORDER BY created_at DESC",
            (status,),
        )
    return fetchall("SELECT * FROM incidents ORDER BY created_at DESC")


def create_incident(data: Dict[str, Any]) -> int:
    return insert("incidents", data)


def update_incident(incident_id: int, data: Dict[str, Any]) -> None:
    data["updated_at"] = datetime.now(timezone.utc).isoformat()
    sets = ", ".join(f"{k}=?" for k in data)
    execute(
        f"UPDATE incidents SET {sets} WHERE id=?",
        tuple(data.values()) + (incident_id,),
    )


def audit(username: str, action: str, detail: str = "", ip_address: str = "") -> None:
    insert("audit_log", {
        "username": username, "action": action,
        "detail": detail, "ip_address": ip_address,
    })


def get_top_talkers(limit: int = 10) -> List:
    return fetchall(
        """SELECT src_ip, COUNT(*) as packets, SUM(length) as bytes
           FROM traffic GROUP BY src_ip ORDER BY packets DESC LIMIT ?""",
        (limit,),
    )


def get_threat_intel_cache(ip: str) -> Optional[Dict]:
    import time, json
    row = fetchone("SELECT * FROM threat_intel_cache WHERE ip=?", (ip,))
    if row and (time.time() - row["cached_at"]) < 3600:
        try:
            return json.loads(row["data"])
        except Exception:
            return None
    return None


def set_threat_intel_cache(ip: str, data: Dict, source: str) -> None:
    import time, json
    execute(
        """INSERT OR REPLACE INTO threat_intel_cache (ip, data, source, cached_at)
           VALUES (?, ?, ?, ?)""",
        (ip, json.dumps(data), source, time.time()),
    )
