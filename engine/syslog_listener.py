"""
engine/syslog_listener.py — UDP syslog receiver (RFC 3164)
"""

import re
import socket
import threading
from datetime import datetime, timezone
from typing import Callable, List, Optional

import config
from db import database as db
from utils.helpers import parse_log_level
from utils.logger import get_logger

log = get_logger(__name__)

# RFC 3164 syslog pattern: <PRI>TIMESTAMP HOSTNAME PROGRAM: MESSAGE
_SYSLOG_RE = re.compile(
    r"<(\d+)>"                           # priority
    r"(\w{3}\s+\d+\s+\d+:\d+:\d+)?\s*"  # optional timestamp
    r"(\S+)?\s*"                          # optional hostname
    r"([^:]+)?:\s*"                       # optional program
    r"(.*)",                              # message
    re.DOTALL,
)


def parse_syslog(raw: bytes, source_ip: str) -> dict:
    try:
        msg = raw.decode("utf-8", errors="replace").strip()
    except Exception:
        msg = str(raw)

    event = {
        "source_ip": source_ip,
        "facility":  0,
        "severity":  6,
        "hostname":  source_ip,
        "program":   "unknown",
        "message":   msg,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    m = _SYSLOG_RE.match(msg)
    if m:
        pri = int(m.group(1)) if m.group(1) else 0
        event["facility"] = pri >> 3
        event["severity"] = pri & 0x07
        if m.group(3):
            event["hostname"] = m.group(3)
        if m.group(4):
            event["program"] = m.group(4).strip()
        if m.group(5):
            event["message"] = m.group(5).strip()

    return event


class SyslogListener:
    """
    Listens on UDP for syslog messages from firewalls, routers, switches, etc.
    Persists events to DB and fires callbacks.
    """

    def __init__(self):
        self._callbacks: List[Callable] = []
        self._socket: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._stats = {"received": 0, "errors": 0}

    def add_callback(self, fn: Callable[[dict], None]) -> None:
        self._callbacks.append(fn)

    def start(self) -> bool:
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._socket.bind((config.SYSLOG_HOST, config.SYSLOG_PORT))
            self._socket.settimeout(1.0)
            self._running = True
            self._thread = threading.Thread(
                target=self._listen_loop, daemon=True, name="SyslogListener"
            )
            self._thread.start()
            log.info("Syslog listener started on %s:%d", config.SYSLOG_HOST, config.SYSLOG_PORT)
            return True
        except Exception as e:
            log.error("Cannot start syslog listener: %s", e)
            return False

    def stop(self) -> None:
        self._running = False
        if self._socket:
            try:
                self._socket.close()
            except Exception:
                pass

    def get_stats(self) -> dict:
        return dict(self._stats)

    def _listen_loop(self) -> None:
        while self._running:
            try:
                data, addr = self._socket.recvfrom(config.SYSLOG_BUFFER)
                self._stats["received"] += 1
                event = parse_syslog(data, addr[0])
                db.insert_syslog(event)
                for cb in self._callbacks:
                    try:
                        cb(event)
                    except Exception:
                        pass
            except socket.timeout:
                continue
            except Exception as e:
                if self._running:
                    self._stats["errors"] += 1
                    log.debug("Syslog recv error: %s", e)
