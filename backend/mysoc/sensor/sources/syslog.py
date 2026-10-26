"""Syslog over UDP (RFC 3164 and RFC 5424)."""

import logging
import queue
import re
import socket
import threading
from datetime import UTC, datetime

from .demo import LogLine

log = logging.getLogger("mysoc.sensor")

_PRI = re.compile(r"^<(\d{1,3})>")
_5424 = re.compile(r"^1 \S+ (?P<host>\S+) (?P<app>\S+) \S+ \S+ (?:-|\[.*?\])\s?(?P<msg>.*)$", re.S)
_3164 = re.compile(r"^(?:\w{3} [ \d]\d \d\d:\d\d:\d\d )?(?P<host>\S+) (?P<app>[^:\[\s]+)(?:\[\d+\])?: (?P<msg>.*)$", re.S)

MAX_DATAGRAM = 8192


def parse(raw: bytes, source_ip: str) -> LogLine:
    text = raw.decode("utf-8", errors="replace").strip()
    facility, severity = 1, 6
    m = _PRI.match(text)
    if m:
        pri = min(int(m.group(1)), 191)
        facility, severity = pri >> 3, pri & 7
        text = text[m.end():]
    host, app, msg = source_ip, "", text
    for pattern in (_5424, _3164):
        m = pattern.match(text)
        if m:
            host, app, msg = m.group("host"), m.group("app"), m.group("msg")
            break
    line = LogLine(datetime.now(UTC), source_ip, host[:255], app[:64], severity, msg)
    line.facility = facility  # type: ignore[attr-defined]
    return line


class SyslogServer:
    def __init__(self, out: queue.Queue, port: int, host: str = "0.0.0.0"):
        self.out, self.port, self.host = out, port, host
        self.received = 0

    def start(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((self.host, self.port))
        log.info("Syslog listening on udp/%d", self.port)
        threading.Thread(target=self._run, args=(sock,), name="syslog", daemon=True).start()

    def _run(self, sock: socket.socket) -> None:
        while True:
            data, (ip, _) = sock.recvfrom(MAX_DATAGRAM)
            self.received += 1
            try:
                self.out.put_nowait(parse(data, ip))
            except queue.Full:
                pass  # shed load rather than block the socket
