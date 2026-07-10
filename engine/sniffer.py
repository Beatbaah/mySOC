"""
engine/sniffer.py — Live packet capture via Scapy with ring buffer
"""

import queue
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional

import config
from utils.logger import get_logger
from utils.helpers import proto_name

log = get_logger(__name__)

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    log.warning("Scapy not installed — live capture disabled")


@dataclass
class PacketRecord:
    timestamp:  str
    src_ip:     str
    dst_ip:     str
    src_port:   int  = 0
    dst_port:   int  = 0
    protocol:   str  = "UNKNOWN"
    length:     int  = 0
    flags:      str  = ""
    ttl:        int  = 0
    payload:    bytes = field(default_factory=bytes, repr=False)


class PacketSniffer:
    """
    Captures packets on a background thread.
    Keeps the last N packets in a ring buffer (deque).
    External callbacks receive each PacketRecord.
    """

    def __init__(self):
        self._buffer: deque = deque(maxlen=config.CAPTURE_BUFFER_SIZE)
        self._callbacks: list[Callable] = []
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._stats = {"packets": 0, "bytes": 0, "start_time": None}
        self._lock = threading.Lock()

    # ── Public API ──────────────────────────────────────────────────────────────

    def add_callback(self, fn: Callable[[PacketRecord], None]) -> None:
        self._callbacks.append(fn)

    def start(self, interface: Optional[str] = None) -> bool:
        if not SCAPY_AVAILABLE:
            log.error("Cannot start sniffer — Scapy unavailable")
            return False
        if self._running:
            return True

        iface = interface or config.CAPTURE_INTERFACE
        self._running = True
        self._stats["start_time"] = time.time()

        self._thread = threading.Thread(
            target=self._capture_loop,
            args=(iface,),
            daemon=True,
            name="PacketSniffer",
        )
        self._thread.start()
        log.info("Packet sniffer started on interface=%s", iface or "auto")
        return True

    def stop(self) -> None:
        self._running = False
        log.info("Packet sniffer stopping...")

    def get_buffer(self) -> list[PacketRecord]:
        with self._lock:
            return list(self._buffer)

    def get_stats(self) -> dict:
        elapsed = time.time() - (self._stats["start_time"] or time.time())
        pps = self._stats["packets"] / max(elapsed, 1)
        return {
            "packets":  self._stats["packets"],
            "bytes":    self._stats["bytes"],
            "pps":      round(pps, 1),
            "running":  self._running,
            "elapsed":  int(elapsed),
        }

    # ── Internal ────────────────────────────────────────────────────────────────

    def _capture_loop(self, iface: Optional[str]) -> None:
        try:
            sniff(
                iface=iface,
                filter=config.CAPTURE_FILTER,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda _: not self._running,
                timeout=config.CAPTURE_TIMEOUT_MS / 1000,
            )
        except Exception as e:
            log.error("Sniffer error: %s", e)
            self._running = False

    def _process_packet(self, pkt) -> None:
        try:
            if not pkt.haslayer(IP):
                return

            ip = pkt[IP]
            record = PacketRecord(
                timestamp=datetime.now(timezone.utc).isoformat(),
                src_ip=ip.src,
                dst_ip=ip.dst,
                protocol=proto_name(ip.proto),
                length=len(pkt),
                ttl=ip.ttl,
            )

            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                record.src_port = tcp.sport
                record.dst_port = tcp.dport
                record.flags = str(tcp.flags)

            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                record.src_port = udp.sport
                record.dst_port = udp.dport

            if pkt.haslayer(Raw):
                record.payload = bytes(pkt[Raw])[:256]

            with self._lock:
                self._buffer.append(record)
            self._stats["packets"] += 1
            self._stats["bytes"] += record.length

            for cb in self._callbacks:
                try:
                    cb(record)
                except Exception as e:
                    log.debug("Callback error: %s", e)

        except Exception as e:
            log.debug("Packet processing error: %s", e)


# ─── Demo / simulation mode ────────────────────────────────────────────────────

import random

DEMO_IPS_SRC = ["192.168.1.10", "10.0.0.5", "172.16.0.20",
                "203.0.113.5", "198.51.100.3", "45.33.32.156"]
DEMO_IPS_DST = ["8.8.8.8", "1.1.1.1", "192.168.1.1",
                "10.0.0.1", "104.21.40.1", "172.217.14.78"]


class DemoSniffer:
    """Generates synthetic packet data for demo / development mode."""

    def __init__(self):
        self._buffer: deque = deque(maxlen=config.CAPTURE_BUFFER_SIZE)
        self._callbacks: list[Callable] = []
        self._running = False
        self._stats = {"packets": 0, "bytes": 0, "start_time": None}
        self._lock = threading.Lock()

    def add_callback(self, fn):
        self._callbacks.append(fn)

    def start(self, interface=None) -> bool:
        self._running = True
        self._stats["start_time"] = time.time()
        t = threading.Thread(target=self._gen_loop, daemon=True, name="DemoSniffer")
        t.start()
        log.info("Demo sniffer started")
        return True

    def stop(self):
        self._running = False

    def get_buffer(self):
        with self._lock:
            return list(self._buffer)

    def get_stats(self):
        elapsed = time.time() - (self._stats["start_time"] or time.time())
        return {
            "packets": self._stats["packets"],
            "bytes":   self._stats["bytes"],
            "pps":     round(self._stats["packets"] / max(elapsed, 1), 1),
            "running": self._running,
            "elapsed": int(elapsed),
        }

    def _gen_loop(self):
        protocols = ["TCP", "UDP", "ICMP"]
        while self._running:
            burst = random.randint(1, 8)
            for _ in range(burst):
                record = PacketRecord(
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    src_ip=random.choice(DEMO_IPS_SRC),
                    dst_ip=random.choice(DEMO_IPS_DST),
                    src_port=random.randint(1024, 65535),
                    dst_port=random.choice([80, 443, 22, 53, 8080, 3389]),
                    protocol=random.choice(protocols),
                    length=random.randint(40, 1500),
                    ttl=random.randint(32, 128),
                    flags="S" if random.random() < 0.3 else "PA",
                )
                with self._lock:
                    self._buffer.append(record)
                self._stats["packets"] += 1
                self._stats["bytes"] += record.length
                for cb in self._callbacks:
                    try:
                        cb(record)
                    except Exception:
                        pass
            time.sleep(random.uniform(0.05, 0.3))
