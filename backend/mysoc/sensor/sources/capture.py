"""Live packet capture with Scapy, aggregated into flows.

Needs raw-socket privileges (root, or CAP_NET_RAW + CAP_NET_ADMIN). Only
headers are read; payloads are never stored.
"""

import logging
import queue
import threading
from datetime import UTC, datetime

from ..flows import FlowAggregator

log = logging.getLogger("mysoc.sensor")

_TCP_FLAGS = {"S": 0x02, "A": 0x10, "F": 0x01, "R": 0x04, "P": 0x08, "U": 0x20}


class PacketCapture:
    def __init__(self, out: queue.Queue, interface: str | None, active_timeout: float):
        self.out = out
        self.interface = interface
        self.agg = FlowAggregator(active=active_timeout)
        self.lock = threading.Lock()
        self.packets = 0
        self.error: str | None = None

    def start(self) -> None:
        try:
            from scapy.all import AsyncSniffer  # noqa: F401
        except ImportError as e:
            raise RuntimeError("Live capture needs Scapy: pip install -r requirements-capture.txt") from e
        threading.Thread(target=self._sniff, name="capture", daemon=True).start()
        threading.Thread(target=self._flush, name="capture-flush", daemon=True).start()

    def _sniff(self) -> None:
        from scapy.all import IP, TCP, UDP, IPv6, sniff

        def on_packet(pkt) -> None:
            ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
            if ip is None:
                return
            proto, sport, dport, flags = "OTHER", 0, 0, ""
            if pkt.haslayer(TCP):
                t = pkt[TCP]
                proto, sport, dport = "TCP", int(t.sport), int(t.dport)
                flags = "".join(k for k, bit in _TCP_FLAGS.items() if int(t.flags) & bit)
            elif pkt.haslayer(UDP):
                u = pkt[UDP]
                proto, sport, dport = "UDP", int(u.sport), int(u.dport)
            elif getattr(ip, "proto", getattr(ip, "nh", 0)) in (1, 58):
                proto = "ICMP"
            with self.lock:
                self.packets += 1
                self.agg.add(datetime.now(UTC), ip.src, sport, ip.dst, dport, proto, len(pkt), flags)

        try:
            # No timeout: capture runs until the process stops.
            sniff(iface=self.interface, filter="ip or ip6", prn=on_packet, store=False)
        except Exception as e:
            self.error = str(e)
            log.error("Packet capture stopped: %s", e)

    def _flush(self) -> None:
        import time

        while True:
            time.sleep(1)
            with self.lock:
                done = self.agg.expire()
            for f in done:
                self.out.put(f)
