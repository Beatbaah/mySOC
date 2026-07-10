"""
engine/detection.py — Rule-based detection + correlation engine
"""

import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, List, Optional

import config
from db import database as db
from utils.helpers import is_whitelisted, is_internal
from utils.logger import get_logger

log = get_logger(__name__)


@dataclass
class DetectionResult:
    triggered: bool
    rule_name: str
    severity: str
    description: str
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: str = ""
    raw_data: str = ""
    threat_score: int = 0


T = config.DETECTION_THRESHOLDS


class DetectionEngine:
    """
    Stateful rule engine.  Call `process(packet_record)` for each packet.
    Fires alert callbacks when a rule matches.
    """

    def __init__(self):
        self._alert_callbacks: List[Callable] = []

        # Per-IP sliding-window counters
        # { ip: deque of timestamps }
        self._port_scan:    defaultdict = defaultdict(lambda: defaultdict(list))
        self._syn_track:    defaultdict = defaultdict(list)
        self._icmp_track:   defaultdict = defaultdict(list)
        self._auth_fail:    defaultdict = defaultdict(list)
        self._dns_queries:  defaultdict = defaultdict(list)
        self._conn_track:   defaultdict = defaultdict(list)
        self._bytes_out:    defaultdict = defaultdict(int)
        self._bytes_window: defaultdict = defaultdict(float)  # window start

        # Correlation: recent alerts for multi-stage detection
        self._recent_alerts: deque = deque(maxlen=500)

    # ── Public API ──────────────────────────────────────────────────────────────

    def add_alert_callback(self, fn: Callable[[DetectionResult], None]) -> None:
        self._alert_callbacks.append(fn)

    def process(self, pkt) -> List[DetectionResult]:
        if is_whitelisted(pkt.src_ip):
            return []

        results = []
        now = time.time()

        results += self._rule_port_scan(pkt, now)
        results += self._rule_syn_flood(pkt, now)
        results += self._rule_icmp_flood(pkt, now)
        results += self._rule_brute_force(pkt, now)
        results += self._rule_dns_tunnel(pkt, now)
        results += self._rule_data_exfil(pkt, now)
        results += self._rule_suspicious_port(pkt)
        results += self._rule_rdp_external(pkt)

        for r in results:
            self._fire(r)
        return results

    # ── Rules ───────────────────────────────────────────────────────────────────

    def _rule_port_scan(self, pkt, now: float) -> List[DetectionResult]:
        results = []
        window = 10
        self._port_scan[pkt.src_ip][pkt.dst_ip].append((now, pkt.dst_port))

        # Prune old entries
        self._port_scan[pkt.src_ip][pkt.dst_ip] = [
            e for e in self._port_scan[pkt.src_ip][pkt.dst_ip]
            if now - e[0] < window
        ]
        unique_ports = len(set(e[1] for e in self._port_scan[pkt.src_ip][pkt.dst_ip]))

        if unique_ports >= T["port_scan_threshold"]:
            self._port_scan[pkt.src_ip][pkt.dst_ip].clear()
            results.append(DetectionResult(
                triggered=True,
                rule_name="PORT_SCAN",
                severity="HIGH",
                description=f"Port scan: {pkt.src_ip} → {pkt.dst_ip} ({unique_ports} ports in {window}s)",
                src_ip=pkt.src_ip,
                dst_ip=pkt.dst_ip,
                protocol=pkt.protocol,
                raw_data=f"unique_ports={unique_ports}",
                threat_score=70,
            ))
        return results

    def _rule_syn_flood(self, pkt, now: float) -> List[DetectionResult]:
        if pkt.protocol != "TCP" or "S" not in pkt.flags:
            return []
        window = 5
        self._syn_track[pkt.src_ip].append(now)
        self._syn_track[pkt.src_ip] = [t for t in self._syn_track[pkt.src_ip] if now - t < window]
        count = len(self._syn_track[pkt.src_ip])

        if count >= T["syn_flood_threshold"]:
            self._syn_track[pkt.src_ip].clear()
            return [DetectionResult(
                triggered=True,
                rule_name="SYN_FLOOD",
                severity="CRITICAL",
                description=f"SYN flood from {pkt.src_ip} ({count} SYNs in {window}s)",
                src_ip=pkt.src_ip, dst_ip=pkt.dst_ip,
                protocol="TCP", raw_data=f"syn_count={count}",
                threat_score=90,
            )]
        return []

    def _rule_icmp_flood(self, pkt, now: float) -> List[DetectionResult]:
        if pkt.protocol != "ICMP":
            return []
        window = 10
        self._icmp_track[pkt.src_ip].append(now)
        self._icmp_track[pkt.src_ip] = [t for t in self._icmp_track[pkt.src_ip] if now - t < window]
        count = len(self._icmp_track[pkt.src_ip])

        if count >= T["icmp_flood_threshold"]:
            self._icmp_track[pkt.src_ip].clear()
            return [DetectionResult(
                triggered=True,
                rule_name="ICMP_FLOOD",
                severity="HIGH",
                description=f"ICMP flood from {pkt.src_ip} ({count} packets in {window}s)",
                src_ip=pkt.src_ip, dst_ip=pkt.dst_ip,
                protocol="ICMP", raw_data=f"icmp_count={count}",
                threat_score=75,
            )]
        return []

    def _rule_brute_force(self, pkt, now: float) -> List[DetectionResult]:
        """Detect repeated connections to auth ports (22, 21, 3389, 445)."""
        AUTH_PORTS = {22, 21, 3389, 445, 1433, 3306, 5432}
        if pkt.dst_port not in AUTH_PORTS:
            return []
        window = 60
        self._auth_fail[pkt.src_ip].append(now)
        self._auth_fail[pkt.src_ip] = [t for t in self._auth_fail[pkt.src_ip] if now - t < window]
        count = len(self._auth_fail[pkt.src_ip])

        if count >= T["brute_force_threshold"]:
            self._auth_fail[pkt.src_ip].clear()
            svc = {22: "SSH", 21: "FTP", 3389: "RDP", 445: "SMB"}.get(pkt.dst_port, str(pkt.dst_port))
            return [DetectionResult(
                triggered=True,
                rule_name="BRUTE_FORCE",
                severity="HIGH",
                description=f"Brute-force attack on {svc} from {pkt.src_ip} ({count} attempts in {window}s)",
                src_ip=pkt.src_ip, dst_ip=pkt.dst_ip,
                dst_port=pkt.dst_port, protocol=pkt.protocol,
                raw_data=f"attempts={count}, service={svc}",
                threat_score=80,
            )]
        return []

    def _rule_dns_tunnel(self, pkt, now: float) -> List[DetectionResult]:
        if pkt.dst_port != 53 and pkt.src_port != 53:
            return []
        window = 5
        self._dns_queries[pkt.src_ip].append(now)
        self._dns_queries[pkt.src_ip] = [t for t in self._dns_queries[pkt.src_ip] if now - t < window]
        count = len(self._dns_queries[pkt.src_ip])

        if count >= T["dns_query_threshold"]:
            self._dns_queries[pkt.src_ip].clear()
            return [DetectionResult(
                triggered=True,
                rule_name="DNS_TUNNEL",
                severity="MEDIUM",
                description=f"Suspected DNS tunneling from {pkt.src_ip} ({count} queries in {window}s)",
                src_ip=pkt.src_ip, dst_ip=pkt.dst_ip,
                dst_port=53, protocol="UDP",
                raw_data=f"dns_count={count}",
                threat_score=60,
            )]
        return []

    def _rule_data_exfil(self, pkt, now: float) -> List[DetectionResult]:
        """Detect large outbound data transfers from internal IPs."""
        if not is_internal(pkt.src_ip):
            return []
        window = 60

        if now - self._bytes_window[pkt.src_ip] > window:
            self._bytes_out[pkt.src_ip] = 0
            self._bytes_window[pkt.src_ip] = now

        self._bytes_out[pkt.src_ip] += pkt.length

        if self._bytes_out[pkt.src_ip] >= T["data_exfil_bytes"]:
            total = self._bytes_out[pkt.src_ip]
            self._bytes_out[pkt.src_ip] = 0
            return [DetectionResult(
                triggered=True,
                rule_name="DATA_EXFIL",
                severity="CRITICAL",
                description=f"Possible data exfiltration from {pkt.src_ip} ({total/1e6:.1f} MB in {window}s)",
                src_ip=pkt.src_ip, dst_ip=pkt.dst_ip,
                protocol=pkt.protocol,
                raw_data=f"bytes={total}",
                threat_score=95,
            )]
        return []

    def _rule_suspicious_port(self, pkt) -> List[DetectionResult]:
        SUSPICIOUS = {4444, 1337, 31337, 6666, 6667, 6668, 6669, 12345, 54321, 9001}
        if pkt.dst_port in SUSPICIOUS or pkt.src_port in SUSPICIOUS:
            port = pkt.dst_port if pkt.dst_port in SUSPICIOUS else pkt.src_port
            return [DetectionResult(
                triggered=True,
                rule_name="SUSPICIOUS_PORT",
                severity="MEDIUM",
                description=f"Traffic on suspicious port {port}: {pkt.src_ip} → {pkt.dst_ip}",
                src_ip=pkt.src_ip, dst_ip=pkt.dst_ip,
                dst_port=pkt.dst_port, protocol=pkt.protocol,
                raw_data=f"port={port}",
                threat_score=55,
            )]
        return []

    def _rule_rdp_external(self, pkt) -> List[DetectionResult]:
        """Alert on RDP (3389) connections from external IPs to internal."""
        if pkt.dst_port == 3389 and not is_internal(pkt.src_ip) and is_internal(pkt.dst_ip):
            return [DetectionResult(
                triggered=True,
                rule_name="EXTERNAL_RDP",
                severity="HIGH",
                description=f"External RDP access attempt: {pkt.src_ip} → {pkt.dst_ip}:3389",
                src_ip=pkt.src_ip, dst_ip=pkt.dst_ip,
                dst_port=3389, protocol="TCP",
                raw_data="external_rdp=true",
                threat_score=78,
            )]
        return []

    # ── Fire callbacks ──────────────────────────────────────────────────────────

    def _fire(self, result: DetectionResult) -> None:
        self._recent_alerts.append(result)
        alert_data = {
            "severity":    result.severity,
            "alert_type":  result.rule_name,
            "src_ip":      result.src_ip,
            "dst_ip":      result.dst_ip,
            "src_port":    result.src_port,
            "dst_port":    result.dst_port,
            "protocol":    result.protocol,
            "description": result.description,
            "raw_data":    result.raw_data,
            "threat_score": result.threat_score,
        }
        db.insert_alert(alert_data)

        for cb in self._alert_callbacks:
            try:
                cb(result)
            except Exception as e:
                log.error("Alert callback error: %s", e)
