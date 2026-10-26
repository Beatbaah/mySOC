"""Detection logic. Works on flows (and log events) in event time, so the
same code gives the same answers live, on replayed history and in tests.

Every detector keeps small per-key sliding windows and returns Findings;
turning findings into stored, deduplicated alerts is alerts.py's job.
"""

import re
import statistics
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from ..flows import FlowRecord
from ..netctx import NetContext

SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 135: "RPC", 445: "SMB", 1433: "MS SQL", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM", 5986: "WinRM",
}


def service(port: int) -> str:
    return SERVICE_NAMES.get(port, f"port {port}")


@dataclass
class Finding:
    rule_id: str
    title: str
    description: str
    at: datetime
    src_ip: str = ""
    dst_ip: str = ""
    dst_port: int = 0
    protocol: str = ""
    src_country: str = ""
    severity: str | None = None  # overrides the rule's severity when set
    evidence: dict = field(default_factory=dict)
    # Which fields make two findings "the same thing happening again".
    dedup_fields: tuple[str, ...] = ("src_ip", "dst_ip")

    @property
    def dedup_key(self) -> str:
        return "|".join([self.rule_id, *(str(getattr(self, f)) for f in self.dedup_fields)])


@dataclass
class RuleConfig:
    id: str
    name: str
    kind: str
    enabled: bool
    severity: str
    params: dict


class _Windows:
    """Per-key deques of (time, value), trimmed to a time window."""

    def __init__(self):
        self.data: dict = defaultdict(deque)

    def add(self, key, at: datetime, value, window: timedelta) -> deque:
        q = self.data[key]
        q.append((at, value))
        cutoff = at - window
        while q and q[0][0] < cutoff:
            q.popleft()
        return q

    def clear(self, key) -> None:
        self.data.pop(key, None)

    def prune(self, now: datetime, window: timedelta) -> None:
        cutoff = now - window
        for k in [k for k, q in self.data.items() if not q or q[-1][0] < cutoff]:
            del self.data[k]


# Match-rule fields: name -> (flow attribute or function, comparison)
MATCH_FIELDS = {
    "protocol": "equals (TCP, UDP, ICMP)",
    "src_port": "equals",
    "dst_port": "equals",
    "src_ip": "equals",
    "dst_ip": "equals",
    "src_internal": "true / false",
    "dst_internal": "true / false",
    "bytes_gt": "flow bytes greater than",
    "packets_gt": "flow packets greater than",
    "avg_packet_bytes_gt": "average packet size greater than",
    "established": "true: TCP handshake completed (not a lone probe)",
}

_FAILED_LOGIN = [
    re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)"),
    re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)"),
    re.compile(r"authentication failure;.*rhost=(?P<ip>[0-9a-fA-F:.]+)(?:.*user=(?P<user>\S+))?"),
    re.compile(r"Login failed for user '(?P<user>[^']*)'.*\[CLIENT: (?P<ip>[0-9a-fA-F:.]+)\]"),
]


def parse_failed_login(message: str) -> tuple[str, str] | None:
    """(source IP, username) if the log line records a failed login."""
    for pattern in _FAILED_LOGIN:
        m = pattern.search(message)
        if m:
            return m.group("ip"), (m.groupdict().get("user") or "")
    return None


class DetectionEngine:
    def __init__(self, net: NetContext):
        self.net = net
        self.rules: dict[str, RuleConfig] = {}
        self.indicators: dict[str, str] = {}  # ip -> threat
        self._w: dict[str, _Windows] = defaultdict(_Windows)
        # Once a windowed rule fires for a key, stay quiet for one window;
        # repeats would only fold into the same alert anyway.
        self._quiet_until: dict[tuple, datetime] = {}
        self._seen = 0

    # ── configuration ─────────────────────────────────────────────────────

    def set_rules(self, rules: list[RuleConfig]) -> None:
        self.rules = {r.id: r for r in rules}

    def set_indicators(self, indicators: dict[str, str]) -> None:
        self.indicators = indicators

    def _on(self, rule_id: str) -> RuleConfig | None:
        r = self.rules.get(rule_id)
        return r if r and r.enabled else None

    def _quiet(self, rule_id: str, key, at: datetime) -> bool:
        until = self._quiet_until.get((rule_id, key))
        return until is not None and at < until

    def _hush(self, rule_id: str, key, at: datetime, seconds: float) -> None:
        self._quiet_until[(rule_id, key)] = at + timedelta(seconds=seconds)

    # ── flows ─────────────────────────────────────────────────────────────

    def process_flow(self, f: FlowRecord) -> list[Finding]:
        if self.net.allowlisted(f.src_ip) or self.net.allowlisted(f.dst_ip):
            return []
        out: list[Finding] = []
        for check in (
            self._port_scan, self._syn_flood, self._icmp_flood, self._brute_force, self._dns_tunnel,
            self._exfil, self._tool_port, self._remote_access, self._beaconing, self._indicator,
            self._lateral, self._match_rules,
        ):
            out.extend(check(f))
        self._seen += 1
        if self._seen % 5000 == 0:
            self._gc(f.end)
        return out

    def _port_scan(self, f: FlowRecord) -> list[Finding]:
        r = self._on("NET-001")
        if not r or f.protocol not in ("TCP", "UDP"):
            return []
        window = r.params["window_seconds"]
        key = (f.src_ip, f.dst_ip)
        if self._quiet(r.id, key, f.start):
            return []
        q = self._w[r.id].add(key, f.start, f.dst_port, timedelta(seconds=window))
        ports = {p for _, p in q}
        if len(ports) < r.params["distinct_ports"]:
            return []
        self._w[r.id].clear(key)
        self._hush(r.id, key, f.start, window)
        internal = self.net.internal(f.src_ip)
        sample = sorted(ports)[:25]
        return [Finding(
            r.id,
            f"{'Internal host' if internal else 'External address'} {f.src_ip} scanned {f.dst_ip}",
            f"{f.src_ip} probed {len(ports)} different ports on {f.dst_ip} within {window} seconds.",
            f.start, f.src_ip, f.dst_ip, 0, f.protocol, f.src_country,
            severity="high" if internal else None,
            evidence={"distinct_ports": len(ports), "window_seconds": window, "ports_sample": sample},
        )]

    def _syn_flood(self, f: FlowRecord) -> list[Finding]:
        r = self._on("NET-002")
        if not r or f.protocol != "TCP" or "S" not in f.tcp_flags or "A" in f.tcp_flags:
            return []
        window = r.params["window_seconds"]
        key = f.dst_ip
        if self._quiet(r.id, key, f.start):
            return []
        q = self._w[r.id].add(key, f.start, (f.packets, f.src_ip), timedelta(seconds=window))
        total = sum(p for _, (p, _) in q)
        if total < r.params["syn_packets"]:
            return []
        sources = {s for _, (_, s) in q}
        self._w[r.id].clear(key)
        self._hush(r.id, key, f.start, window)
        return [Finding(
            r.id, f"SYN flood against {f.dst_ip}",
            f"{total:,} unanswered connection attempts reached {f.dst_ip}:{f.dst_port} from {len(sources)} "
            f"source{'s' if len(sources) != 1 else ''} within {window} seconds.",
            f.start, "" if len(sources) > 1 else f.src_ip, f.dst_ip, f.dst_port, "TCP",
            evidence={"syn_packets": total, "sources": len(sources), "sources_sample": sorted(sources)[:20]},
            dedup_fields=("dst_ip",),
        )]

    def _icmp_flood(self, f: FlowRecord) -> list[Finding]:
        r = self._on("NET-003")
        if not r or f.protocol != "ICMP":
            return []
        window = r.params["window_seconds"]
        key = f.dst_ip
        if self._quiet(r.id, key, f.start):
            return []
        q = self._w[r.id].add(key, f.start, f.packets, timedelta(seconds=window))
        total = sum(p for _, p in q)
        if total < r.params["icmp_packets"]:
            return []
        self._w[r.id].clear(key)
        self._hush(r.id, key, f.start, window)
        return [Finding(
            r.id, f"ICMP flood against {f.dst_ip}",
            f"{total:,} ICMP packets reached {f.dst_ip} within {window} seconds.",
            f.start, f.src_ip, f.dst_ip, 0, "ICMP", f.src_country,
            evidence={"icmp_packets": total}, dedup_fields=("dst_ip",),
        )]

    def _brute_force(self, f: FlowRecord) -> list[Finding]:
        r = self._on("NET-004")
        if not r or f.protocol != "TCP" or f.dst_port not in r.params["ports"]:
            return []
        window = r.params["window_seconds"]
        key = (f.src_ip, f.dst_ip, f.dst_port)
        if self._quiet(r.id, key, f.start):
            return []
        q = self._w[r.id].add(key, f.start, 1, timedelta(seconds=window))
        if len(q) < r.params["connections"]:
            return []
        n = len(q)
        self._w[r.id].clear(key)
        self._hush(r.id, key, f.start, window)
        svc = service(f.dst_port)
        return [Finding(
            r.id, f"{svc} brute force on {f.dst_ip} from {f.src_ip}",
            f"{f.src_ip} opened {n} separate {svc} connections to {f.dst_ip} within {window} seconds, "
            "consistent with password guessing.",
            f.start, f.src_ip, f.dst_ip, f.dst_port, "TCP", f.src_country,
            evidence={"connections": n, "window_seconds": window, "service": svc},
            dedup_fields=("src_ip", "dst_ip", "dst_port"),
        )]

    def _dns_tunnel(self, f: FlowRecord) -> list[Finding]:
        r = self._on("NET-005")
        if not r or f.dst_port != 53 or not self.net.internal(f.src_ip):
            return []
        window = r.params["window_seconds"]
        key = f.src_ip
        if self._quiet(r.id, key, f.start):
            return []
        q = self._w[r.id].add(key, f.start, (f.packets, f.bytes), timedelta(seconds=window))
        queries = sum(p for _, (p, _) in q)
        if queries < r.params["queries"]:
            return []
        avg = sum(b for _, (_, b) in q) / max(queries, 1)
        self._w[r.id].clear(key)
        self._hush(r.id, key, f.start, window)
        return [Finding(
            r.id, f"Possible DNS tunnelling from {f.src_ip}",
            f"{f.src_ip} sent {queries:,} DNS queries within {window} seconds (average {avg:.0f} bytes each). "
            "Normal browsing produces a fraction of that.",
            f.start, f.src_ip, f.dst_ip, 53, f.protocol,
            evidence={"queries": queries, "avg_query_bytes": round(avg), "window_seconds": window},
            dedup_fields=("src_ip",),
        )]

    def _exfil(self, f: FlowRecord) -> list[Finding]:
        r = self._on("NET-006")
        if not r or not self.net.internal(f.src_ip) or self.net.internal(f.dst_ip):
            return []
        window = r.params["window_seconds"]
        key = (f.src_ip, f.dst_ip)
        if self._quiet(r.id, key, f.start):
            return []
        q = self._w[r.id].add(key, f.start, f.bytes, timedelta(seconds=window))
        total = sum(b for _, b in q)
        if total < r.params["bytes"]:
            return []
        self._w[r.id].clear(key)
        self._hush(r.id, key, f.start, window)
        return [Finding(
            r.id, f"{f.src_ip} sent {total / 1e6:.0f} MB to {f.dst_ip}",
            f"Internal host {f.src_ip} uploaded {total / 1e6:.1f} MB to external address {f.dst_ip} "
            f"within {window // 60} minutes.",
            f.start, f.src_ip, f.dst_ip, f.dst_port, f.protocol, f.dst_country,
            evidence={"bytes": total, "window_seconds": window, "dst_country": f.dst_country},
        )]

    def _tool_port(self, f: FlowRecord) -> list[Finding]:
        r = self._on("NET-007")
        if not r:
            return []
        ports = r.params["ports"]
        port = f.dst_port if f.dst_port in ports else f.src_port if f.src_port in ports else 0
        if not port:
            return []
        return [Finding(
            r.id, f"Port {port} traffic between {f.src_ip} and {f.dst_ip}",
            f"{f.src_ip}:{f.src_port} → {f.dst_ip}:{f.dst_port} ({f.protocol}). Port {port} is a common default "
            "for remote-access trojans and attack tools.",
            f.start, f.src_ip, f.dst_ip, f.dst_port, f.protocol, f.src_country,
            evidence={"port": port, "bytes": f.bytes, "packets": f.packets},
            dedup_fields=("src_ip", "dst_ip", "dst_port"),
        )]

    def _remote_access(self, f: FlowRecord) -> list[Finding]:
        r = self._on("NET-008")
        # "A" in the flags: the handshake completed. A lone SYN is a probe
        # (the port scan rule covers those), not a connection.
        if (
            not r or f.protocol != "TCP" or f.dst_port not in r.params["ports"] or "A" not in f.tcp_flags
            or self.net.internal(f.src_ip) or not self.net.internal(f.dst_ip)
        ):
            return []
        svc = service(f.dst_port)
        return [Finding(
            r.id, f"{svc} reached from the internet: {f.src_ip} → {f.dst_ip}",
            f"External address {f.src_ip} connected to {svc} on internal host {f.dst_ip}. Check whether this "
            "service should be exposed, and block it at the firewall if not.",
            f.start, f.src_ip, f.dst_ip, f.dst_port, "TCP", f.src_country,
            evidence={"service": svc},
            dedup_fields=("src_ip", "dst_ip", "dst_port"),
        )]

    def _beaconing(self, f: FlowRecord) -> list[Finding]:
        r = self._on("NET-009")
        if not r or not self.net.internal(f.src_ip) or self.net.internal(f.dst_ip) or f.dst_port == 53:
            return []
        lookback = r.params["lookback_seconds"]
        key = (f.src_ip, f.dst_ip, f.dst_port)
        q = self._w[r.id].add(key, f.start, None, timedelta(seconds=lookback))
        if self._quiet(r.id, key, f.start) or len(q) < r.params["min_connections"]:
            return []
        times = [t for t, _ in q]
        gaps = [(b - a).total_seconds() for a, b in zip(times, times[1:], strict=False)]
        mean = statistics.fmean(gaps)
        if mean < 5:
            return []  # bursts, not a heartbeat
        jitter = statistics.pstdev(gaps) / mean
        if jitter > r.params["max_jitter"]:
            return []
        self._hush(r.id, key, f.start, lookback / 2)
        return [Finding(
            r.id, f"{f.src_ip} is beaconing to {f.dst_ip}",
            f"{f.src_ip} contacted {f.dst_ip}:{f.dst_port} {len(times)} times, every {mean:.0f} seconds "
            f"(±{jitter * 100:.0f}%). Regular check-ins like this are typical of malware calling home.",
            f.start, f.src_ip, f.dst_ip, f.dst_port, f.protocol, f.dst_country,
            evidence={"connections": len(times), "interval_seconds": round(mean, 1), "jitter": round(jitter, 3)},
            dedup_fields=("src_ip", "dst_ip", "dst_port"),
        )]

    def _indicator(self, f: FlowRecord) -> list[Finding]:
        r = self._on("NET-010")
        if not r or not self.indicators:
            return []
        hit = f.dst_ip if f.dst_ip in self.indicators else f.src_ip if f.src_ip in self.indicators else ""
        if not hit:
            return []
        other = f.src_ip if hit == f.dst_ip else f.dst_ip
        threat = self.indicators[hit]
        return [Finding(
            r.id, f"{other} talked to known-bad address {hit}",
            f"{f.src_ip}:{f.src_port} → {f.dst_ip}:{f.dst_port} ({f.protocol}). {hit} is on the indicator list"
            + (f" ({threat})." if threat else "."),
            f.start, f.src_ip, f.dst_ip, f.dst_port, f.protocol, f.dst_country if hit == f.dst_ip else f.src_country,
            evidence={"indicator": hit, "threat": threat},
        )]

    def _lateral(self, f: FlowRecord) -> list[Finding]:
        r = self._on("NET-011")
        if (
            not r or f.dst_port not in r.params["ports"]
            or not self.net.internal(f.src_ip) or not self.net.internal(f.dst_ip)
        ):
            return []
        window = r.params["window_seconds"]
        key = f.src_ip
        if self._quiet(r.id, key, f.start):
            return []
        q = self._w[r.id].add(key, f.start, (f.dst_ip, f.dst_port), timedelta(seconds=window))
        hosts = {h for _, (h, _) in q}
        if len(hosts) < r.params["distinct_hosts"]:
            return []
        services = sorted({service(p) for _, (_, p) in q})
        self._w[r.id].clear(key)
        self._hush(r.id, key, f.start, window)
        return [Finding(
            r.id, f"{f.src_ip} connected to {len(hosts)} internal hosts over {', '.join(services)}",
            f"Internal host {f.src_ip} reached admin services on {len(hosts)} other internal hosts within "
            f"{window // 60} minutes. Workstations rarely do this; attackers spreading through a network do.",
            f.start, f.src_ip, "", 0, f.protocol,
            evidence={"hosts": sorted(hosts), "services": services, "window_seconds": window},
            dedup_fields=("src_ip",),
        )]

    def _match_rules(self, f: FlowRecord) -> list[Finding]:
        out = []
        for r in self.rules.values():
            if r.kind != "match" or not r.enabled:
                continue
            cond = r.params.get("conditions") or {}
            if cond and all(self._cond(f, k, v) for k, v in cond.items()):
                out.append(Finding(
                    r.id, f"{r.name}: {f.src_ip} → {f.dst_ip}",
                    f"{f.src_ip}:{f.src_port} → {f.dst_ip}:{f.dst_port} ({f.protocol}, {f.packets} packets, "
                    f"{f.bytes:,} bytes) matched rule “{r.name}”.",
                    f.start, f.src_ip, f.dst_ip, f.dst_port, f.protocol, f.src_country,
                    evidence={"conditions": cond},
                    dedup_fields=("src_ip", "dst_ip", "dst_port"),
                ))
        return out

    def _cond(self, f: FlowRecord, key: str, value) -> bool:
        match key:
            case "protocol":
                return f.protocol == str(value).upper()
            case "src_port" | "dst_port" | "src_ip" | "dst_ip":
                return str(getattr(f, key)) == str(value)
            case "src_internal":
                return self.net.internal(f.src_ip) == bool(value)
            case "dst_internal":
                return self.net.internal(f.dst_ip) == bool(value)
            case "bytes_gt":
                return f.bytes > int(value)
            case "packets_gt":
                return f.packets > int(value)
            case "avg_packet_bytes_gt":
                return f.packets > 0 and f.bytes / f.packets > int(value)
            case "established":
                return ("A" in f.tcp_flags) == bool(value)
        return False  # unknown field: never match (validated when saved)

    # ── logs ──────────────────────────────────────────────────────────────

    def process_log(self, at: datetime, source_ip: str, host: str, message: str) -> list[Finding]:
        r = self._on("LOG-001")
        if not r:
            return []
        parsed = parse_failed_login(message)
        if not parsed:
            return []
        ip, user = parsed
        if self.net.allowlisted(ip):
            return []
        window = r.params["window_seconds"]
        key = (ip, source_ip)
        if self._quiet(r.id, key, at):
            return []
        q = self._w[r.id].add(key, at, user, timedelta(seconds=window))
        if len(q) < r.params["failures"]:
            return []
        users = sorted({u for _, u in q if u})
        self._w[r.id].clear(key)
        self._hush(r.id, key, at, window)
        target = host or source_ip
        return [Finding(
            r.id, f"{len(q)} failed logins on {target} from {ip}",
            f"{target} logged {len(q)} failed logins from {ip} within {window} seconds"
            + (f", trying {', '.join(users[:5])}{'…' if len(users) > 5 else ''}." if users else "."),
            at, ip, source_ip, 0, "",
            evidence={"failures": len(q), "usernames": users[:20], "log_host": target},
        )]

    # ── housekeeping ──────────────────────────────────────────────────────

    def _gc(self, now: datetime) -> None:
        longest = timedelta(hours=1)
        for w in self._w.values():
            w.prune(now, longest)
        self._quiet_until = {k: v for k, v in self._quiet_until.items() if v > now}
