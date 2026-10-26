"""Demo traffic: an office network's normal day, with an intrusion story
replayed on a loop.

All "internet" addresses come from the ranges reserved for documentation
(RFC 5737: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), so the demo
never points at a real organisation. Countries for them are made up for
the map and marked as demo data.

The story, in the order an analyst would see it:
  1. Internet scanners probe the public web server.
  2. Someone brute-forces RDP that was left exposed, and SSH on the
     jump host (with matching failed-login syslog lines).
  3. A workstation starts beaconing to a command server every ~45 s.
  4. It talks to the server on 4444 and over DNS at high volume.
  5. It moves laterally over SMB/RDP to file servers.
  6. It uploads tens of megabytes to the command server.
Plus an occasional SYN flood against the web server.
"""

import random
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta

from ..flows import FlowRecord

# ── The demo network ──────────────────────────────────────────────────────────

WEB = "10.10.0.10"
MAIL = "10.10.0.11"
RDP_GW = "10.10.0.20"
JUMP = "10.10.0.30"
DNS = "10.10.0.53"
FILE_SERVERS = ["10.10.1.10", "10.10.1.11", "10.10.1.12", "10.10.1.13", "10.10.1.14", "10.10.1.15"]
DC = "10.10.1.5"
WORKSTATIONS = [f"10.20.0.{i}" for i in range(21, 61)]
VICTIM = "10.20.0.45"

ASSETS = [
    {"ip": WEB, "hostname": "web-01", "criticality": "high", "os": "Ubuntu 24.04", "owner": "Web team", "tags": ["dmz", "public"]},
    {"ip": MAIL, "hostname": "mail-01", "criticality": "high", "os": "Ubuntu 24.04", "owner": "IT", "tags": ["dmz"]},
    {"ip": RDP_GW, "hostname": "rdp-gw", "criticality": "high", "os": "Windows Server 2022", "owner": "IT", "tags": ["dmz", "remote-access"]},
    {"ip": JUMP, "hostname": "jump-01", "criticality": "high", "os": "Debian 12", "owner": "IT", "tags": ["dmz", "admin"]},
    {"ip": DNS, "hostname": "dns-01", "criticality": "high", "os": "Debian 12", "owner": "IT", "tags": ["core"]},
    {"ip": DC, "hostname": "dc-01", "criticality": "critical", "os": "Windows Server 2022", "owner": "IT", "tags": ["core", "identity"]},
    *[
        {"ip": ip, "hostname": f"fs-0{i + 1}", "criticality": "critical" if i == 0 else "high", "os": "Windows Server 2019",
         "owner": "Finance" if i == 0 else "IT", "tags": ["file-share"]}
        for i, ip in enumerate(FILE_SERVERS)
    ],
    *[
        {"ip": ip, "hostname": f"ws-{ip.split('.')[-1]}", "criticality": "medium", "os": "Windows 11", "owner": "Staff", "tags": ["workstation"]}
        for ip in WORKSTATIONS
    ],
]

# Made-up locations for the documentation ranges (demo only).
_COUNTRIES = ["US", "NL", "DE", "GB", "FR", "BR", "IN", "SG", "RU", "CN", "VN", "KR", "UA", "RO", "ZA", "NG", "GH", "CA", "JP", "TR"]
C2 = "198.51.100.77"
INDICATORS = [
    {"kind": "ip", "value": C2, "threat": "Cobalt Strike team server (demo feed)", "confidence": 90},
    {"kind": "ip", "value": "203.0.113.66", "threat": "Known RDP brute-forcer (demo feed)", "confidence": 75},
    {"kind": "domain", "value": "update-check.example.net", "threat": "C2 domain (demo feed)", "confidence": 85},
]
SAAS = [f"192.0.2.{i}" for i in range(10, 40)]  # "cloud services" the office uses


def country_of(ip: str) -> str:
    if ip.startswith(("192.0.2.", "198.51.100.", "203.0.113.")):
        if ip == C2:
            return "RU"
        last = int(ip.rsplit(".", 1)[1])
        if ip.startswith("192.0.2."):
            return "US" if last % 3 else "IE"
        return _COUNTRIES[(last * 7 + len(ip)) % len(_COUNTRIES)]
    return ""


@dataclass
class LogLine:
    at: datetime
    source_ip: str
    host: str
    app: str
    severity: int
    message: str


Event = FlowRecord | LogLine


class DemoTraffic:
    """Generates events in time order from `start` onwards, as fast as the
    caller consumes them. The caller paces them (real time) or doesn't
    (backfilling history)."""

    STORY_EVERY = timedelta(minutes=40)

    def __init__(self, start: datetime, seed: int = 1, background_per_second: float = 2.0, story_offset: timedelta = timedelta(minutes=2)):
        self.rng = random.Random(seed)
        self.now = start
        self.rate = background_per_second
        self.next_story = start + story_offset
        self._queue: list[Event] = []

    # ── public ────────────────────────────────────────────────────────────

    def until(self, end: datetime) -> Iterator[Event]:
        """Events with timestamps before `end`."""
        while self.now < end:
            step_end = min(end, self.now + timedelta(seconds=1))
            self._background(self.now, step_end)
            if self.now >= self.next_story:
                self._story(self.now)
                self.next_story = self.now + self.STORY_EVERY + timedelta(minutes=self.rng.uniform(-8, 8))
            self.now = step_end
            ready = sorted((e for e in self._queue if _at(e) < self.now), key=_at)
            self._queue = [e for e in self._queue if _at(e) >= self.now]
            yield from ready

    # ── helpers ───────────────────────────────────────────────────────────

    def _flow(self, at, src, dst, dport, proto="TCP", packets=None, nbytes=None, flags="SAF", sport=None, duration=None):
        r = self.rng
        packets = packets if packets is not None else r.randint(6, 40)
        nbytes = nbytes if nbytes is not None else packets * r.randint(80, 1200)
        duration = duration if duration is not None else r.uniform(0.05, 6)
        self._queue.append(FlowRecord(
            start=at, end=at + timedelta(seconds=duration), src_ip=src, src_port=sport or r.randint(49152, 65535),
            dst_ip=dst, dst_port=dport, protocol=proto, packets=packets, bytes=nbytes,
            tcp_flags=flags if proto == "TCP" else "", src_country=country_of(src), dst_country=country_of(dst),
        ))

    def _log(self, at, host_ip, host, app, message, severity=4):
        self._queue.append(LogLine(at, host_ip, host, app, severity, message))

    def _rand_at(self, a: datetime, b: datetime) -> datetime:
        return a + timedelta(seconds=self.rng.uniform(0, max((b - a).total_seconds(), 0.001)))

    # ── normal traffic ────────────────────────────────────────────────────

    def _background(self, a: datetime, b: datetime) -> None:
        r = self.rng
        hour = a.hour
        # Busier in office hours (UTC, roughly), quiet at night.
        busy = 1.0 if 7 <= hour <= 18 else 0.35
        n = _poisson(r, self.rate * busy * (b - a).total_seconds())
        for _ in range(n):
            at = self._rand_at(a, b)
            ws = r.choice(WORKSTATIONS)
            kind = r.random()
            if kind < 0.45:  # web / SaaS over HTTPS
                self._flow(at, ws, r.choice(SAAS), 443, packets=r.randint(10, 300))
            elif kind < 0.65:  # DNS to the internal resolver
                self._flow(at, ws, DNS, 53, "UDP", packets=r.randint(1, 3), nbytes=r.randint(70, 240), duration=0.02)
            elif kind < 0.72:  # resolver forwarding upstream
                self._flow(at, DNS, "192.0.2.53", 53, "UDP", packets=r.randint(1, 4), nbytes=r.randint(80, 400), duration=0.03)
            elif kind < 0.82:  # file shares
                self._flow(at, ws, r.choice(FILE_SERVERS[:2]), 445, packets=r.randint(20, 400))
            elif kind < 0.88:  # domain controller (Kerberos/LDAP)
                self._flow(at, ws, DC, r.choice([88, 389, 445]), packets=r.randint(4, 30))
            elif kind < 0.93:  # inbound web traffic to the public site
                src = f"203.0.113.{r.randint(1, 254)}"
                self._flow(at, src, WEB, 443, packets=r.randint(8, 80))
            elif kind < 0.96:  # mail
                self._flow(at, f"198.51.100.{r.randint(1, 60)}", MAIL, 25, packets=r.randint(10, 60))
            elif kind < 0.98:  # admins on the jump host
                self._flow(at, r.choice(WORKSTATIONS[:3]), JUMP, 22, packets=r.randint(30, 600), duration=r.uniform(30, 300))
            else:  # NTP
                self._flow(at, ws, "192.0.2.123", 123, "UDP", packets=1, nbytes=76, duration=0.01)

    # ── the intrusion ─────────────────────────────────────────────────────

    def _story(self, t0: datetime) -> None:
        r = self.rng
        scanner = f"203.0.113.{r.randint(100, 199)}"
        brute = r.choice(["203.0.113.66", f"203.0.113.{r.randint(200, 250)}"])
        ssh_brute = f"198.51.100.{r.randint(120, 200)}"

        # 1. Scan of the public web server (t+0)
        ports = r.sample(range(1, 10000), 60) + [21, 22, 23, 25, 80, 443, 445, 3389, 8080]
        for i, p in enumerate(ports):
            self._flow(t0 + timedelta(seconds=i * 0.4), scanner, WEB, p, packets=1, nbytes=60, flags="S", duration=0.001)

        # 2a. RDP exposed on the gateway, brute-forced (t+1 min)
        t = t0 + timedelta(minutes=1)
        for i in range(40):
            self._flow(t + timedelta(seconds=i * 1.5), brute, RDP_GW, 3389, packets=r.randint(12, 24), nbytes=r.randint(2500, 5000))

        # 2b. SSH brute force on the jump host, with its auth log (t+2 min)
        t = t0 + timedelta(minutes=2)
        users = ["root", "admin", "ubuntu", "oracle", "test", "deploy", "git", "postgres"]
        for i in range(24):
            at = t + timedelta(seconds=i * 2.5)
            self._flow(at, ssh_brute, JUMP, 22, packets=r.randint(14, 22), nbytes=r.randint(2600, 4200))
            user = r.choice(users)
            self._log(at + timedelta(milliseconds=300), JUMP, "jump-01", "sshd",
                      f"Failed password for {'invalid user ' if user not in ('root', 'admin') else ''}{user} "
                      f"from {ssh_brute} port {r.randint(30000, 65000)} ssh2")

        # 3. The workstation is compromised (phishing, off-screen) and
        #    beacons to its command server every ~45 s for 20 minutes (t+4)
        t = t0 + timedelta(minutes=4)
        at = t
        while at < t + timedelta(minutes=20):
            self._flow(at, VICTIM, C2, 443, packets=r.randint(8, 12), nbytes=r.randint(1800, 2600), duration=0.4)
            at += timedelta(seconds=45 * r.uniform(0.97, 1.03))

        # 4a. Interactive session on 4444 (t+8)
        t = t0 + timedelta(minutes=8)
        self._flow(t, VICTIM, C2, 4444, packets=900, nbytes=410_000, duration=240)

        # 4b. DNS tunnelling burst through the resolver (t+10)
        t = t0 + timedelta(minutes=10)
        for i in range(260):
            self._flow(t + timedelta(seconds=i * 0.2), VICTIM, DNS, 53, "UDP", packets=1, nbytes=r.randint(180, 250), duration=0.01)

        # 5. Lateral movement to the file servers and DC (t+12)
        t = t0 + timedelta(minutes=12)
        for i, host in enumerate([*FILE_SERVERS, DC]):
            self._flow(t + timedelta(seconds=i * 9), VICTIM, host, 445, packets=r.randint(40, 120))
            if i % 2 == 0:
                self._flow(t + timedelta(seconds=i * 9 + 3), VICTIM, host, 3389, packets=r.randint(60, 300))
        self._log(t + timedelta(seconds=40), DC, "dc-01", "Security",
                  f"An account was successfully logged on. Account Name: svc-backup Source Network Address: {VICTIM} Logon Type: 3",
                  severity=5)

        # 6. Upload to the command server, 30-45 MB over ~4 minutes (t+16)
        t = t0 + timedelta(minutes=16)
        for i in range(24):
            self._flow(t + timedelta(seconds=i * 10), VICTIM, C2, 443, packets=r.randint(1200, 1600),
                       nbytes=r.randint(1_300_000, 1_900_000), duration=9)

        # An unrelated SYN flood against the website, some loops (t+25)
        if r.random() < 0.5:
            t = t0 + timedelta(minutes=25)
            for i in range(60):
                src = f"203.0.113.{r.randint(1, 254)}"
                self._flow(t + timedelta(seconds=i * 0.1), src, WEB, 443, packets=r.randint(40, 80), nbytes=3000, flags="S", duration=0.1)

        # Telnet left on an old device (t+30)
        if r.random() < 0.4:
            self._flow(t0 + timedelta(minutes=30), r.choice(WORKSTATIONS), "10.10.2.40", 23, packets=40)


def _at(e: Event) -> datetime:
    return e.start if isinstance(e, FlowRecord) else e.at


def _poisson(r: random.Random, lam: float) -> int:
    # Knuth's method; lam is small here.
    if lam <= 0:
        return 0
    if lam > 30:
        return max(0, round(r.gauss(lam, lam ** 0.5)))
    import math

    limit, k, p = math.exp(-lam), 0, 1.0
    while True:
        p *= r.random()
        if p <= limit:
            return k
        k += 1
