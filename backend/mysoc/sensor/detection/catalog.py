"""The built-in detection rules, mapped to MITRE ATT&CK.

Each rule's logic lives in detectors.py; what's here is the metadata and
the default thresholds, copied into the rules table on first run. After
that the table is the source of truth: analysts tune thresholds or turn
rules off from the console, and the sensor picks the change up live.
"""

from sqlalchemy import select

from ...db import session_scope
from ...models import Rule

BUILTIN_RULES: list[dict] = [
    {
        "id": "NET-001",
        "name": "Port scan",
        "severity": "medium",
        "description": "One source probed many ports on one host in a short window. From the internet this is "
        "usually background scanning; from inside the network it suggests a compromised host mapping targets, "
        "so internal sources are raised to high.",
        "mitre_tactic": "Discovery",
        "mitre_technique": "T1046",
        "params": {"distinct_ports": 20, "window_seconds": 60},
    },
    {
        "id": "NET-002",
        "name": "SYN flood",
        "severity": "critical",
        "description": "A burst of TCP connection attempts (SYN without completing the handshake) aimed at one host: "
        "a denial-of-service attack.",
        "mitre_tactic": "Impact",
        "mitre_technique": "T1498.001",
        "params": {"syn_packets": 2000, "window_seconds": 10},
    },
    {
        "id": "NET-003",
        "name": "ICMP flood",
        "severity": "high",
        "description": "An unusually high rate of ICMP (ping) traffic toward one host.",
        "mitre_tactic": "Impact",
        "mitre_technique": "T1498",
        "params": {"icmp_packets": 500, "window_seconds": 10},
    },
    {
        "id": "NET-004",
        "name": "Brute force on a login service",
        "severity": "high",
        "description": "Many separate connections from one source to a login service (SSH, RDP, SMB, FTP, "
        "databases) in a short window: password guessing.",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110",
        "params": {"connections": 15, "window_seconds": 60, "ports": [21, 22, 23, 445, 1433, 3306, 3389, 5432, 5900]},
    },
    {
        "id": "NET-005",
        "name": "DNS tunnelling",
        "severity": "medium",
        "description": "A host sent far more DNS traffic than normal browsing produces. Attackers hide command "
        "traffic or stolen data inside DNS queries because it's rarely blocked.",
        "mitre_tactic": "Command and Control",
        "mitre_technique": "T1071.004",
        "params": {"queries": 150, "window_seconds": 60},
    },
    {
        "id": "NET-006",
        "name": "Large outbound transfer",
        "severity": "critical",
        "description": "An internal host sent a large amount of data to one external address in a short time: "
        "possible data theft.",
        "mitre_tactic": "Exfiltration",
        "mitre_technique": "T1048",
        "params": {"bytes": 20_000_000, "window_seconds": 300},
    },
    {
        "id": "NET-007",
        "name": "Connection on a known attack-tool port",
        "severity": "medium",
        "description": "Traffic on a port commonly used by remote-access trojans and attack frameworks "
        "(e.g. 4444 for Metasploit).",
        "mitre_tactic": "Command and Control",
        "mitre_technique": "T1571",
        "params": {"ports": [1337, 4444, 5555, 6666, 6667, 12345, 31337, 54321]},
    },
    {
        "id": "NET-008",
        "name": "Remote access from the internet",
        "severity": "high",
        "description": "An external address connected to a remote-access service (RDP, SMB, WinRM, VNC, Telnet) "
        "on an internal host. These services shouldn't be reachable from the internet.",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1133",
        "params": {"ports": [23, 445, 3389, 5900, 5985, 5986]},
    },
    {
        "id": "NET-009",
        "name": "Beaconing",
        "severity": "high",
        "description": "An internal host contacted the same external address at near-regular intervals, the "
        "heartbeat pattern of malware checking in with its command server.",
        "mitre_tactic": "Command and Control",
        "mitre_technique": "T1071.001",
        "params": {"min_connections": 8, "max_jitter": 0.15, "lookback_seconds": 1800},
    },
    {
        "id": "NET-010",
        "name": "Traffic with a known-bad address",
        "severity": "high",
        "description": "Traffic to or from an address on the indicator (IOC) list.",
        "mitre_tactic": "Command and Control",
        "mitre_technique": "T1071",
        "params": {},
    },
    {
        "id": "NET-011",
        "name": "Lateral movement",
        "severity": "high",
        "description": "One internal host connected to admin services (SMB, RDP, WinRM, SSH) on many other "
        "internal hosts in a short time, as an attacker does when spreading through a network.",
        "mitre_tactic": "Lateral Movement",
        "mitre_technique": "T1021",
        "params": {"distinct_hosts": 5, "window_seconds": 300, "ports": [22, 135, 445, 3389, 5985, 5986]},
    },
    {
        "id": "LOG-001",
        "name": "Repeated failed logins in device logs",
        "severity": "high",
        "description": "A server or device logged many failed logins from one address.",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110",
        "params": {"failures": 8, "window_seconds": 120},
    },
    {
        "id": "ML-001",
        "name": "Unusual flow (machine learning)",
        "severity": "low",
        "description": "An Isolation Forest model trained on this network's recent traffic scored the flow as an "
        "outlier. Low severity on its own; useful context next to other alerts.",
        "mitre_tactic": "",
        "mitre_technique": "",
        "params": {"min_training_flows": 2000, "score_threshold": -0.2},
    },
]

# Field-condition rules, editable by analysts. Conditions are ANDed;
# supported keys are listed in detectors.MATCH_FIELDS.
MATCH_RULES: list[dict] = [
    {
        "id": "CUS-001",
        "name": "Telnet in use",
        "severity": "medium",
        "description": "Telnet sends passwords in clear text and shouldn't be used anywhere on the network.",
        "mitre_tactic": "Lateral Movement",
        "mitre_technique": "T1021",
        "params": {"conditions": {"protocol": "TCP", "dst_port": 23, "established": True}},
    },
    {
        "id": "CUS-002",
        "name": "Oversized NTP response",
        "severity": "medium",
        "description": "Large UDP responses from port 123: a sign of NTP amplification attacks using or "
        "targeting this network.",
        "mitre_tactic": "Impact",
        "mitre_technique": "T1498.002",
        "params": {"conditions": {"protocol": "UDP", "src_port": 123, "avg_packet_bytes_gt": 400}},
    },
]


def ensure_builtin_rules() -> None:
    with session_scope() as s:
        existing = set(s.scalars(select(Rule.id)))
        for kind, rules in (("builtin", BUILTIN_RULES), ("match", MATCH_RULES)):
            for r in rules:
                if r["id"] not in existing:
                    s.add(Rule(kind=kind, **r))
