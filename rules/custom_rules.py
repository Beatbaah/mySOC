"""
rules/custom_rules.py — YAML-defined custom detection rules engine.

Rule format (YAML):
  id: MY_RULE_001
  name: "Suspicious Outbound DNS"
  enabled: true
  severity: HIGH
  description: "Large DNS response from external resolver"
  conditions:
    protocol: UDP
    dst_port: 53
    length_gt: 512
  action: alert
  tags: [dns, exfil]

Conditions supported:
  src_ip, dst_ip, src_port, dst_port, protocol,
  length_gt, length_lt, flags_contains,
  src_is_internal, dst_is_internal,
  src_in_list, dst_in_list   (comma-separated IP list)
"""

import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from utils.helpers import is_internal
from utils.logger import get_logger
from db import database as db

log = get_logger(__name__)

RULES_DIR  = Path("rules")
RULES_FILE = RULES_DIR / "custom_rules.yaml"

_rules_cache:     List[Dict] = []
_rules_cache_mtime: float    = 0.0


def _load_yaml_safe(text: str) -> Any:
    try:
        import yaml  # type: ignore
        return yaml.safe_load(text)
    except ImportError:
        # Minimal YAML fallback — only handles simple key: value
        log.warning("PyYAML not installed; using minimal YAML parser")
        return _minimal_yaml(text)


def _minimal_yaml(text: str) -> Any:
    """Bare-bones YAML parser for key: value and lists only."""
    result: Any = None
    current: Dict = {}
    items: List[Dict] = []
    in_conditions = False
    in_tags       = False
    tags: List    = []

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("- id:") or stripped.startswith("id:"):
            if current:
                items.append(current)
            current      = {}
            in_conditions = False
            in_tags       = False
            tags          = []
            key, _, val = stripped.lstrip("- ").partition(":")
            current[key.strip()] = val.strip()
        elif stripped == "conditions:":
            current["conditions"] = {}
            in_conditions = True
            in_tags       = False
        elif stripped.startswith("tags:"):
            in_conditions = False
            in_tags       = True
        elif in_tags and stripped.startswith("- "):
            tags.append(stripped[2:].strip())
            current["tags"] = tags
        elif in_conditions and ":" in stripped:
            k, _, v = stripped.partition(":")
            current["conditions"][k.strip()] = _coerce(v.strip())
            in_tags = False
        elif ":" in stripped:
            in_conditions = False
            in_tags       = False
            k, _, v = stripped.partition(":")
            current[k.strip()] = _coerce(v.strip())

    if current:
        items.append(current)
    return items if items else result


def _coerce(v: str) -> Any:
    if v.lower() in ("true", "yes"):
        return True
    if v.lower() in ("false", "no"):
        return False
    try:
        return int(v)
    except ValueError:
        pass
    try:
        return float(v)
    except ValueError:
        pass
    return v


# ── Rule storage ───────────────────────────────────────────────────────────────

def ensure_rules_dir() -> None:
    RULES_DIR.mkdir(parents=True, exist_ok=True)
    if not RULES_FILE.exists():
        _write_default_rules()


def _write_default_rules() -> None:
    defaults = """\
# MY SOC Custom Detection Rules
# Each rule is a YAML list item.

- id: CUSTOM_001
  name: "Telnet Access Attempt"
  enabled: true
  severity: HIGH
  description: "Telnet (port 23) traffic detected — unencrypted remote access"
  conditions:
    dst_port: 23
  tags: [lateral_movement, cleartext]

- id: CUSTOM_002
  name: "SMB from External"
  enabled: true
  severity: CRITICAL
  description: "SMB traffic from an external IP — potential ransomware / lateral movement"
  conditions:
    dst_port: 445
    src_is_internal: false
  tags: [ransomware, smb]

- id: CUSTOM_003
  name: "Large Outbound Packet"
  enabled: true
  severity: MEDIUM
  description: "Single outbound packet exceeds 8 KB — possible data staging"
  conditions:
    length_gt: 8192
    src_is_internal: true
  tags: [exfil]

- id: CUSTOM_004
  name: "NTP Amplification Candidate"
  enabled: true
  severity: MEDIUM
  description: "Large UDP packet from port 123 — possible NTP amplification"
  conditions:
    protocol: UDP
    src_port: 123
    length_gt: 400
  tags: [ddos, amplification]
"""
    RULES_FILE.write_text(defaults)
    log.info("Default custom rules written to %s", RULES_FILE)


def load_rules(force: bool = False) -> List[Dict]:
    global _rules_cache, _rules_cache_mtime

    ensure_rules_dir()
    try:
        mtime = RULES_FILE.stat().st_mtime
    except FileNotFoundError:
        return []

    if not force and mtime == _rules_cache_mtime:
        return _rules_cache

    try:
        text  = RULES_FILE.read_text()
        rules = _load_yaml_safe(text) or []
        if not isinstance(rules, list):
            rules = [rules]
        _rules_cache       = [r for r in rules if isinstance(r, dict)]
        _rules_cache_mtime = mtime
        log.info("Loaded %d custom rules", len(_rules_cache))
    except Exception as e:
        log.error("Failed to load custom rules: %s", e)
        _rules_cache = []

    return _rules_cache


def save_rules(rules: List[Dict]) -> None:
    ensure_rules_dir()
    try:
        import yaml  # type: ignore
        text = yaml.dump(rules, default_flow_style=False, allow_unicode=True)
    except ImportError:
        # Fallback serialization
        lines = []
        for r in rules:
            lines.append(f"- id: {r.get('id', 'UNKNOWN')}")
            for k, v in r.items():
                if k == "id":
                    continue
                if k == "conditions" and isinstance(v, dict):
                    lines.append(f"  conditions:")
                    for ck, cv in v.items():
                        lines.append(f"    {ck}: {cv}")
                elif k == "tags" and isinstance(v, list):
                    lines.append(f"  tags:")
                    for t in v:
                        lines.append(f"    - {t}")
                else:
                    lines.append(f"  {k}: {v}")
            lines.append("")
        text = "\n".join(lines)

    RULES_FILE.write_text(text)
    load_rules(force=True)
    log.info("Custom rules saved (%d rules)", len(rules))


def get_rules_text() -> str:
    ensure_rules_dir()
    return RULES_FILE.read_text() if RULES_FILE.exists() else ""


def save_rules_text(text: str) -> Tuple_or_error:
    """Save raw YAML text; returns (ok, error_msg)."""
    try:
        parsed = _load_yaml_safe(text)
        if parsed is None:
            parsed = []
        RULES_FILE.write_text(text)
        load_rules(force=True)
        return True, ""
    except Exception as e:
        return False, str(e)


# Workaround for missing Tuple import in save_rules_text type hint
from typing import Tuple
Tuple_or_error = Tuple[bool, str]


# ── Rule evaluation ────────────────────────────────────────────────────────────

def _match_condition(pkt, key: str, value: Any) -> bool:
    """Evaluate a single condition against a packet."""
    try:
        if key == "src_ip":
            return pkt.src_ip == str(value)
        if key == "dst_ip":
            return pkt.dst_ip == str(value)
        if key == "src_port":
            return pkt.src_port == int(value)
        if key == "dst_port":
            return pkt.dst_port == int(value)
        if key == "protocol":
            return pkt.protocol.upper() == str(value).upper()
        if key == "length_gt":
            return pkt.length > int(value)
        if key == "length_lt":
            return pkt.length < int(value)
        if key == "flags_contains":
            return str(value) in (pkt.flags or "")
        if key == "src_is_internal":
            return is_internal(pkt.src_ip) == bool(value)
        if key == "dst_is_internal":
            return is_internal(pkt.dst_ip) == bool(value)
        if key == "src_in_list":
            ip_list = [ip.strip() for ip in str(value).split(",")]
            return pkt.src_ip in ip_list
        if key == "dst_in_list":
            ip_list = [ip.strip() for ip in str(value).split(",")]
            return pkt.dst_ip in ip_list
    except Exception as e:
        log.debug("Condition eval error (%s=%s): %s", key, value, e)
    return False


def evaluate(pkt) -> List[Dict]:
    """
    Evaluate all enabled custom rules against a packet.
    Returns list of fired rule dicts (with added match metadata).
    """
    fired = []
    for rule in load_rules():
        if not rule.get("enabled", True):
            continue
        conditions = rule.get("conditions", {})
        if not conditions:
            continue
        # ALL conditions must match (AND logic)
        if all(_match_condition(pkt, k, v) for k, v in conditions.items()):
            result = dict(rule)
            result["matched_pkt"] = {
                "src_ip": pkt.src_ip, "dst_ip": pkt.dst_ip,
                "src_port": pkt.src_port, "dst_port": pkt.dst_port,
                "protocol": pkt.protocol, "length": pkt.length,
            }
            fired.append(result)
            # Persist alert
            db.insert_alert({
                "severity":    rule.get("severity", "MEDIUM"),
                "alert_type":  f"CUSTOM_{rule.get('id', 'RULE')}",
                "src_ip":      pkt.src_ip,
                "dst_ip":      pkt.dst_ip,
                "src_port":    pkt.src_port,
                "dst_port":    pkt.dst_port,
                "protocol":    pkt.protocol,
                "description": rule.get("description", rule.get("name", "")),
                "raw_data":    f"rule_id={rule.get('id')}",
                "threat_score": {"CRITICAL": 90, "HIGH": 70,
                                 "MEDIUM": 50, "LOW": 25}.get(
                    rule.get("severity", "MEDIUM"), 50
                ),
            })
    return fired
