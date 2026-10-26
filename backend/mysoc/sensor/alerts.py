"""Turning findings into alerts: deduplication and risk scoring.

A finding that matches an open alert (same rule and entities) seen within
the dedup window updates that alert's count and last-seen time instead of
creating another. One port scan is one alert, however long it runs.
"""

import math
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Alert, Asset
from .detection.detectors import Finding, RuleConfig

SEVERITY_BASE = {"info": 10, "low": 25, "medium": 45, "high": 65, "critical": 85}
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
CRITICALITY_BONUS = {"low": -5, "medium": 0, "high": 8, "critical": 15}


def risk_score(severity: str, count: int, asset_criticality: str | None, indicator_hit: bool) -> int:
    """0-100. Severity sets the base; repeated activity, an important
    target and a known-bad address push it up."""
    score = SEVERITY_BASE.get(severity, 25)
    score += min(10, round(4 * math.log10(max(count, 1))))
    score += CRITICALITY_BONUS.get(asset_criticality or "medium", 0)
    if indicator_hit:
        score += 10
    return max(0, min(100, score))


class AlertWriter:
    def __init__(self, dedup_minutes: int):
        self.window = timedelta(minutes=dedup_minutes)

    def write(self, s: Session, findings: list[Finding], rules: dict[str, RuleConfig], meta: dict[str, dict]) -> list[Alert]:
        """Store findings; returns alerts that are new (for notifications).
        `meta` maps rule id to its MITRE fields."""
        created: list[Alert] = []
        if not findings:
            return created
        criticality = self._criticality(s, findings)
        pending: dict[str, Alert] = {}
        for fd in findings:
            rule = rules.get(fd.rule_id)
            if rule is None:
                continue
            severity = fd.severity or rule.severity
            key = fd.dedup_key
            alert = pending.get(key) or s.scalar(
                select(Alert)
                .where(Alert.dedup_key == key, Alert.status != "closed", Alert.last_seen >= fd.at - self.window)
                .order_by(Alert.last_seen.desc())
                .limit(1)
            )
            target_crit = criticality.get(fd.dst_ip) or criticality.get(fd.src_ip)
            ioc = fd.rule_id == "NET-010"
            if alert is not None:
                alert.count += 1
                if fd.at > alert.last_seen:
                    alert.last_seen = fd.at
                if SEVERITY_ORDER.index(severity) > SEVERITY_ORDER.index(alert.severity):
                    alert.severity = severity
                alert.evidence = {**alert.evidence, **fd.evidence, "occurrences": alert.count}
                alert.risk_score = risk_score(alert.severity, alert.count, target_crit, ioc)
            else:
                m = meta.get(fd.rule_id, {})
                alert = Alert(
                    rule_id=fd.rule_id,
                    title=fd.title[:255],
                    description=fd.description,
                    severity=severity,
                    risk_score=risk_score(severity, 1, target_crit, ioc),
                    src_ip=fd.src_ip,
                    dst_ip=fd.dst_ip,
                    dst_port=fd.dst_port,
                    protocol=fd.protocol,
                    src_country=fd.src_country,
                    mitre_tactic=m.get("tactic", ""),
                    mitre_technique=m.get("technique", ""),
                    evidence=fd.evidence,
                    dedup_key=key,
                    count=1,
                    status="new",
                    first_seen=fd.at,
                    last_seen=fd.at,
                )
                s.add(alert)
                created.append(alert)
            pending[key] = alert
        return created

    @staticmethod
    def _criticality(s: Session, findings: list[Finding]) -> dict[str, str]:
        ips = {f.dst_ip for f in findings if f.dst_ip} | {f.src_ip for f in findings if f.src_ip}
        if not ips:
            return {}
        rows = s.execute(select(Asset.ip, Asset.criticality).where(Asset.ip.in_(ips)))
        return {ip: c for ip, c in rows}
