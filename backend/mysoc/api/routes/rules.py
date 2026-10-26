"""Detection rules: view, tune, enable/disable, and write match rules."""

import re
from datetime import timedelta
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from ... import audit
from ...db import get_session, utcnow
from ...models import Alert, Rule
from ...sensor.detection.catalog import BUILTIN_RULES, MATCH_RULES
from ...sensor.detection.detectors import MATCH_FIELDS
from .. import serialize as ser
from ..deps import Principal, admin, viewer

router = APIRouter(prefix="/api/rules", tags=["rules"])

Severity = Literal["info", "low", "medium", "high", "critical"]
_DEFAULTS = {r["id"]: r["params"] for r in BUILTIN_RULES + MATCH_RULES}
_TECHNIQUE = re.compile(r"^(T\d{4}(\.\d{3})?)?$")


@router.get("")
def list_rules(p: Principal = Depends(viewer), s: Session = Depends(get_session)):
    since = utcnow() - timedelta(days=7)
    stats = {
        rid: {"alerts7d": n, "falsePositives7d": int(fp or 0), "lastAlert": ser.iso(last)}
        for rid, n, fp, last in s.execute(
            select(
                Alert.rule_id, func.count(),
                func.sum(case((Alert.disposition == "false_positive", 1), else_=0)),
                func.max(Alert.last_seen),
            ).where(Alert.first_seen >= since).group_by(Alert.rule_id)
        )
    }
    rules = s.scalars(select(Rule).order_by(Rule.id)).all()
    return {"items": [ser.rule(r, stats.get(r.id)) for r in rules], "matchFields": MATCH_FIELDS}


def _check_params(rule: Rule, params: dict) -> dict:
    """Built-in rules: only the existing keys, with the same types, within
    sane bounds. Match rules: only known condition fields."""
    if rule.kind == "match":
        cond = params.get("conditions")
        _check_conditions(cond)
        return {"conditions": cond}
    defaults = _DEFAULTS.get(rule.id, rule.params)
    out = dict(rule.params)
    for k, v in params.items():
        if k not in defaults:
            raise HTTPException(400, f"{rule.id} has no parameter {k!r}.")
        d = defaults[k]
        if isinstance(d, list):
            if not isinstance(v, list) or not all(isinstance(x, int) and 0 <= x <= 65535 for x in v) or len(v) > 100:
                raise HTTPException(400, f"{k} must be a list of port numbers.")
        elif isinstance(d, float):
            if not isinstance(v, int | float) or not -10 <= v <= 10:
                raise HTTPException(400, f"{k} must be a number.")
            v = float(v)
        elif isinstance(d, int):
            if not isinstance(v, int) or isinstance(v, bool) or not 1 <= v <= 10**12:
                raise HTTPException(400, f"{k} must be a positive whole number.")
        out[k] = v
    return out


def _check_conditions(cond) -> None:
    if not isinstance(cond, dict) or not cond:
        raise HTTPException(400, "A match rule needs at least one condition.")
    for k, v in cond.items():
        if k not in MATCH_FIELDS:
            raise HTTPException(400, f"Unknown condition {k!r}. Use: {', '.join(MATCH_FIELDS)}.")
        if k in ("src_internal", "dst_internal", "established") and not isinstance(v, bool):
            raise HTTPException(400, f"{k} must be true or false.")
        if k in ("src_port", "dst_port") and not (isinstance(v, int) and 0 <= v <= 65535):
            raise HTTPException(400, f"{k} must be a port number.")
        if k.endswith("_gt") and not (isinstance(v, int) and v >= 0):
            raise HTTPException(400, f"{k} must be a whole number.")
        if k == "protocol" and str(v).upper() not in ("TCP", "UDP", "ICMP"):
            raise HTTPException(400, "protocol must be TCP, UDP or ICMP.")


class RuleUpdate(BaseModel):
    enabled: bool | None = None
    severity: Severity | None = None
    params: dict | None = None


@router.patch("/{rule_id}")
def update_rule(rule_id: str, body: RuleUpdate, p: Principal = Depends(admin), s: Session = Depends(get_session)):
    r = s.get(Rule, rule_id)
    if not r:
        raise HTTPException(404, "Rule not found.")
    before = {"enabled": r.enabled, "severity": r.severity, "params": r.params}
    if body.enabled is not None:
        r.enabled = body.enabled
    if body.severity is not None:
        r.severity = body.severity
    if body.params is not None:
        r.params = _check_params(r, body.params)
    r.updated_at, r.updated_by = utcnow(), p.username
    audit.record(s, p.username, "rule_updated", "rule", r.id, ip=p.ip, before=before,
                 after={"enabled": r.enabled, "severity": r.severity, "params": r.params})
    s.commit()
    return ser.rule(r)


class MatchRuleIn(BaseModel):
    name: str = Field(min_length=3, max_length=120)
    description: str = Field(default="", max_length=2000)
    severity: Severity = "medium"
    mitreTactic: str = Field(default="", max_length=64)
    mitreTechnique: str = Field(default="", max_length=16)
    conditions: dict


@router.post("", status_code=201)
def create_rule(body: MatchRuleIn, p: Principal = Depends(admin), s: Session = Depends(get_session)):
    _check_conditions(body.conditions)
    if not _TECHNIQUE.match(body.mitreTechnique):
        raise HTTPException(400, "MITRE technique looks like T1046 or T1071.004.")
    ids = [int(i[4:]) for i in s.scalars(select(Rule.id).where(Rule.id.like("CUS-%"))) if i[4:].isdigit()]
    r = Rule(
        id=f"CUS-{max(ids, default=0) + 1:03d}", name=body.name.strip(), kind="match", enabled=True, severity=body.severity,
        description=body.description.strip(), mitre_tactic=body.mitreTactic.strip(), mitre_technique=body.mitreTechnique,
        params={"conditions": body.conditions}, updated_by=p.username,
    )
    s.add(r)
    audit.record(s, p.username, "rule_created", "rule", r.id, ip=p.ip, conditions=body.conditions)
    s.commit()
    return ser.rule(r)


@router.delete("/{rule_id}")
def delete_rule(rule_id: str, p: Principal = Depends(admin), s: Session = Depends(get_session)):
    r = s.get(Rule, rule_id)
    if not r:
        raise HTTPException(404, "Rule not found.")
    if r.kind != "match":
        raise HTTPException(400, "Built-in rules can be turned off but not deleted.")
    audit.record(s, p.username, "rule_deleted", "rule", r.id, ip=p.ip)
    s.delete(r)
    s.commit()
    return {"ok": True}
