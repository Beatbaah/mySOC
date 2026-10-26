"""The alert queue: list, inspect, triage."""

from datetime import timedelta
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, selectinload

from ... import audit
from ...db import get_session, utcnow
from ...models import Alert, Asset, Case, CaseEvent, Flow, Indicator, User
from .. import serialize as ser
from ..deps import Principal, analyst, viewer

router = APIRouter(prefix="/api/alerts", tags=["alerts"])

Status = Literal["new", "in_progress", "closed"]
Severity = Literal["info", "low", "medium", "high", "critical"]
Disposition = Literal["true_positive", "false_positive", "benign"]
SORTS = {
    "last_seen": Alert.last_seen.desc(),
    "risk": Alert.risk_score.desc(),
    "first_seen": Alert.first_seen.desc(),
    "count": Alert.count.desc(),
}


@router.get("")
def list_alerts(
    status: list[Status] = Query(default=[]),
    severity: list[Severity] = Query(default=[]),
    rule: str | None = Query(default=None, max_length=32),
    q: str | None = Query(default=None, max_length=100),
    ip: str | None = Query(default=None, max_length=45),
    assignee: Literal["me", "unassigned"] | None = None,
    hours: int | None = Query(default=None, ge=1, le=24 * 365),
    sort: Literal["last_seen", "risk", "first_seen", "count"] = "last_seen",
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    p: Principal = Depends(viewer),
    s: Session = Depends(get_session),
):
    stmt = select(Alert)
    if status:
        stmt = stmt.where(Alert.status.in_(status))
    if severity:
        stmt = stmt.where(Alert.severity.in_(severity))
    if rule:
        stmt = stmt.where(Alert.rule_id == rule)
    if ip:
        stmt = stmt.where(or_(Alert.src_ip == ip, Alert.dst_ip == ip))
    if q:
        like = f"%{q.replace('%', '').replace('_', '')}%"
        stmt = stmt.where(or_(Alert.title.ilike(like), Alert.src_ip.ilike(like), Alert.dst_ip.ilike(like), Alert.rule_id.ilike(like)))
    if assignee == "me":
        stmt = stmt.where(Alert.assignee_id == p.user.id)
    elif assignee == "unassigned":
        stmt = stmt.where(Alert.assignee_id.is_(None))
    if hours:
        stmt = stmt.where(Alert.last_seen >= utcnow() - timedelta(hours=hours))
    total = s.scalar(select(func.count()).select_from(stmt.subquery()))
    rows = s.scalars(
        stmt.options(selectinload(Alert.assignee)).order_by(SORTS[sort], Alert.id.desc()).limit(limit).offset(offset)
    ).all()
    return {"items": [ser.alert(a) for a in rows], "total": total}


@router.get("/{alert_id}")
def get_alert(alert_id: int, p: Principal = Depends(viewer), s: Session = Depends(get_session)):
    a = s.get(Alert, alert_id)
    if not a:
        raise HTTPException(404, "Alert not found.")
    ips = [ip for ip in (a.src_ip, a.dst_ip) if ip]
    window_start, window_end = a.first_seen - timedelta(minutes=5), a.last_seen + timedelta(minutes=5)

    related = s.scalars(
        select(Alert)
        .where(Alert.id != a.id, or_(Alert.src_ip.in_(ips), Alert.dst_ip.in_(ips)), Alert.last_seen >= a.first_seen - timedelta(hours=24))
        .order_by(Alert.last_seen.desc())
        .limit(25)
    ).all()
    flows = []
    if a.src_ip:
        cond = Flow.src_ip == a.src_ip
        if a.dst_ip:
            cond = or_((Flow.src_ip == a.src_ip) & (Flow.dst_ip == a.dst_ip), (Flow.src_ip == a.dst_ip) & (Flow.dst_ip == a.src_ip))
        flows = s.scalars(
            select(Flow).where(cond, Flow.start >= window_start, Flow.start <= window_end).order_by(Flow.start.desc()).limit(100)
        ).all()
    assets = s.scalars(select(Asset).where(Asset.ip.in_(ips))).all() if ips else []
    indicators = s.scalars(select(Indicator).where(Indicator.kind == "ip", Indicator.value.in_(ips))).all() if ips else []
    c = s.get(Case, a.case_id) if a.case_id else None
    return {
        "alert": ser.alert(a),
        "related": [ser.alert(r) for r in related],
        "flows": [ser.flow(f) for f in flows],
        "assets": [ser.asset(x) for x in assets],
        "indicators": [ser.indicator(i) for i in indicators],
        "case": ser.case(c) if c else None,
    }


class AlertUpdate(BaseModel):
    status: Status | None = None
    disposition: Disposition | None = None
    assigneeId: int | None = Field(default=None, description="0 to unassign")


def _apply(s: Session, a: Alert, body: AlertUpdate, p: Principal) -> dict:
    changes: dict = {}
    if body.assigneeId is not None:
        if body.assigneeId == 0:
            a.assignee_id = None
        else:
            u = s.get(User, body.assigneeId)
            if not u or not u.is_active or u.role == "viewer":
                raise HTTPException(400, "That person can't be assigned alerts.")
            a.assignee_id = u.id
        changes["assignee"] = body.assigneeId or None
    if body.status is not None and body.status != a.status:
        if body.status == "closed" and not (body.disposition or a.disposition):
            raise HTTPException(400, "Choose a disposition (true positive, false positive or benign) to close an alert.")
        changes["status"] = [a.status, body.status]
        a.status = body.status
        if body.status == "closed":
            a.closed_at, a.closed_by = utcnow(), p.username
        else:
            a.closed_at = a.closed_by = None
        if body.status == "in_progress" and a.assignee_id is None:
            a.assignee_id = p.user.id
    if body.disposition is not None:
        a.disposition = body.disposition
        changes["disposition"] = body.disposition
    return changes


@router.patch("/{alert_id}")
def update_alert(alert_id: int, body: AlertUpdate, p: Principal = Depends(analyst), s: Session = Depends(get_session)):
    a = s.get(Alert, alert_id)
    if not a:
        raise HTTPException(404, "Alert not found.")
    changes = _apply(s, a, body, p)
    if changes:
        audit.record(s, p.username, "alert_updated", "alert", a.id, ip=p.ip, **changes)
        if a.case_id:
            s.add(CaseEvent(case_id=a.case_id, actor=p.username, kind="alert_updated",
                            body=f"Alert #{a.id} updated", data={"alertId": a.id, **changes}))
    s.commit()
    s.refresh(a)
    return ser.alert(a)


class BulkUpdate(AlertUpdate):
    ids: list[int] = Field(min_length=1, max_length=500)


@router.post("/bulk")
def bulk_update(body: BulkUpdate, p: Principal = Depends(analyst), s: Session = Depends(get_session)):
    alerts = s.scalars(select(Alert).where(Alert.id.in_(body.ids))).all()
    for a in alerts:
        _apply(s, a, body, p)
    audit.record(s, p.username, "alerts_bulk_updated", "alert", ",".join(str(a.id) for a in alerts)[:64], ip=p.ip,
                 count=len(alerts), **body.model_dump(exclude={"ids"}, exclude_none=True))
    s.commit()
    return {"updated": len(alerts)}
