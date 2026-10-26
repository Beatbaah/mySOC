"""Cases: investigations that group alerts, with an owner and a timeline."""

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from ... import audit
from ...db import get_session, utcnow
from ...models import SEVERITIES, Alert, Case, CaseEvent, User
from .. import serialize as ser
from ..deps import Principal, analyst, viewer

router = APIRouter(prefix="/api/cases", tags=["cases"])

CaseStatus = Literal["open", "investigating", "contained", "resolved", "closed"]
Severity = Literal["info", "low", "medium", "high", "critical"]


def _counts(s: Session, ids: list[int]) -> dict[int, int]:
    if not ids:
        return {}
    rows = s.execute(select(Alert.case_id, func.count()).where(Alert.case_id.in_(ids)).group_by(Alert.case_id))
    return {cid: n for cid, n in rows}


def _owner(s: Session, owner_id: int | None) -> int | None:
    if not owner_id:
        return None
    u = s.get(User, owner_id)
    if not u or not u.is_active or u.role == "viewer":
        raise HTTPException(400, "That person can't own cases.")
    return u.id


@router.get("")
def list_cases(
    status: list[CaseStatus] = Query(default=[]),
    mine: bool = False,
    limit: int = Query(default=100, ge=1, le=500),
    p: Principal = Depends(viewer),
    s: Session = Depends(get_session),
):
    stmt = select(Case).options(selectinload(Case.owner))
    if status:
        stmt = stmt.where(Case.status.in_(status))
    if mine:
        stmt = stmt.where(Case.owner_id == p.user.id)
    rows = s.scalars(stmt.order_by(Case.updated_at.desc()).limit(limit)).all()
    counts = _counts(s, [c.id for c in rows])
    return {"items": [ser.case(c, counts.get(c.id, 0)) for c in rows]}


class CaseIn(BaseModel):
    title: str = Field(min_length=3, max_length=255)
    summary: str = Field(default="", max_length=20_000)
    severity: Severity = "medium"
    ownerId: int | None = None
    alertIds: list[int] = Field(default_factory=list, max_length=500)
    tags: list[str] = Field(default_factory=list, max_length=20)


@router.post("", status_code=201)
def create_case(body: CaseIn, p: Principal = Depends(analyst), s: Session = Depends(get_session)):
    c = Case(
        title=body.title.strip(),
        summary=body.summary,
        severity=body.severity,
        status="open",
        owner_id=_owner(s, body.ownerId) or p.user.id,
        created_by=p.username,
        tags=[t.strip()[:40] for t in body.tags if t.strip()],
    )
    s.add(c)
    s.flush()
    s.add(CaseEvent(case_id=c.id, actor=p.username, kind="created", body=f"Case opened by {p.username}"))
    if body.alertIds:
        _link(s, c, body.alertIds, p)
    audit.record(s, p.username, "case_created", "case", c.id, ip=p.ip, title=c.title)
    s.commit()
    return ser.case(c, len(body.alertIds))


def _link(s: Session, c: Case, alert_ids: list[int], p: Principal) -> int:
    alerts = s.scalars(select(Alert).where(Alert.id.in_(alert_ids))).all()
    for a in alerts:
        a.case_id = c.id
        if a.status == "new":
            a.status = "in_progress"
            a.assignee_id = a.assignee_id or c.owner_id
    if alerts:
        # The case is at least as severe as its worst alert.
        worst = max(alerts, key=lambda a: SEVERITIES.index(a.severity)).severity
        if SEVERITIES.index(worst) > SEVERITIES.index(c.severity):
            s.add(CaseEvent(case_id=c.id, actor="system", kind="severity", body=f"Severity raised to {worst} by a linked alert",
                            data={"from": c.severity, "to": worst}))
            c.severity = worst
        s.add(CaseEvent(
            case_id=c.id, actor=p.username, kind="alert_linked",
            body=f"Linked {len(alerts)} alert{'s' if len(alerts) != 1 else ''}",
            data={"alerts": [{"id": a.id, "title": a.title, "severity": a.severity} for a in alerts]},
        ))
        c.updated_at = utcnow()
    return len(alerts)


@router.get("/{case_id}")
def get_case(case_id: int, p: Principal = Depends(viewer), s: Session = Depends(get_session)):
    c = s.get(Case, case_id)
    if not c:
        raise HTTPException(404, "Case not found.")
    alerts = s.scalars(select(Alert).where(Alert.case_id == c.id).order_by(Alert.first_seen)).all()
    return {
        "case": ser.case(c, len(alerts)),
        "events": [ser.case_event(e) for e in c.events],
        "alerts": [ser.alert(a) for a in alerts],
    }


class CaseUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=255)
    summary: str | None = Field(default=None, max_length=20_000)
    severity: Severity | None = None
    status: CaseStatus | None = None
    ownerId: int | None = None
    tags: list[str] | None = Field(default=None, max_length=20)


@router.patch("/{case_id}")
def update_case(case_id: int, body: CaseUpdate, p: Principal = Depends(analyst), s: Session = Depends(get_session)):
    c = s.get(Case, case_id)
    if not c:
        raise HTTPException(404, "Case not found.")
    events = []
    if body.status and body.status != c.status:
        events.append(("status", f"Status changed from {c.status} to {body.status}", {"from": c.status, "to": body.status}))
        c.status = body.status
        c.resolved_at = utcnow() if body.status in ("resolved", "closed") else None
    if body.severity and body.severity != c.severity:
        events.append(("severity", f"Severity changed from {c.severity} to {body.severity}", {"from": c.severity, "to": body.severity}))
        c.severity = body.severity
    if body.ownerId is not None and body.ownerId != c.owner_id:
        owner = _owner(s, body.ownerId)
        name = s.get(User, owner).username if owner else "nobody"
        events.append(("owner", f"Assigned to {name}", {"ownerId": owner}))
        c.owner_id = owner
    if body.title is not None:
        c.title = body.title.strip()
    if body.summary is not None:
        c.summary = body.summary
    if body.tags is not None:
        c.tags = [t.strip()[:40] for t in body.tags if t.strip()]
    for kind, text, data in events:
        s.add(CaseEvent(case_id=c.id, actor=p.username, kind=kind, body=text, data=data))
    c.updated_at = utcnow()
    audit.record(s, p.username, "case_updated", "case", c.id, ip=p.ip, **body.model_dump(exclude_none=True, exclude={"summary"}))
    s.commit()
    s.refresh(c)
    return ser.case(c)


class NoteIn(BaseModel):
    body: str = Field(min_length=1, max_length=20_000)


@router.post("/{case_id}/notes", status_code=201)
def add_note(case_id: int, body: NoteIn, p: Principal = Depends(analyst), s: Session = Depends(get_session)):
    c = s.get(Case, case_id)
    if not c:
        raise HTTPException(404, "Case not found.")
    e = CaseEvent(case_id=c.id, actor=p.username, kind="note", body=body.body)
    s.add(e)
    c.updated_at = utcnow()
    s.commit()
    return ser.case_event(e)


class LinkIn(BaseModel):
    alertIds: list[int] = Field(min_length=1, max_length=500)


@router.post("/{case_id}/alerts")
def link_alerts(case_id: int, body: LinkIn, p: Principal = Depends(analyst), s: Session = Depends(get_session)):
    c = s.get(Case, case_id)
    if not c:
        raise HTTPException(404, "Case not found.")
    n = _link(s, c, body.alertIds, p)
    audit.record(s, p.username, "case_alerts_linked", "case", c.id, ip=p.ip, alerts=body.alertIds)
    s.commit()
    return {"linked": n}


@router.delete("/{case_id}/alerts/{alert_id}")
def unlink_alert(case_id: int, alert_id: int, p: Principal = Depends(analyst), s: Session = Depends(get_session)):
    a = s.get(Alert, alert_id)
    if not a or a.case_id != case_id:
        raise HTTPException(404, "That alert isn't part of this case.")
    a.case_id = None
    s.add(CaseEvent(case_id=case_id, actor=p.username, kind="alert_unlinked", body=f"Removed alert #{a.id}", data={"alertId": a.id}))
    audit.record(s, p.username, "case_alert_unlinked", "case", case_id, ip=p.ip, alert=a.id)
    s.commit()
    return {"ok": True}
