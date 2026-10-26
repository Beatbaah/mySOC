"""Shift handovers, reports, CSV export and live updates."""

import asyncio
import csv
import io
import json
from datetime import timedelta
from typing import Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from ... import audit
from ...db import get_session, session_scope, utcnow
from ...models import Alert, AuthSession, Case, Handover
from .. import serialize as ser
from ..deps import Principal, analyst, viewer
from .overview import SEVS, sensors

router = APIRouter(prefix="/api", tags=["operations"])


# ── shift handover ────────────────────────────────────────────────────────────


def _snapshot(s: Session, hours: int = 12) -> dict:
    since = utcnow() - timedelta(hours=hours)
    open_by_sev = dict(s.execute(select(Alert.severity, func.count()).where(Alert.status != "closed").group_by(Alert.severity)).all())
    urgent = s.scalars(
        select(Alert).where(Alert.status != "closed", Alert.severity.in_(["critical", "high"]))
        .order_by(Alert.risk_score.desc()).limit(10)
    ).all()
    cases = s.scalars(select(Case).where(Case.status.notin_(["resolved", "closed"])).order_by(Case.updated_at.desc()).limit(15)).all()
    closed = s.scalar(select(func.count()).select_from(Alert).where(Alert.closed_at >= since))
    new = s.scalar(select(func.count()).select_from(Alert).where(Alert.first_seen >= since))
    return {
        "hours": hours,
        "openBySeverity": {sv: open_by_sev.get(sv, 0) for sv in SEVS},
        "newAlerts": new,
        "closedAlerts": closed,
        "urgent": [{"id": a.id, "title": a.title, "severity": a.severity, "status": a.status, "riskScore": a.risk_score} for a in urgent],
        "openCases": [{"id": c.id, "title": c.title, "severity": c.severity, "status": c.status,
                       "owner": c.owner.username if c.owner else None} for c in cases],
        "sensors": [{"name": x["name"], "online": x["online"]} for x in sensors(s)],
    }


@router.get("/handovers")
def list_handovers(p: Principal = Depends(viewer), s: Session = Depends(get_session)):
    rows = s.scalars(select(Handover).order_by(Handover.created_at.desc()).limit(50)).all()
    return {"items": [ser.handover(h) for h in rows], "current": _snapshot(s)}


class HandoverIn(BaseModel):
    incoming: str = Field(default="", max_length=64)
    shift: Literal["day", "evening", "night", ""] = ""
    notes: str = Field(min_length=1, max_length=20_000)


@router.post("/handovers", status_code=201)
def create_handover(body: HandoverIn, p: Principal = Depends(analyst), s: Session = Depends(get_session)):
    h = Handover(author=p.username, incoming=body.incoming.strip(), shift=body.shift, notes=body.notes, snapshot=_snapshot(s))
    s.add(h)
    audit.record(s, p.username, "handover_created", "handover", "", ip=p.ip)
    s.commit()
    return ser.handover(h)


# ── reports ───────────────────────────────────────────────────────────────────


@router.get("/reports/summary")
def report(days: int = Query(default=7, ge=1, le=90), p: Principal = Depends(viewer), s: Session = Depends(get_session)):
    now = utcnow()
    since = now - timedelta(days=days)
    alerts = s.execute(
        select(Alert.first_seen, Alert.severity, Alert.status, Alert.disposition, Alert.closed_at, Alert.rule_id,
               Alert.mitre_tactic, Alert.src_ip, Alert.src_country, Alert.risk_score)
        .where(Alert.first_seen >= since)
    ).all()
    per_day: dict[str, dict] = {}
    for i in range(days, -1, -1):
        d = (now - timedelta(days=i)).date().isoformat()
        per_day[d] = {"date": d, **{sv: 0 for sv in SEVS}}
    disp = {"true_positive": 0, "false_positive": 0, "benign": 0, "open": 0}
    close_minutes = []
    by_rule: dict[str, int] = {}
    by_tactic: dict[str, int] = {}
    attackers: dict[str, list] = {}
    for first, sev, status, disposition, closed_at, rule, tactic, src, country, risk in alerts:
        day = first.date().isoformat()
        if day in per_day:
            per_day[day][sev] += 1
        disp[disposition if status == "closed" and disposition else "open"] += 1
        if closed_at:
            close_minutes.append((closed_at - first).total_seconds() / 60)
        by_rule[rule] = by_rule.get(rule, 0) + 1
        if tactic:
            by_tactic[tactic] = by_tactic.get(tactic, 0) + 1
        if src:
            a = attackers.setdefault(src, [country, 0, 0])
            a[1] += 1
            a[2] = max(a[2], risk)
    close_minutes.sort()
    cases_opened = s.scalar(select(func.count()).select_from(Case).where(Case.created_at >= since))
    cases_resolved = s.scalar(select(func.count()).select_from(Case).where(Case.resolved_at >= since))
    crit_high = sum(1 for a in alerts if a[1] in ("critical", "high"))
    tp = disp["true_positive"]
    # A simple 0-100 posture indicator for the executive summary: weighted
    # by confirmed serious incidents and how much of the queue is untouched.
    open_now = s.scalar(select(func.count()).select_from(Alert).where(Alert.status != "closed")) or 0
    risk = min(100, round(tp * 4 + crit_high * 0.5 + open_now * 0.3))
    return {
        "days": days,
        "totals": {
            "alerts": len(alerts),
            "criticalHigh": crit_high,
            "dispositions": disp,
            "medianMinutesToClose": round(close_minutes[len(close_minutes) // 2], 1) if close_minutes else None,
            "p90MinutesToClose": round(close_minutes[int(len(close_minutes) * 0.9)], 1) if close_minutes else None,
            "casesOpened": cases_opened,
            "casesResolved": cases_resolved,
            "riskIndex": risk,
        },
        "perDay": list(per_day.values()),
        "byRule": sorted(({"ruleId": k, "alerts": v} for k, v in by_rule.items()), key=lambda x: -x["alerts"])[:10],
        "byTactic": sorted(({"tactic": k, "alerts": v} for k, v in by_tactic.items()), key=lambda x: -x["alerts"]),
        "topSources": sorted(
            ({"ip": ip, "country": c, "alerts": n, "maxRisk": r} for ip, (c, n, r) in attackers.items()),
            key=lambda x: (-x["maxRisk"], -x["alerts"]),
        )[:10],
    }


def _cell(v) -> str:
    """CSV cell safe to open in a spreadsheet: values starting with a
    formula character are prefixed so they're shown, not executed."""
    text = "" if v is None else str(v)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


@router.get("/reports/alerts.csv")
def export_alerts(days: int = Query(default=7, ge=1, le=365), p: Principal = Depends(analyst), s: Session = Depends(get_session)):
    rows = s.scalars(select(Alert).where(Alert.first_seen >= utcnow() - timedelta(days=days)).order_by(Alert.first_seen)).all()
    buf = io.StringIO()
    w = csv.writer(buf)
    cols = ["id", "first_seen", "last_seen", "severity", "risk_score", "status", "disposition", "rule_id", "title",
            "src_ip", "dst_ip", "dst_port", "protocol", "mitre_tactic", "mitre_technique", "count", "case_id"]
    w.writerow(cols)
    for a in rows:
        w.writerow([_cell(getattr(a, c).isoformat() if c in ("first_seen", "last_seen") else getattr(a, c)) for c in cols])
    audit.record(s, p.username, "alerts_exported", ip=p.ip, days=days, rows=len(rows))
    s.commit()
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="mysoc-alerts-{days}d.csv"'},
    )


# ── live updates ──────────────────────────────────────────────────────────────


def _pulse(token_hash: str) -> dict | None:
    with session_scope() as s:
        sess = s.get(AuthSession, token_hash)
        if sess is None or sess.expires_at <= utcnow() or not sess.user.is_active:
            return None
        latest = s.scalar(select(func.max(Alert.id))) or 0
        open_by_sev = dict(s.execute(select(Alert.severity, func.count()).where(Alert.status != "closed").group_by(Alert.severity)).all())
        newest = s.scalars(select(Alert).where(Alert.id > latest - 20).order_by(Alert.id.desc()).limit(5)).all()
        return {
            "latestAlertId": latest,
            "openBySeverity": {sv: open_by_sev.get(sv, 0) for sv in SEVS},
            "newest": [{"id": a.id, "title": a.title, "severity": a.severity} for a in newest],
            "sensors": [{"name": x["name"], "online": x["online"], "flowsPerSecond": x["stats"].get("flows_per_second")} for x in sensors(s)],
        }


@router.get("/stream")
async def stream(request: Request, p: Principal = Depends(viewer), s: Session = Depends(get_session)):
    """Server-sent events: a small status message whenever something
    changes, plus a keep-alive. The console refetches what it shows. The
    session is re-checked on every tick, so signing out (or an admin
    disabling the account) ends the stream."""
    token_hash = p.session.token_hash
    s.commit()  # release the request's database connection for the stream's lifetime

    async def events():
        last = None
        ticks = 0
        while not await request.is_disconnected():
            data = await run_in_threadpool(_pulse, token_hash)
            if data is None:
                yield "event: expired\ndata: {}\n\n"
                return
            body = json.dumps(data, sort_keys=True)
            if body != last:
                yield f"event: pulse\ndata: {body}\n\n"
                last = body
            elif ticks % 5 == 0:
                yield ": keep-alive\n\n"
            ticks += 1
            await asyncio.sleep(3)

    return StreamingResponse(events(), media_type="text/event-stream", headers={"X-Accel-Buffering": "no"})

