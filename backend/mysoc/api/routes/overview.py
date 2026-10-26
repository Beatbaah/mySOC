"""The landing view: queue health, what's attacking us, sensor status."""

from datetime import timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ...db import get_session, utcnow
from ...models import Alert, Case, Flow, SensorStatus
from .. import serialize as ser
from ..deps import Principal, viewer
from ..sqlutil import bucket, bucket_time

router = APIRouter(prefix="/api", tags=["overview"])

SEVS = ["critical", "high", "medium", "low", "info"]


def sensors(s: Session) -> list[dict]:
    now = utcnow()
    out = []
    for r in s.scalars(select(SensorStatus).order_by(SensorStatus.name)):
        out.append({
            "name": r.name,
            "source": r.source,
            "online": now - r.last_seen < timedelta(seconds=30),
            "lastSeen": ser.iso(r.last_seen),
            "startedAt": ser.iso(r.started_at),
            "stats": r.stats,
        })
    return out


@router.get("/overview")
def overview(hours: int = Query(default=24, ge=1, le=24 * 30), p: Principal = Depends(viewer), s: Session = Depends(get_session)):
    now = utcnow()
    since = now - timedelta(hours=hours)
    step = 3600 if hours > 6 else 600 if hours > 1 else 60

    open_by_sev = dict(s.execute(select(Alert.severity, func.count()).where(Alert.status != "closed").group_by(Alert.severity)).all())
    new_unassigned = s.scalar(select(func.count()).select_from(Alert).where(Alert.status == "new", Alert.assignee_id.is_(None)))
    in_period = s.scalar(select(func.count()).select_from(Alert).where(Alert.first_seen >= since))
    prev_period = s.scalar(
        select(func.count()).select_from(Alert).where(Alert.first_seen >= since - (now - since), Alert.first_seen < since)
    )

    # Mean time to close and the false-positive rate, over closed alerts in the period.
    closed = s.execute(
        select(Alert.first_seen, Alert.closed_at, Alert.disposition).where(Alert.closed_at >= since, Alert.closed_at.is_not(None))
    ).all()
    mttc = (
        sum((c - f).total_seconds() for f, c, _ in closed) / len(closed) / 60 if closed else None
    )
    fp_rate = sum(1 for *_, d in closed if d == "false_positive") / len(closed) if closed else None

    b = bucket(s, Alert.first_seen, step)
    timeline_rows = s.execute(
        select(b, Alert.severity, func.count()).where(Alert.first_seen >= since).group_by(b, Alert.severity)
    ).all()
    series: dict[int, dict] = {}
    first = int(since.timestamp()) // step + 1
    last = int(now.timestamp()) // step
    for n in range(first, last + 1):
        series[n] = {"t": bucket_time(n, step), **{sv: 0 for sv in SEVS}}
    for n, sev, cnt in timeline_rows:
        if n in series:
            series[n][sev] = cnt

    tactics = s.execute(
        select(Alert.mitre_tactic, func.count()).where(Alert.first_seen >= since, Alert.mitre_tactic != "").group_by(Alert.mitre_tactic)
    ).all()
    top_rules = s.execute(
        select(Alert.rule_id, func.min(Alert.title), func.count(), func.sum(Alert.count))
        .where(Alert.first_seen >= since).group_by(Alert.rule_id).order_by(func.count().desc()).limit(8)
    ).all()
    top_sources = s.execute(
        select(Alert.src_ip, func.min(Alert.src_country), func.count(), func.max(Alert.risk_score))
        .where(Alert.first_seen >= since, Alert.src_ip != "")
        .group_by(Alert.src_ip).order_by(func.max(Alert.risk_score).desc(), func.count().desc()).limit(8)
    ).all()
    countries = s.execute(
        select(Alert.src_country, func.count()).where(Alert.first_seen >= since, Alert.src_country != "").group_by(Alert.src_country)
    ).all()
    urgent = s.scalars(
        select(Alert).where(Alert.status != "closed", Alert.severity.in_(["critical", "high"]))
        .order_by(Alert.risk_score.desc(), Alert.last_seen.desc()).limit(6)
    ).all()

    flows_n, flows_bytes = s.execute(select(func.count(), func.coalesce(func.sum(Flow.bytes), 0)).where(Flow.start >= since)).one()
    cases = dict(s.execute(select(Case.status, func.count()).where(Case.status.notin_(["closed"])).group_by(Case.status)).all())

    return {
        "hours": hours,
        "kpis": {
            "openBySeverity": {sv: open_by_sev.get(sv, 0) for sv in SEVS},
            "openTotal": sum(open_by_sev.values()),
            "newUnassigned": new_unassigned,
            "alertsInPeriod": in_period,
            "alertsPrevPeriod": prev_period,
            "meanMinutesToClose": round(mttc, 1) if mttc is not None else None,
            "falsePositiveRate": round(fp_rate, 3) if fp_rate is not None else None,
            "flows": flows_n,
            "bytes": int(flows_bytes or 0),
            "openCases": sum(cases.values()),
            "casesByStatus": cases,
        },
        "timeline": list(series.values()),
        "stepSeconds": step,
        "tactics": [{"tactic": t, "count": n} for t, n in sorted(tactics, key=lambda x: -x[1])],
        "topRules": [{"ruleId": r, "title": t, "alerts": n, "events": int(e or 0)} for r, t, n, e in top_rules],
        "topSources": [{"ip": ip, "country": c, "alerts": n, "maxRisk": m} for ip, c, n, m in top_sources],
        "countries": [{"country": c, "alerts": n} for c, n in countries],
        "urgent": [ser.alert(a) for a in urgent],
        "sensors": sensors(s),
    }


@router.get("/status")
def status(p: Principal = Depends(viewer), s: Session = Depends(get_session)):
    """Small, cheap summary for the sidebar and live updates."""
    open_by_sev = dict(
        s.execute(select(Alert.severity, func.count()).where(Alert.status != "closed").group_by(Alert.severity)).all()
    )
    latest = s.scalar(select(func.max(Alert.id)))
    mine = s.scalar(select(func.count()).select_from(Alert).where(Alert.assignee_id == p.user.id, Alert.status != "closed"))
    return {
        "openBySeverity": {sv: open_by_sev.get(sv, 0) for sv in SEVS},
        "latestAlertId": latest or 0,
        "assignedToMe": mine,
        "sensors": sensors(s),
    }

