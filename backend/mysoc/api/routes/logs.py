"""Device logs received over syslog."""

from datetime import timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ...db import get_session, utcnow
from ...models import LogEvent
from .. import serialize as ser
from ..deps import Principal, viewer
from ..sqlutil import safe_like

router = APIRouter(prefix="/api/logs", tags=["logs"])


@router.get("")
def search_logs(
    q: str | None = Query(default=None, max_length=200),
    host: str | None = Query(default=None, max_length=255),
    app: str | None = Query(default=None, max_length=64),
    max_severity: int = Query(default=7, ge=0, le=7, description="0 emergency … 7 debug"),
    hours: int = Query(default=24, ge=1, le=24 * 30),
    limit: int = Query(default=200, ge=1, le=2000),
    p: Principal = Depends(viewer),
    s: Session = Depends(get_session),
):
    stmt = select(LogEvent).where(LogEvent.received_at >= utcnow() - timedelta(hours=hours), LogEvent.severity <= max_severity)
    if q:
        stmt = stmt.where(LogEvent.message.ilike(safe_like(q)))
    if host:
        stmt = stmt.where(LogEvent.host == host)
    if app:
        stmt = stmt.where(LogEvent.app == app)
    rows = s.scalars(stmt.order_by(LogEvent.received_at.desc()).limit(limit)).all()
    facets_hosts = s.execute(
        select(LogEvent.host, func.count()).where(LogEvent.received_at >= utcnow() - timedelta(hours=hours))
        .group_by(LogEvent.host).order_by(func.count().desc()).limit(20)
    ).all()
    facets_apps = s.execute(
        select(LogEvent.app, func.count()).where(LogEvent.received_at >= utcnow() - timedelta(hours=hours))
        .group_by(LogEvent.app).order_by(func.count().desc()).limit(20)
    ).all()
    return {
        "items": [ser.log_event(e) for e in rows],
        "hosts": [{"value": h, "count": n} for h, n in facets_hosts],
        "apps": [{"value": a, "count": n} for a, n in facets_apps],
    }
