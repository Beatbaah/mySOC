"""Entity pages (everything about one IP) and the asset inventory."""

from datetime import timedelta
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ... import audit
from ...config import get_settings
from ...db import get_session, utcnow
from ...models import Alert, Asset, Flow, Indicator, IntelCache, LogEvent
from ...sensor.netctx import NetContext
from .. import serialize as ser
from ..deps import Principal, analyst, viewer
from ..sqlutil import bucket, bucket_time, safe_like
from ..validate import ip_or_400

router = APIRouter(prefix="/api", tags=["entities"])

Criticality = Literal["low", "medium", "high", "critical"]


def _net() -> NetContext:
    st = get_settings()
    return NetContext(st.internal_networks, st.allowlist_ips)


@router.get("/entities/ip/{ip}")
def ip_entity(ip: str, hours: int = Query(default=24, ge=1, le=24 * 30), p: Principal = Depends(viewer), s: Session = Depends(get_session)):
    ip = ip_or_400(ip)
    since = utcnow() - timedelta(hours=hours)
    either = or_(Flow.src_ip == ip, Flow.dst_ip == ip)

    totals = s.execute(
        select(func.count(), func.coalesce(func.sum(Flow.bytes), 0), func.min(Flow.start), func.max(Flow.end))
        .where(either, Flow.start >= since)
    ).one()
    sent = s.scalar(select(func.coalesce(func.sum(Flow.bytes), 0)).where(Flow.src_ip == ip, Flow.start >= since))

    peers_out = s.execute(
        select(Flow.dst_ip, func.min(Flow.dst_country), func.count(), func.sum(Flow.bytes))
        .where(Flow.src_ip == ip, Flow.start >= since).group_by(Flow.dst_ip).order_by(func.sum(Flow.bytes).desc()).limit(15)
    ).all()
    peers_in = s.execute(
        select(Flow.src_ip, func.min(Flow.src_country), func.count(), func.sum(Flow.bytes))
        .where(Flow.dst_ip == ip, Flow.start >= since).group_by(Flow.src_ip).order_by(func.sum(Flow.bytes).desc()).limit(15)
    ).all()
    ports = s.execute(
        select(Flow.dst_port, Flow.protocol, func.count()).where(either, Flow.start >= since, Flow.dst_port < 49152)
        .group_by(Flow.dst_port, Flow.protocol).order_by(func.count().desc()).limit(12)
    ).all()
    step = 3600 if hours > 6 else 300
    b = bucket(s, Flow.start, step)
    activity = s.execute(
        select(b, func.count(), func.sum(Flow.bytes)).where(either, Flow.start >= since).group_by(b).order_by(b)
    ).all()

    alerts = s.scalars(
        select(Alert).where(or_(Alert.src_ip == ip, Alert.dst_ip == ip)).order_by(Alert.last_seen.desc()).limit(50)
    ).all()
    logs = s.scalars(
        select(LogEvent).where(or_(LogEvent.source_ip == ip, LogEvent.message.like(safe_like(ip))))
        .order_by(LogEvent.received_at.desc()).limit(30)
    ).all()
    asset = s.scalar(select(Asset).where(Asset.ip == ip))
    indicator = s.scalar(select(Indicator).where(Indicator.kind == "ip", Indicator.value == ip))
    intel = s.scalars(select(IntelCache).where(IntelCache.key.like(f"%:ip:{ip}"))).all()
    country = s.scalar(select(Flow.src_country).where(Flow.src_ip == ip, Flow.src_country != "").limit(1)) or s.scalar(
        select(Flow.dst_country).where(Flow.dst_ip == ip, Flow.dst_country != "").limit(1)
    )

    return {
        "ip": ip,
        "internal": _net().internal(ip),
        "country": country or "",
        "asset": ser.asset(asset) if asset else None,
        "indicator": ser.indicator(indicator) if indicator else None,
        "intel": {c.key.split(":", 1)[0]: {**c.data, "fetchedAt": ser.iso(c.fetched_at)} for c in intel},
        "traffic": {
            "flows": totals[0],
            "bytes": int(totals[1] or 0),
            "bytesSent": int(sent or 0),
            "firstSeen": ser.iso(totals[2]),
            "lastSeen": ser.iso(totals[3]),
            "peersOut": [{"ip": a, "country": c, "flows": n, "bytes": int(by or 0)} for a, c, n, by in peers_out],
            "peersIn": [{"ip": a, "country": c, "flows": n, "bytes": int(by or 0)} for a, c, n, by in peers_in],
            "ports": [{"port": po, "protocol": pr, "flows": n} for po, pr, n in ports],
            "activity": [{"t": bucket_time(n, step), "flows": c, "bytes": int(by or 0)} for n, c, by in activity],
            "stepSeconds": step,
        },
        "alerts": [ser.alert(a) for a in alerts],
        "logs": [ser.log_event(e) for e in logs],
    }


@router.get("/assets")
def list_assets(
    q: str | None = Query(default=None, max_length=100),
    criticality: list[Criticality] = Query(default=[]),
    limit: int = Query(default=500, ge=1, le=2000),
    p: Principal = Depends(viewer),
    s: Session = Depends(get_session),
):
    stmt = select(Asset)
    if q:
        like = safe_like(q)
        stmt = stmt.where(or_(Asset.ip.like(like), Asset.hostname.ilike(like), Asset.owner.ilike(like), Asset.os.ilike(like)))
    if criticality:
        stmt = stmt.where(Asset.criticality.in_(criticality))
    assets = s.scalars(stmt.order_by(Asset.ip).limit(limit)).all()
    ips = [a.ip for a in assets]
    open_alerts = dict(
        s.execute(
            select(Alert.dst_ip, func.count()).where(Alert.status != "closed", Alert.dst_ip.in_(ips)).group_by(Alert.dst_ip)
        ).all()
    ) if ips else {}
    as_source = dict(
        s.execute(
            select(Alert.src_ip, func.count()).where(Alert.status != "closed", Alert.src_ip.in_(ips)).group_by(Alert.src_ip)
        ).all()
    ) if ips else {}
    return {"items": [{**ser.asset(a), "openAlerts": open_alerts.get(a.ip, 0) + as_source.get(a.ip, 0)} for a in assets]}


class AssetUpdate(BaseModel):
    hostname: str | None = Field(default=None, max_length=255)
    owner: str | None = Field(default=None, max_length=120)
    criticality: Criticality | None = None
    os: str | None = Field(default=None, max_length=64)
    tags: list[str] | None = Field(default=None, max_length=20)


@router.patch("/assets/{ip}")
def update_asset(ip: str, body: AssetUpdate, p: Principal = Depends(analyst), s: Session = Depends(get_session)):
    ip = ip_or_400(ip)
    if not _net().internal(ip):
        raise HTTPException(400, "Only internal addresses can be tracked as assets.")
    a = s.scalar(select(Asset).where(Asset.ip == ip))
    if a is None:
        a = Asset(ip=ip)
        s.add(a)
    changes = body.model_dump(exclude_none=True)
    for k, v in changes.items():
        setattr(a, k, [t.strip()[:40] for t in v if t.strip()] if k == "tags" else v.strip() if isinstance(v, str) else v)
    audit.record(s, p.username, "asset_updated", "asset", ip, ip=p.ip, **changes)
    s.commit()
    return ser.asset(a)
