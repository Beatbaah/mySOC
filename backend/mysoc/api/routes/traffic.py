"""Network traffic: live summary, flow search, the geo view."""

from datetime import datetime, timedelta
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ...db import get_session, utcnow
from ...models import Flow
from .. import serialize as ser
from ..deps import Principal, viewer
from ..sqlutil import bucket, bucket_time
from ..validate import ip_or_400

router = APIRouter(prefix="/api/traffic", tags=["traffic"])


@router.get("/summary")
def summary(minutes: int = Query(default=60, ge=5, le=60 * 24 * 7), p: Principal = Depends(viewer), s: Session = Depends(get_session)):
    now = utcnow()
    since = now - timedelta(minutes=minutes)
    step = 60 if minutes <= 180 else 600 if minutes <= 60 * 24 else 3600
    b = bucket(s, Flow.start, step)
    rows = s.execute(
        select(b, func.count(), func.sum(Flow.bytes), func.sum(Flow.packets)).where(Flow.start >= since).group_by(b)
    ).all()
    found = {n: (c, by, pk) for n, c, by, pk in rows}
    series = []
    for n in range(int(since.timestamp()) // step + 1, int(now.timestamp()) // step + 1):
        c, by, pk = found.get(n, (0, 0, 0))
        series.append({"t": bucket_time(n, step), "flows": c, "bytes": int(by or 0), "packets": int(pk or 0)})

    def top(col, limit=10):
        return s.execute(
            select(col, func.count(), func.sum(Flow.bytes)).where(Flow.start >= since).group_by(col)
            .order_by(func.sum(Flow.bytes).desc()).limit(limit)
        ).all()

    protocols = s.execute(
        select(Flow.protocol, func.count(), func.sum(Flow.bytes)).where(Flow.start >= since).group_by(Flow.protocol)
    ).all()
    ports = s.execute(
        select(Flow.dst_port, Flow.protocol, func.count(), func.sum(Flow.bytes)).where(Flow.start >= since, Flow.dst_port < 49152)
        .group_by(Flow.dst_port, Flow.protocol).order_by(func.count().desc()).limit(12)
    ).all()
    countries_in = s.execute(
        select(Flow.src_country, func.count(), func.sum(Flow.bytes)).where(Flow.start >= since, Flow.src_country != "")
        .group_by(Flow.src_country)
    ).all()
    countries_out = s.execute(
        select(Flow.dst_country, func.count(), func.sum(Flow.bytes)).where(Flow.start >= since, Flow.dst_country != "")
        .group_by(Flow.dst_country)
    ).all()
    return {
        "minutes": minutes,
        "stepSeconds": step,
        "series": series,
        "topSources": [{"ip": ip, "flows": c, "bytes": int(by or 0)} for ip, c, by in top(Flow.src_ip)],
        "topDestinations": [{"ip": ip, "flows": c, "bytes": int(by or 0)} for ip, c, by in top(Flow.dst_ip)],
        "protocols": [{"protocol": pr, "flows": c, "bytes": int(by or 0)} for pr, c, by in protocols],
        "ports": [{"port": po, "protocol": pr, "flows": c, "bytes": int(by or 0)} for po, pr, c, by in ports],
        "countriesIn": [{"country": co, "flows": c, "bytes": int(by or 0)} for co, c, by in countries_in],
        "countriesOut": [{"country": co, "flows": c, "bytes": int(by or 0)} for co, c, by in countries_out],
    }


@router.get("/flows")
def flows(
    ip: str | None = Query(default=None, max_length=45),
    peer: str | None = Query(default=None, max_length=45),
    port: int | None = Query(default=None, ge=0, le=65535),
    protocol: Literal["TCP", "UDP", "ICMP", "OTHER"] | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    min_bytes: int | None = Query(default=None, ge=0),
    sort: Literal["start", "bytes", "packets"] = "start",
    limit: int = Query(default=200, ge=1, le=2000),
    p: Principal = Depends(viewer),
    s: Session = Depends(get_session),
):
    stmt = select(Flow)
    if ip:
        ip = ip_or_400(ip)
        stmt = stmt.where(or_(Flow.src_ip == ip, Flow.dst_ip == ip))
    if peer:
        peer = ip_or_400(peer)
        stmt = stmt.where(or_(Flow.src_ip == peer, Flow.dst_ip == peer))
    if port is not None:
        stmt = stmt.where(or_(Flow.dst_port == port, Flow.src_port == port))
    if protocol:
        stmt = stmt.where(Flow.protocol == protocol)
    for name, value in (("since", since), ("until", until)):
        if value is not None and value.tzinfo is None:
            raise HTTPException(400, f"`{name}` needs a timezone, e.g. 2026-10-24T12:00:00Z")
    since = since or utcnow() - timedelta(hours=24)
    stmt = stmt.where(Flow.start >= since)
    if until:
        stmt = stmt.where(Flow.start <= until)
    if min_bytes:
        stmt = stmt.where(Flow.bytes >= min_bytes)
    order = {"start": Flow.start.desc(), "bytes": Flow.bytes.desc(), "packets": Flow.packets.desc()}[sort]
    rows = s.scalars(stmt.order_by(order).limit(limit)).all()
    return {"items": [ser.flow(f) for f in rows]}
