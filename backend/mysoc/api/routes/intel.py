"""Indicators of compromise and reputation lookups."""

import csv
import io
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ... import audit
from ...db import get_session
from ...intel.providers import lookup
from ...models import Alert, Flow, Indicator
from .. import serialize as ser
from ..deps import Principal, analyst, viewer
from ..sqlutil import safe_like
from ..validate import indicator_kind

router = APIRouter(prefix="/api", tags=["intel"])

Kind = Literal["ip", "domain", "hash", "url"]
MAX_IMPORT = 5000


@router.get("/indicators")
def list_indicators(
    kind: Kind | None = None,
    q: str | None = Query(default=None, max_length=200),
    limit: int = Query(default=500, ge=1, le=5000),
    p: Principal = Depends(viewer),
    s: Session = Depends(get_session),
):
    stmt = select(Indicator)
    if kind:
        stmt = stmt.where(Indicator.kind == kind)
    if q:
        like = safe_like(q)
        stmt = stmt.where(or_(Indicator.value.ilike(like), Indicator.threat.ilike(like), Indicator.source.ilike(like)))
    rows = s.scalars(stmt.order_by(Indicator.created_at.desc()).limit(limit)).all()
    # How often each IP indicator has actually been seen.
    ips = [i.value for i in rows if i.kind == "ip"]
    hits = dict(
        s.execute(
            select(Alert.dst_ip, func.sum(Alert.count)).where(Alert.rule_id == "NET-010", Alert.dst_ip.in_(ips)).group_by(Alert.dst_ip)
        ).all()
    ) if ips else {}
    hits_src = dict(
        s.execute(
            select(Alert.src_ip, func.sum(Alert.count)).where(Alert.rule_id == "NET-010", Alert.src_ip.in_(ips)).group_by(Alert.src_ip)
        ).all()
    ) if ips else {}
    total = s.scalar(select(func.count()).select_from(Indicator))
    return {
        "items": [{**ser.indicator(i), "hits": int(hits.get(i.value, 0) or 0) + int(hits_src.get(i.value, 0) or 0)} for i in rows],
        "total": total,
    }


class IndicatorIn(BaseModel):
    value: str = Field(min_length=3, max_length=2000)
    threat: str = Field(default="", max_length=120)
    confidence: int = Field(default=80, ge=0, le=100)
    expiresAt: datetime | None = None


@router.post("/indicators", status_code=201)
def add_indicator(body: IndicatorIn, p: Principal = Depends(analyst), s: Session = Depends(get_session)):
    parsed = indicator_kind(body.value)
    if not parsed:
        raise HTTPException(400, "Enter an IP address, domain, URL or file hash (MD5, SHA-1 or SHA-256).")
    if body.expiresAt is not None and body.expiresAt.tzinfo is None:
        raise HTTPException(400, "Expiry needs a timezone.")
    kind, value = parsed
    if s.scalar(select(Indicator.id).where(Indicator.kind == kind, Indicator.value == value)):
        raise HTTPException(409, "That indicator is already on the list.")
    i = Indicator(kind=kind, value=value, threat=body.threat.strip(), confidence=body.confidence,
                  source="manual", added_by=p.username, expires_at=body.expiresAt)
    s.add(i)
    audit.record(s, p.username, "indicator_added", "indicator", value[:64], ip=p.ip, kind=kind)
    s.commit()
    return ser.indicator(i)


class ImportIn(BaseModel):
    text: str = Field(max_length=2_000_000)
    source: str = Field(default="import", max_length=64)
    threat: str = Field(default="", max_length=120)


@router.post("/indicators/import")
def import_indicators(body: ImportIn, p: Principal = Depends(analyst), s: Session = Depends(get_session)):
    """One indicator per line, or CSV with value[,threat[,confidence]]."""
    added = skipped = invalid = 0
    existing = {(k, v) for k, v in s.execute(select(Indicator.kind, Indicator.value))}
    for row in csv.reader(io.StringIO(body.text)):
        if not row or not row[0].strip() or row[0].lstrip().startswith("#"):
            continue
        if added + skipped + invalid >= MAX_IMPORT:
            break
        parsed = indicator_kind(row[0])
        if not parsed:
            invalid += 1
            continue
        if parsed in existing:
            skipped += 1
            continue
        try:
            confidence = max(0, min(100, int(row[2]))) if len(row) > 2 and row[2].strip() else 70
        except ValueError:
            confidence = 70
        threat = (row[1].strip() if len(row) > 1 else "") or body.threat
        s.add(Indicator(kind=parsed[0], value=parsed[1], threat=threat[:120], confidence=confidence,
                        source=body.source.strip()[:64] or "import", added_by=p.username))
        existing.add(parsed)
        added += 1
    audit.record(s, p.username, "indicators_imported", ip=p.ip, added=added, skipped=skipped, invalid=invalid)
    s.commit()
    return {"added": added, "skipped": skipped, "invalid": invalid}


@router.delete("/indicators/{indicator_id}")
def delete_indicator(indicator_id: int, p: Principal = Depends(analyst), s: Session = Depends(get_session)):
    i = s.get(Indicator, indicator_id)
    if not i:
        raise HTTPException(404, "Indicator not found.")
    audit.record(s, p.username, "indicator_deleted", "indicator", i.value[:64], ip=p.ip, kind=i.kind)
    s.delete(i)
    s.commit()
    return {"ok": True}


@router.get("/intel/lookup")
def intel_lookup(
    value: str = Query(min_length=3, max_length=2000),
    refresh: bool = False,
    p: Principal = Depends(analyst),
    s: Session = Depends(get_session),
):
    parsed = indicator_kind(value)
    if not parsed:
        raise HTTPException(400, "Enter an IP address, domain, URL or file hash.")
    kind, value = parsed
    results = lookup(s, kind, value, refresh)
    listed = s.scalar(select(Indicator).where(Indicator.kind == kind, Indicator.value == value))
    seen = None
    if kind == "ip":
        seen = s.execute(
            select(func.count(), func.min(Flow.start), func.max(Flow.end)).where(or_(Flow.src_ip == value, Flow.dst_ip == value))
        ).one()
    audit.record(s, p.username, "intel_lookup", kind, value[:64], ip=p.ip)
    s.commit()
    return {
        "kind": kind,
        "value": value,
        "providers": results,
        "indicator": ser.indicator(listed) if listed else None,
        "seenLocally": {"flows": seen[0], "firstSeen": ser.iso(seen[1]), "lastSeen": ser.iso(seen[2])} if seen else None,
    }
