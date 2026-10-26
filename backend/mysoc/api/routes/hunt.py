"""Threat hunting: pre-built, parameterised hunts over stored flows.

Analysts pick a hunt and tune its parameters; there's no free-form SQL,
so a hunt can't read tables it shouldn't or run unbounded queries.
"""

import statistics
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import distinct, func, select
from sqlalchemy.orm import Session

from ... import audit
from ...config import get_settings
from ...db import get_session, utcnow
from ...models import Flow
from ...sensor.netctx import NetContext
from ..deps import Principal, analyst, viewer

router = APIRouter(prefix="/api/hunts", tags=["hunt"])

COMMON_PORTS = {22, 25, 53, 80, 123, 443, 465, 587, 853, 993, 995}

HUNTS = {
    "beaconing": {
        "name": "Regular check-ins (beaconing)",
        "question": "Which internal hosts contact an external address at suspiciously regular intervals?",
        "mitre": "T1071",
        "params": {"hours": 6, "min_connections": 8, "max_jitter": 0.2},
        "columns": [("src", "Internal host", "ip"), ("dst", "External address", "ip"), ("port", "Port", "int"),
                    ("connections", "Connections", "int"), ("interval", "Every (s)", "num"), ("jitter", "Jitter", "pct")],
    },
    "rare_destinations": {
        "name": "Rare external destinations",
        "question": "Which external addresses did only one internal host talk to? Command servers usually have one victim.",
        "mitre": "T1071",
        "params": {"hours": 24, "min_flows": 3},
        "columns": [("dst", "External address", "ip"), ("country", "Country", "country"), ("src", "Only host", "ip"),
                    ("flows", "Flows", "int"), ("bytes", "Bytes", "bytes")],
    },
    "large_uploads": {
        "name": "Large uploads",
        "question": "Which internal hosts sent the most data out to a single external address?",
        "mitre": "T1048",
        "params": {"hours": 24, "min_mb": 5},
        "columns": [("src", "Internal host", "ip"), ("dst", "External address", "ip"), ("country", "Country", "country"),
                    ("bytes", "Sent", "bytes"), ("flows", "Flows", "int")],
    },
    "unusual_ports": {
        "name": "Outbound on unusual ports",
        "question": "Which internal hosts connect out on ports that normal web, mail and DNS traffic doesn't use?",
        "mitre": "T1571",
        "params": {"hours": 24},
        "columns": [("src", "Internal host", "ip"), ("dst", "External address", "ip"), ("port", "Port", "int"),
                    ("protocol", "Protocol", "text"), ("flows", "Flows", "int"), ("bytes", "Bytes", "bytes")],
    },
    "dns_heavy": {
        "name": "Heaviest DNS users",
        "question": "Which hosts send the most DNS queries? Outliers can mean tunnelling or malware.",
        "mitre": "T1071.004",
        "params": {"hours": 24},
        "columns": [("src", "Host", "ip"), ("queries", "Queries", "int"), ("avg_bytes", "Avg bytes", "num"),
                    ("resolvers", "Resolvers", "int")],
    },
    "internal_fanout": {
        "name": "Internal hosts touching many others",
        "question": "Which internal hosts connected to unusually many other internal hosts or ports?",
        "mitre": "T1021 / T1046",
        "params": {"hours": 24, "min_hosts": 5},
        "columns": [("src", "Internal host", "ip"), ("hosts", "Hosts reached", "int"), ("ports", "Distinct ports", "int"),
                    ("flows", "Flows", "int")],
    },
    "new_countries": {
        "name": "New destination countries",
        "question": "Which countries did we send traffic to recently that we hadn't in the week before?",
        "mitre": "",
        "params": {"hours": 24},
        "columns": [("country", "Country", "country"), ("hosts", "Internal hosts", "int"), ("flows", "Flows", "int"),
                    ("bytes", "Bytes", "bytes")],
    },
}

LIMITS = {"hours": (1, 24 * 7), "min_connections": (3, 1000), "max_jitter": (0.01, 1.0), "min_flows": (1, 10000),
          "min_mb": (1, 100_000), "min_hosts": (2, 1000)}


def _net() -> NetContext:
    st = get_settings()
    return NetContext(st.internal_networks, st.allowlist_ips)


def _hunt_out(hid: str) -> dict:
    h = HUNTS[hid]
    return {"id": hid, "name": h["name"], "question": h["question"], "mitre": h["mitre"], "params": h["params"],
            "columns": [{"key": k, "label": label, "type": t} for k, label, t in h["columns"]]}


@router.get("")
def list_hunts(p: Principal = Depends(viewer)):
    return {"items": [_hunt_out(h) for h in HUNTS]}


class RunIn(BaseModel):
    params: dict[str, float] = Field(default_factory=dict)


@router.post("/{hunt_id}/run")
def run_hunt(hunt_id: str, body: RunIn, p: Principal = Depends(analyst), s: Session = Depends(get_session)):
    if hunt_id not in HUNTS:
        raise HTTPException(404, "No such hunt.")
    params = dict(HUNTS[hunt_id]["params"])
    for k, v in body.params.items():
        if k not in params:
            raise HTTPException(400, f"Unknown parameter {k!r}.")
        lo, hi = LIMITS[k]
        if not lo <= v <= hi:
            raise HTTPException(400, f"{k} must be between {lo} and {hi}.")
        params[k] = v
    since = utcnow() - timedelta(hours=params["hours"])
    rows = RUNNERS[hunt_id](s, since, params, _net())
    audit.record(s, p.username, "hunt_run", "hunt", hunt_id, ip=p.ip, params=params, results=len(rows))
    s.commit()
    return {**_hunt_out(hunt_id), "params": params, "rows": rows[:500]}


def _beaconing(s, since, params, net):
    cands = s.execute(
        select(Flow.src_ip, Flow.dst_ip, Flow.dst_port, func.count())
        .where(Flow.start >= since, Flow.dst_port != 53)
        .group_by(Flow.src_ip, Flow.dst_ip, Flow.dst_port)
        .having(func.count() >= params["min_connections"])
        .order_by(func.count().desc()).limit(400)
    ).all()
    out = []
    for src, dst, port, _n in cands:
        if not net.internal(src) or net.internal(dst):
            continue
        times = s.scalars(
            select(Flow.start).where(Flow.src_ip == src, Flow.dst_ip == dst, Flow.dst_port == port, Flow.start >= since).order_by(Flow.start)
        ).all()
        gaps = [(b - a).total_seconds() for a, b in zip(times, times[1:], strict=False) if (b - a).total_seconds() > 1]
        if len(gaps) < params["min_connections"] - 1:
            continue
        mean = statistics.fmean(gaps)
        jitter = statistics.pstdev(gaps) / mean if mean else 1
        if jitter <= params["max_jitter"]:
            out.append({"src": src, "dst": dst, "port": port, "connections": len(times), "interval": round(mean, 1), "jitter": round(jitter, 3)})
    return sorted(out, key=lambda r: r["jitter"])


def _rare_destinations(s, since, params, net):
    rows = s.execute(
        select(Flow.dst_ip, func.min(Flow.dst_country), func.min(Flow.src_ip), func.count(distinct(Flow.src_ip)), func.count(), func.sum(Flow.bytes))
        .where(Flow.start >= since)
        .group_by(Flow.dst_ip)
        .having(func.count(distinct(Flow.src_ip)) == 1, func.count() >= params["min_flows"])
        .order_by(func.sum(Flow.bytes).desc()).limit(1000)
    ).all()
    return [
        {"dst": d, "country": c, "src": src, "flows": n, "bytes": int(b or 0)}
        for d, c, src, _, n, b in rows if net.internal(src) and not net.internal(d)
    ]


def _large_uploads(s, since, params, net):
    rows = s.execute(
        select(Flow.src_ip, Flow.dst_ip, func.min(Flow.dst_country), func.sum(Flow.bytes), func.count())
        .where(Flow.start >= since)
        .group_by(Flow.src_ip, Flow.dst_ip)
        .having(func.sum(Flow.bytes) >= params["min_mb"] * 1_000_000)
        .order_by(func.sum(Flow.bytes).desc()).limit(500)
    ).all()
    return [{"src": a, "dst": b, "country": c, "bytes": int(by), "flows": n} for a, b, c, by, n in rows if net.internal(a) and not net.internal(b)]


def _unusual_ports(s, since, params, net):
    rows = s.execute(
        select(Flow.src_ip, Flow.dst_ip, Flow.dst_port, Flow.protocol, func.count(), func.sum(Flow.bytes))
        .where(Flow.start >= since, Flow.dst_port.notin_(COMMON_PORTS), Flow.dst_port < 49152, Flow.protocol.in_(["TCP", "UDP"]))
        .group_by(Flow.src_ip, Flow.dst_ip, Flow.dst_port, Flow.protocol)
        .order_by(func.sum(Flow.bytes).desc()).limit(1000)
    ).all()
    return [
        {"src": a, "dst": b, "port": po, "protocol": pr, "flows": n, "bytes": int(by or 0)}
        for a, b, po, pr, n, by in rows if net.internal(a) and not net.internal(b)
    ]


def _dns_heavy(s, since, params, net):
    rows = s.execute(
        select(Flow.src_ip, func.sum(Flow.packets), func.sum(Flow.bytes), func.count(distinct(Flow.dst_ip)))
        .where(Flow.start >= since, Flow.dst_port == 53)
        .group_by(Flow.src_ip).order_by(func.sum(Flow.packets).desc()).limit(50)
    ).all()
    return [{"src": a, "queries": int(q or 0), "avg_bytes": round((b or 0) / max(q or 1, 1)), "resolvers": r} for a, q, b, r in rows]


def _internal_fanout(s, since, params, net):
    rows = s.execute(
        select(Flow.src_ip, func.count(distinct(Flow.dst_ip)), func.count(distinct(Flow.dst_port)), func.count())
        .where(Flow.start >= since)
        .group_by(Flow.src_ip)
        .having(func.count(distinct(Flow.dst_ip)) >= params["min_hosts"])
        .order_by(func.count(distinct(Flow.dst_ip)).desc()).limit(500)
    ).all()
    out = []
    for src, _, _, _ in rows:
        if not net.internal(src):
            continue
        dsts = s.execute(select(distinct(Flow.dst_ip), Flow.dst_port).where(Flow.src_ip == src, Flow.start >= since)).all()
        internal = [(d, po) for d, po in dsts if net.internal(d)]
        hosts = {d for d, _ in internal}
        if len(hosts) >= params["min_hosts"]:
            out.append({"src": src, "hosts": len(hosts), "ports": len({po for _, po in internal}), "flows": len(internal)})
    return sorted(out, key=lambda r: -r["hosts"])


def _new_countries(s, since, params, net):
    before = set(s.scalars(
        select(distinct(Flow.dst_country)).where(Flow.start < since, Flow.start >= since - timedelta(days=7), Flow.dst_country != "")
    ))
    rows = s.execute(
        select(Flow.dst_country, func.count(distinct(Flow.src_ip)), func.count(), func.sum(Flow.bytes))
        .where(Flow.start >= since, Flow.dst_country != "").group_by(Flow.dst_country)
    ).all()
    return [{"country": c, "hosts": h, "flows": n, "bytes": int(b or 0)} for c, h, n, b in rows if c not in before]


RUNNERS = {
    "beaconing": _beaconing,
    "rare_destinations": _rare_destinations,
    "large_uploads": _large_uploads,
    "unusual_ports": _unusual_ports,
    "dns_heavy": _dns_heavy,
    "internal_fanout": _internal_fanout,
    "new_countries": _new_countries,
}
