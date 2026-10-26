"""The sensor pipeline: store → enrich → detect → alert, in batches."""

import logging
from collections import Counter
from datetime import datetime, timedelta

from sqlalchemy import insert, select, update
from sqlalchemy.orm import Session

from ..db import session_scope
from ..models import Alert, Asset, Flow, Indicator, LogEvent, Rule
from .alerts import AlertWriter
from .detection.detectors import DetectionEngine, Finding, RuleConfig
from .flows import FlowRecord
from .geo import Geo
from .ml import AnomalyModel
from .netctx import NetContext
from .notify import Notifier
from .sources.demo import LogLine

log = logging.getLogger("mysoc.sensor")


class Pipeline:
    def __init__(self, net: NetContext, dedup_minutes: int, geo: Geo, notifier: Notifier | None = None, discover_assets: bool = True):
        self.net = net
        self.geo = geo
        self.engine = DetectionEngine(net)
        self.ml = AnomalyModel(net)
        self.writer = AlertWriter(dedup_minutes)
        self.notifier = notifier
        self.discover_assets = discover_assets
        self.meta: dict[str, dict] = {}
        self.counters: Counter = Counter()
        self.reload_rules()
        self.reload_indicators()

    # ── configuration from the database ───────────────────────────────────

    def reload_rules(self) -> None:
        with session_scope() as s:
            rules = s.scalars(select(Rule)).all()
            self.engine.set_rules([RuleConfig(r.id, r.name, r.kind, r.enabled, r.severity, dict(r.params or {})) for r in rules])
            self.meta = {r.id: {"tactic": r.mitre_tactic, "technique": r.mitre_technique} for r in rules}

    def reload_indicators(self) -> None:
        with session_scope() as s:
            rows = s.execute(select(Indicator.value, Indicator.threat).where(Indicator.kind == "ip"))
            self.engine.set_indicators({v: t for v, t in rows})

    # ── processing ────────────────────────────────────────────────────────

    def process(self, events: list[FlowRecord | LogLine], store_flow=lambda f: True) -> list[Alert]:
        """Process a batch. `store_flow` decides which flows are kept in the
        database (all of them live; a sample when backfilling history);
        every flow is still run through detection."""
        if not events:
            return []
        findings: list[Finding] = []
        flow_rows: list[dict] = []
        log_rows: list[dict] = []
        seen_internal: dict[str, datetime] = {}
        ml_rule = self.engine.rules.get("ML-001")
        flows: list[FlowRecord] = []

        for e in events:
            if isinstance(e, FlowRecord):
                self._enrich(e)
                findings += self.engine.process_flow(e)
                flows.append(e)
                self.counters["flows"] += 1
                self.counters["bytes"] += e.bytes
                for ip in (e.src_ip, e.dst_ip):
                    if self.net.internal(ip):
                        seen_internal[ip] = max(seen_internal.get(ip, e.end), e.end)
                if store_flow(e):
                    flow_rows.append({
                        "start": e.start, "end": e.end, "src_ip": e.src_ip, "src_port": e.src_port,
                        "dst_ip": e.dst_ip, "dst_port": e.dst_port, "protocol": e.protocol,
                        "packets": e.packets, "bytes": e.bytes, "tcp_flags": e.tcp_flags,
                        "src_country": e.src_country, "dst_country": e.dst_country,
                    })
            else:
                findings += self.engine.process_log(e.at, e.source_ip, e.host, e.message)
                self.counters["logs"] += 1
                log_rows.append({
                    "received_at": e.at, "source_ip": e.source_ip, "host": e.host, "app": e.app,
                    "severity": e.severity, "message": e.message[:8192],
                })

        findings += self.ml.process(flows, ml_rule)

        with session_scope() as s:
            if flow_rows:
                s.execute(insert(Flow), flow_rows)
            if log_rows:
                s.execute(insert(LogEvent), log_rows)
            if self.discover_assets and seen_internal:
                self._touch_assets(s, seen_internal)
            created = self.writer.write(s, findings, self.engine.rules, self.meta)
            s.flush()
            self.counters["alerts"] += len(created)
            new_alerts = [(a.id, a.severity, a.title, a.description, a.src_ip, a.dst_ip) for a in created]

        if self.notifier:
            for row in new_alerts:
                if row[1] in ("high", "critical"):
                    self.notifier.enqueue(*row)
        return created

    def _enrich(self, f: FlowRecord) -> None:
        if not f.src_country and not self.net.internal(f.src_ip):
            f.src_country = self.geo.country(f.src_ip)
        if not f.dst_country and not self.net.internal(f.dst_ip):
            f.dst_country = self.geo.country(f.dst_ip)

    @staticmethod
    def _touch_assets(s: Session, seen: dict[str, datetime]) -> None:
        known = set(s.scalars(select(Asset.ip).where(Asset.ip.in_(seen))))
        for ip, at in seen.items():
            if ip in known:
                # At most one write per host per minute.
                s.execute(update(Asset).where(Asset.ip == ip, Asset.last_seen < at - timedelta(minutes=1)).values(last_seen=at))
            else:
                s.add(Asset(ip=ip, first_seen=at, last_seen=at))
