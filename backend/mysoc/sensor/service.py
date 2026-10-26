"""The sensor process: runs independently of the API and of anyone being
signed in. Start with `python -m mysoc.sensor`.

Sources (demo traffic or live capture, plus optional syslog) feed one
queue; the main loop drains it every second and pushes the batch through
the pipeline. Rules and indicators are re-read from the database every few
seconds so console changes apply without a restart.
"""

import logging
import queue
import random
import signal
import socket
import time
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, func, select

from ..config import get_settings
from ..db import init_db, session_scope
from ..models import Alert, Asset, Flow, Indicator, LogEvent, SensorStatus
from .detection.catalog import ensure_builtin_rules
from .geo import Geo
from .netctx import NetContext
from .notify import Notifier
from .pipeline import Pipeline
from .sources import demo

log = logging.getLogger("mysoc.sensor")

BACKFILL_HOURS = 24
# Of the background flows replayed into history, keep this share in the
# database (detection still sees all of them). Attack flows are all kept.
BACKFILL_KEEP = 0.25


class Sensor:
    def __init__(self):
        self.settings = get_settings()
        self.name = socket.gethostname()[:64]
        self.q: queue.Queue = queue.Queue(maxsize=50_000)
        self.net = NetContext(self.settings.internal_networks, self.settings.allowlist_ips)
        demo_geo = demo.country_of if self.settings.sensor_source == "demo" else None
        self.geo = Geo(self.settings.geoip_db_path, fallback=demo_geo)
        self.notifier = Notifier(self.settings)
        self.pipeline: Pipeline | None = None
        self.started = datetime.now(UTC)
        self.running = True
        self.capture = None
        self.syslog = None
        self.demo: demo.DemoTraffic | None = None

    # ── setup ─────────────────────────────────────────────────────────────

    def setup(self) -> None:
        init_db()
        ensure_builtin_rules()
        if self.settings.sensor_source == "demo":
            self._seed_demo()
        self.pipeline = Pipeline(self.net, self.settings.alert_dedup_minutes, self.geo, self.notifier)

    def _seed_demo(self) -> None:
        with session_scope() as s:
            if not s.scalar(select(func.count()).select_from(Asset)):
                now = datetime.now(UTC)
                for a in demo.ASSETS:
                    s.add(Asset(**a, first_seen=now - timedelta(days=30), last_seen=now))
            for ind in demo.INDICATORS:
                exists = s.scalar(select(Indicator.id).where(Indicator.kind == ind["kind"], Indicator.value == ind["value"]))
                if not exists:
                    s.add(Indicator(**ind, source="demo-feed"))

    def _backfill(self) -> None:
        """Fill the last 24 hours so a fresh demo has history to explore."""
        with session_scope() as s:
            if s.scalar(select(func.count()).select_from(Flow)):
                return
        assert self.pipeline
        end = datetime.now(UTC)
        start = end - timedelta(hours=BACKFILL_HOURS)
        log.info("Demo: generating %d hours of history…", BACKFILL_HOURS)
        gen = demo.DemoTraffic(start, seed=random.randrange(1 << 30), background_per_second=0.6)
        rng = random.Random(3)
        story_ips = {demo.VICTIM, demo.C2}

        def keep(f) -> bool:
            return f.src_ip in story_ips or f.dst_ip in story_ips or f.packets <= 1 or rng.random() < BACKFILL_KEEP

        batch: list = []
        t = time.monotonic()
        for event in gen.until(end):
            batch.append(event)
            if len(batch) >= 5000:
                self.pipeline.process(batch, keep)
                batch = []
        self.pipeline.process(batch, keep)
        self._age_history(end)
        log.info("Demo: history ready in %.0f s (%d flows seen)", time.monotonic() - t, self.pipeline.counters["flows"])
        # Carry on live from where history ended, with a fresh story soon.
        self.demo = demo.DemoTraffic(end, seed=random.randrange(1 << 30), story_offset=timedelta(minutes=3))

    @staticmethod
    def _age_history(now: datetime) -> None:
        """Make replayed history look worked: older alerts closed with a
        disposition, a few in progress."""
        rng = random.Random(11)
        with session_scope() as s:
            for a in s.scalars(select(Alert).where(Alert.last_seen < now - timedelta(hours=2))):
                roll = rng.random()
                if roll < 0.7:
                    a.status, a.closed_at, a.closed_by = "closed", a.last_seen + timedelta(minutes=rng.randint(5, 90)), "demo"
                    a.disposition = "true_positive" if a.severity in ("high", "critical") and rng.random() < 0.7 else (
                        "benign" if rng.random() < 0.5 else "false_positive")
                elif roll < 0.8:
                    a.status = "in_progress"

    # ── sources ───────────────────────────────────────────────────────────

    def start_sources(self) -> None:
        st = self.settings
        if st.sensor_source == "demo":
            self._backfill()
            if self.demo is None:
                self.demo = demo.DemoTraffic(datetime.now(UTC), seed=random.randrange(1 << 30))
        elif st.sensor_source == "capture":
            from .sources.capture import PacketCapture

            self.capture = PacketCapture(self.q, st.capture_interface, st.flow_window_seconds)
            self.capture.start()
        else:
            raise RuntimeError(f"Unknown MYSOC_SENSOR_SOURCE {st.sensor_source!r} (use demo or capture)")
        if st.syslog_enabled:
            from .sources.syslog import SyslogServer

            self.syslog = SyslogServer(self.q, st.syslog_port)
            self.syslog.start()

    # ── main loop ─────────────────────────────────────────────────────────

    def run(self) -> None:
        self.setup()
        self.start_sources()
        assert self.pipeline
        log.info("Sensor %s running (source: %s)", self.name, self.settings.sensor_source)
        last = {"heartbeat": 0.0, "rules": 0.0, "indicators": 0.0, "retention": 0.0}
        while self.running:
            tick = time.monotonic()
            batch = []
            if self.demo is not None:
                batch.extend(self.demo.until(datetime.now(UTC)))
            while len(batch) < 20_000:
                try:
                    batch.append(self.q.get_nowait())
                except queue.Empty:
                    break
            try:
                self.pipeline.process(batch)
            except Exception:
                log.exception("Batch of %d events failed", len(batch))

            now = time.monotonic()
            if now - last["rules"] > 5:
                self.pipeline.reload_rules()
                last["rules"] = now
            if now - last["indicators"] > 30:
                self.pipeline.reload_indicators()
                last["indicators"] = now
            if now - last["heartbeat"] > 5:
                self._heartbeat()
                last["heartbeat"] = now
            if now - last["retention"] > 3600:
                self._retention()
                last["retention"] = now
            time.sleep(max(0.0, 1.0 - (time.monotonic() - tick)))

    def _heartbeat(self) -> None:
        assert self.pipeline
        c = self.pipeline.counters
        elapsed = max((datetime.now(UTC) - self.started).total_seconds(), 1)
        stats = {
            "flows": c["flows"], "logs": c["logs"], "alerts": c["alerts"], "bytes": c["bytes"],
            "flows_per_second": round(c["flows"] / elapsed, 2), "queue": self.q.qsize(),
            "ml": self.pipeline.ml.stats(), "syslog": self.settings.syslog_enabled,
            "notifications_suppressed": self.notifier.suppressed,
            "capture_error": getattr(self.capture, "error", None),
        }
        with session_scope() as s:
            row = s.get(SensorStatus, self.name)
            if row is None:
                s.add(SensorStatus(name=self.name, source=self.settings.sensor_source, started_at=self.started, stats=stats))
            else:
                row.source, row.started_at, row.last_seen, row.stats = self.settings.sensor_source, self.started, datetime.now(UTC), stats

    def _retention(self) -> None:
        st = self.settings
        now = datetime.now(UTC)
        with session_scope() as s:
            flows = s.execute(delete(Flow).where(Flow.start < now - timedelta(days=st.flow_retention_days))).rowcount
            logs = s.execute(delete(LogEvent).where(LogEvent.received_at < now - timedelta(days=st.log_retention_days))).rowcount
            alerts = s.execute(
                delete(Alert).where(Alert.status == "closed", Alert.case_id.is_(None),
                                    Alert.last_seen < now - timedelta(days=st.alert_retention_days))
            ).rowcount
        if flows or logs or alerts:
            log.info("Retention removed %d flows, %d log events, %d closed alerts", flows, logs, alerts)

    def stop(self, *_) -> None:
        self.running = False


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    sensor = Sensor()
    signal.signal(signal.SIGTERM, sensor.stop)
    signal.signal(signal.SIGINT, sensor.stop)
    sensor.run()
