"""Database tables."""

from datetime import datetime

from sqlalchemy import JSON, Boolean, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base, UTCDateTime, utcnow

ROLES = ("viewer", "analyst", "admin")
SEVERITIES = ("info", "low", "medium", "high", "critical")
ALERT_STATUSES = ("new", "in_progress", "closed")
DISPOSITIONS = ("true_positive", "false_positive", "benign")
CASE_STATUSES = ("open", "investigating", "contained", "resolved", "closed")


# ── People and access ─────────────────────────────────────────────────────────


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    display_name: Mapped[str] = mapped_column(String(120), default="")
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16), default="viewer")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    # Authenticator secret, encrypted with the vault key.
    mfa_secret: Mapped[str | None] = mapped_column(Text, nullable=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    # Last accepted TOTP time step, so a code can't be replayed.
    mfa_last_step: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class AuthSession(Base):
    """Server-side session. The browser holds a random token in an
    HttpOnly cookie; only its SHA-256 is stored, so a database leak doesn't
    hand out live sessions."""

    __tablename__ = "auth_sessions"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    csrf_token: Mapped[str] = mapped_column(String(64))
    # Password accepted, authenticator code (or enrolment) still required.
    mfa_pending: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    ip: Mapped[str] = mapped_column(String(64), default="")
    user_agent: Mapped[str] = mapped_column(String(255), default="")

    user: Mapped[User] = relationship()


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64), index=True)
    target_type: Mapped[str] = mapped_column(String(32), default="")
    target_id: Mapped[str] = mapped_column(String(64), default="")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    ip: Mapped[str] = mapped_column(String(64), default="")


class LoginAttempt(Base):
    """Failed logins per client IP, for throttling across accounts."""

    __tablename__ = "login_attempts"

    id: Mapped[int] = mapped_column(primary_key=True)
    ip: Mapped[str] = mapped_column(String(64), index=True)
    at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)


# ── Telemetry ─────────────────────────────────────────────────────────────────


class Flow(Base):
    """Packets aggregated by 5-tuple over a short window. Storing flows
    instead of every packet keeps the database small and is what network
    detections and hunts actually need."""

    __tablename__ = "flows"

    id: Mapped[int] = mapped_column(primary_key=True)
    start: Mapped[datetime] = mapped_column(UTCDateTime, index=True)
    end: Mapped[datetime] = mapped_column(UTCDateTime)
    src_ip: Mapped[str] = mapped_column(String(45), index=True)
    src_port: Mapped[int] = mapped_column(Integer, default=0)
    dst_ip: Mapped[str] = mapped_column(String(45), index=True)
    dst_port: Mapped[int] = mapped_column(Integer, default=0)
    protocol: Mapped[str] = mapped_column(String(8))
    packets: Mapped[int] = mapped_column(Integer, default=0)
    bytes: Mapped[int] = mapped_column(Integer, default=0)
    tcp_flags: Mapped[str] = mapped_column(String(16), default="")
    src_country: Mapped[str] = mapped_column(String(2), default="")
    dst_country: Mapped[str] = mapped_column(String(2), default="")


class LogEvent(Base):
    """A syslog message from a firewall, server or other device."""

    __tablename__ = "log_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    received_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    source_ip: Mapped[str] = mapped_column(String(45), index=True)
    host: Mapped[str] = mapped_column(String(255), default="")
    app: Mapped[str] = mapped_column(String(64), default="")
    facility: Mapped[int] = mapped_column(Integer, default=1)
    severity: Mapped[int] = mapped_column(Integer, default=6)
    message: Mapped[str] = mapped_column(Text)


class Asset(Base):
    """An internal host, discovered from traffic and enriched by analysts."""

    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(primary_key=True)
    ip: Mapped[str] = mapped_column(String(45), unique=True)
    hostname: Mapped[str] = mapped_column(String(255), default="")
    owner: Mapped[str] = mapped_column(String(120), default="")
    criticality: Mapped[str] = mapped_column(String(16), default="medium")  # low|medium|high|critical
    os: Mapped[str] = mapped_column(String(64), default="")
    tags: Mapped[list] = mapped_column(JSON, default=list)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class SensorStatus(Base):
    __tablename__ = "sensor_status"

    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    source: Mapped[str] = mapped_column(String(16))
    started_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    stats: Mapped[dict] = mapped_column(JSON, default=dict)


# ── Detection ─────────────────────────────────────────────────────────────────


class Rule(Base):
    """A detection rule. Built-in rules have fixed logic with tunable
    thresholds; match rules are field conditions written by analysts. The
    sensor reloads this table every few seconds, so changes apply live."""

    __tablename__ = "rules"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    kind: Mapped[str] = mapped_column(String(16))  # builtin | match
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    severity: Mapped[str] = mapped_column(String(16))
    description: Mapped[str] = mapped_column(Text, default="")
    mitre_tactic: Mapped[str] = mapped_column(String(64), default="")
    mitre_technique: Mapped[str] = mapped_column(String(16), default="")
    params: Mapped[dict] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_by: Mapped[str] = mapped_column(String(64), default="system")


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (Index("ix_alerts_status_last_seen", "status", "last_seen"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(32), index=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), index=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(16), default="new")
    disposition: Mapped[str | None] = mapped_column(String(16), nullable=True)
    src_ip: Mapped[str] = mapped_column(String(45), default="", index=True)
    dst_ip: Mapped[str] = mapped_column(String(45), default="", index=True)
    dst_port: Mapped[int] = mapped_column(Integer, default=0)
    protocol: Mapped[str] = mapped_column(String(8), default="")
    src_country: Mapped[str] = mapped_column(String(2), default="")
    mitre_tactic: Mapped[str] = mapped_column(String(64), default="")
    mitre_technique: Mapped[str] = mapped_column(String(16), default="")
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    # Repeats of the same detection fold into one alert.
    dedup_key: Mapped[str] = mapped_column(String(255), index=True)
    count: Mapped[int] = mapped_column(Integer, default=1)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    assignee_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    case_id: Mapped[int | None] = mapped_column(ForeignKey("cases.id", ondelete="SET NULL"), nullable=True, index=True)
    closed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    closed_by: Mapped[str | None] = mapped_column(String(64), nullable=True)

    assignee: Mapped[User | None] = relationship(foreign_keys=[assignee_id])


class Case(Base):
    """An investigation: alerts grouped together, worked by an owner, with
    a timeline of everything that happened."""

    __tablename__ = "cases"

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(255))
    summary: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16), default="open")
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_by: Mapped[str] = mapped_column(String(64))
    tags: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    owner: Mapped[User | None] = relationship(foreign_keys=[owner_id])
    events: Mapped[list["CaseEvent"]] = relationship(
        back_populates="case", cascade="all, delete-orphan", order_by="CaseEvent.at"
    )


class CaseEvent(Base):
    __tablename__ = "case_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    actor: Mapped[str] = mapped_column(String(64))
    kind: Mapped[str] = mapped_column(String(32))  # note | status | owner | alert_linked | created | severity
    body: Mapped[str] = mapped_column(Text, default="")
    data: Mapped[dict] = mapped_column(JSON, default=dict)

    case: Mapped[Case] = relationship(back_populates="events")


# ── Intelligence ──────────────────────────────────────────────────────────────


class Indicator(Base):
    """A known-bad indicator (IOC). Traffic to or from a listed IP raises
    an alert."""

    __tablename__ = "indicators"
    __table_args__ = (UniqueConstraint("kind", "value"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(16))  # ip | domain | hash | url
    value: Mapped[str] = mapped_column(String(512), index=True)
    threat: Mapped[str] = mapped_column(String(120), default="")
    source: Mapped[str] = mapped_column(String(64), default="manual")
    confidence: Mapped[int] = mapped_column(Integer, default=80)
    added_by: Mapped[str] = mapped_column(String(64), default="system")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class IntelCache(Base):
    __tablename__ = "intel_cache"

    key: Mapped[str] = mapped_column(String(600), primary_key=True)  # provider:indicator
    data: Mapped[dict] = mapped_column(JSON)
    fetched_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class Secret(Base):
    """API keys and passwords set from the console, encrypted at rest."""

    __tablename__ = "secrets"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_by: Mapped[str] = mapped_column(String(64), default="")


# ── Operations ────────────────────────────────────────────────────────────────


class Handover(Base):
    __tablename__ = "handovers"

    id: Mapped[int] = mapped_column(primary_key=True)
    author: Mapped[str] = mapped_column(String(64))
    incoming: Mapped[str] = mapped_column(String(64), default="")
    shift: Mapped[str] = mapped_column(String(16), default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    # Queue and case snapshot at the time of writing.
    snapshot: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
