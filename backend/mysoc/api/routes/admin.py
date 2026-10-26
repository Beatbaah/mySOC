"""Administration: people, the audit trail, integrations and secrets."""

import secrets as pysecrets
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from ... import audit
from ...bootstrap import create_user
from ...config import get_settings
from ...db import get_session, utcnow
from ...models import AuditLog, AuthSession, Secret, User
from ...security import passwords, vault
from .. import serialize as ser
from ..deps import Principal, admin, analyst
from ..sqlutil import safe_like
from .overview import sensors

router = APIRouter(prefix="/api", tags=["admin"])

Role = Literal["viewer", "analyst", "admin"]
SECRET_KEYS = {
    "abuseipdb_api_key": "AbuseIPDB API key",
    "otx_api_key": "AlienVault OTX API key",
    "virustotal_api_key": "VirusTotal API key",
    "smtp_password": "SMTP password",
    "telegram_bot_token": "Telegram bot token",
}


# ── people ────────────────────────────────────────────────────────────────────


@router.get("/users")
def list_users(p: Principal = Depends(admin), s: Session = Depends(get_session)):
    return {"items": [ser.user(u) for u in s.scalars(select(User).order_by(User.username))]}


@router.get("/users/assignable")
def assignable(p: Principal = Depends(analyst), s: Session = Depends(get_session)):
    """People an analyst can hand alerts or cases to."""
    rows = s.scalars(select(User).where(User.is_active, User.role != "viewer").order_by(User.username))
    return {"items": [ser.user_ref(u) for u in rows]}


class UserIn(BaseModel):
    username: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{1,63}$")
    displayName: str = Field(default="", max_length=120)
    role: Role = "analyst"


def _temp_password() -> str:
    return pysecrets.token_urlsafe(12)


@router.post("/users", status_code=201)
def add_user(body: UserIn, p: Principal = Depends(admin), s: Session = Depends(get_session)):
    if s.scalar(select(User.id).where(User.username == body.username)):
        raise HTTPException(409, "That username is taken.")
    temp = _temp_password()
    u = create_user(s, body.username, temp, body.role, body.displayName.strip(), must_change=True)
    audit.record(s, p.username, "user_created", "user", u.id, ip=p.ip, username=u.username, role=u.role)
    s.commit()
    # Shown once to the admin, who passes it on; it must be changed at first sign-in.
    return {"user": ser.user(u), "temporaryPassword": temp}


class UserUpdate(BaseModel):
    role: Role | None = None
    isActive: bool | None = None
    displayName: str | None = Field(default=None, max_length=120)


def _admins_left(s: Session, excluding: int) -> int:
    return s.scalar(select(func.count()).select_from(User).where(User.role == "admin", User.is_active, User.id != excluding)) or 0


@router.patch("/users/{user_id}")
def update_user(user_id: int, body: UserUpdate, p: Principal = Depends(admin), s: Session = Depends(get_session)):
    u = s.get(User, user_id)
    if not u:
        raise HTTPException(404, "User not found.")
    losing_admin = (body.role and body.role != "admin" and u.role == "admin") or (body.isActive is False and u.role == "admin")
    if losing_admin and not _admins_left(s, u.id):
        raise HTTPException(400, "There must always be at least one active admin.")
    changes = body.model_dump(exclude_none=True)
    if body.role:
        u.role = body.role
    if body.isActive is not None:
        u.is_active = body.isActive
    if body.displayName is not None:
        u.display_name = body.displayName.strip()
    if body.role or body.isActive is False:
        # Permissions changed: make them sign in again.
        s.execute(delete(AuthSession).where(AuthSession.user_id == u.id))
    audit.record(s, p.username, "user_updated", "user", u.id, ip=p.ip, **changes)
    s.commit()
    return ser.user(u)


@router.post("/users/{user_id}/reset-password")
def reset_password(user_id: int, p: Principal = Depends(admin), s: Session = Depends(get_session)):
    u = s.get(User, user_id)
    if not u:
        raise HTTPException(404, "User not found.")
    temp = _temp_password()
    u.password_hash = passwords.hash_password(temp)
    u.must_change_password = True
    u.failed_attempts, u.locked_until = 0, None
    s.execute(delete(AuthSession).where(AuthSession.user_id == u.id))
    audit.record(s, p.username, "password_reset", "user", u.id, ip=p.ip)
    s.commit()
    return {"temporaryPassword": temp}


@router.post("/users/{user_id}/reset-mfa")
def reset_mfa(user_id: int, p: Principal = Depends(admin), s: Session = Depends(get_session)):
    u = s.get(User, user_id)
    if not u:
        raise HTTPException(404, "User not found.")
    u.mfa_enabled, u.mfa_secret, u.mfa_last_step = False, None, 0
    s.execute(delete(AuthSession).where(AuthSession.user_id == u.id))
    audit.record(s, p.username, "mfa_reset", "user", u.id, ip=p.ip)
    s.commit()
    return ser.user(u)


@router.post("/users/{user_id}/unlock")
def unlock(user_id: int, p: Principal = Depends(admin), s: Session = Depends(get_session)):
    u = s.get(User, user_id)
    if not u:
        raise HTTPException(404, "User not found.")
    u.failed_attempts, u.locked_until = 0, None
    audit.record(s, p.username, "user_unlocked", "user", u.id, ip=p.ip)
    s.commit()
    return ser.user(u)


# ── audit trail ───────────────────────────────────────────────────────────────


@router.get("/audit")
def audit_log(
    actor: str | None = Query(default=None, max_length=64),
    action: str | None = Query(default=None, max_length=64),
    q: str | None = Query(default=None, max_length=100),
    limit: int = Query(default=200, ge=1, le=2000),
    p: Principal = Depends(admin),
    s: Session = Depends(get_session),
):
    stmt = select(AuditLog)
    if actor:
        stmt = stmt.where(AuditLog.actor == actor)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if q:
        stmt = stmt.where(AuditLog.target_id.ilike(safe_like(q)) | AuditLog.ip.ilike(safe_like(q)))
    rows = s.scalars(stmt.order_by(AuditLog.at.desc()).limit(limit)).all()
    actions = s.scalars(select(AuditLog.action).distinct().order_by(AuditLog.action)).all()
    return {"items": [ser.audit_entry(a) for a in rows], "actions": actions}


# ── settings ──────────────────────────────────────────────────────────────────


@router.get("/settings")
def get_settings_view(p: Principal = Depends(admin), s: Session = Depends(get_session)):
    st = get_settings()
    stored = {k: v for k, v in s.execute(select(Secret.key, Secret.updated_at))}
    return {
        "sensors": sensors(s),
        "sensor": {
            "source": st.sensor_source,
            "syslog": st.syslog_enabled,
            "syslogPort": st.syslog_port,
            "internalNetworks": st.internal_networks,
            "allowlist": st.allowlist_ips,
            "dedupMinutes": st.alert_dedup_minutes,
            "geoip": bool(st.geoip_db_path),
        },
        "retention": {"flowsDays": st.flow_retention_days, "logsDays": st.log_retention_days, "alertsDays": st.alert_retention_days},
        "security": {
            "sessionIdleMinutes": st.session_idle_minutes,
            "sessionMaxHours": st.session_max_hours,
            "adminMfaRequired": st.require_mfa_for_admin,
            "vaultKeyConfigured": bool(st.vault_key),
            "environment": st.env,
        },
        "notifications": {
            "email": bool(st.smtp_host and st.alert_email_to),
            "emailTo": st.alert_email_to,
            "telegram": bool(st.telegram_chat_ids),
        },
        "secrets": [
            {"key": k, "label": label, "set": k in stored, "updatedAt": ser.iso(stored.get(k))}
            for k, label in SECRET_KEYS.items()
        ],
    }


class SecretIn(BaseModel):
    value: str = Field(min_length=1, max_length=4096)


@router.put("/settings/secrets/{key}")
def set_secret(key: str, body: SecretIn, p: Principal = Depends(admin), s: Session = Depends(get_session)):
    if key not in SECRET_KEYS:
        raise HTTPException(404, "Unknown setting.")
    row = s.get(Secret, key)
    enc = vault.encrypt(body.value.strip())
    if row:
        row.value, row.updated_at, row.updated_by = enc, utcnow(), p.username
    else:
        s.add(Secret(key=key, value=enc, updated_by=p.username))
    # Never log the value itself.
    audit.record(s, p.username, "secret_set", "secret", key, ip=p.ip)
    s.commit()
    return {"ok": True}


@router.delete("/settings/secrets/{key}")
def delete_secret(key: str, p: Principal = Depends(admin), s: Session = Depends(get_session)):
    row = s.get(Secret, key)
    if row:
        s.delete(row)
        audit.record(s, p.username, "secret_deleted", "secret", key, ip=p.ip)
        s.commit()
    return {"ok": True}
