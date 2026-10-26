"""Request dependencies: the signed-in user, CSRF checks and roles."""

from dataclasses import dataclass
from datetime import timedelta

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_session, utcnow
from ..models import ROLES, AuthSession, User
from ..security.tokens import same, token_hash

SESSION_COOKIE = "mysoc_session"
CSRF_HEADER = "X-CSRF-Token"
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


@dataclass
class Principal:
    user: User
    session: AuthSession
    ip: str

    @property
    def username(self) -> str:
        return self.user.username


def client_ip(request: Request) -> str:
    # Uvicorn rewrites request.client from X-Forwarded-For only for proxies
    # listed in --forwarded-allow-ips, so this can't be spoofed by clients.
    return request.client.host if request.client else ""


def _load_session(request: Request, s: Session) -> AuthSession:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sign in required.")
    sess = s.get(AuthSession, token_hash(token))
    now = utcnow()
    settings = get_settings()
    if (
        sess is None
        or sess.expires_at <= now
        or now - sess.last_seen_at > timedelta(minutes=settings.session_idle_minutes)
        or not sess.user.is_active
    ):
        if sess is not None:
            s.delete(sess)
            s.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Your session has ended. Sign in again.")

    if request.method not in _SAFE_METHODS:
        sent = request.headers.get(CSRF_HEADER, "")
        if not sent or not same(sent, sess.csrf_token):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Missing or invalid CSRF token.")

    # Sliding idle timeout; write at most once a minute.
    if now - sess.last_seen_at > timedelta(minutes=1):
        sess.last_seen_at = now
    return sess


def pending_principal(request: Request, s: Session = Depends(get_session)) -> Principal:
    """A session that may still be waiting for its authenticator code."""
    sess = _load_session(request, s)
    return Principal(user=sess.user, session=sess, ip=client_ip(request))


def current_principal(p: Principal = Depends(pending_principal)) -> Principal:
    if p.session.mfa_pending:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Enter your authenticator code to continue.")
    return p


def require_role(minimum: str):
    level = ROLES.index(minimum)

    def check(p: Principal = Depends(current_principal)) -> Principal:
        if ROLES.index(p.user.role) < level:
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"This needs the {minimum} role.")
        if p.user.must_change_password and minimum != "viewer":
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Change your password first.")
        return p

    return check


viewer = require_role("viewer")
analyst = require_role("analyst")
admin = require_role("admin")
