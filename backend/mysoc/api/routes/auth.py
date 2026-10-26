"""Sign-in, authenticator codes, sign-out and password changes."""

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from ... import audit
from ...config import get_settings
from ...db import get_session, utcnow
from ...models import AuthSession, LoginAttempt, User
from ...security import passwords, totp, vault
from ...security.tokens import new_token, token_hash
from ..deps import SESSION_COOKIE, Principal, client_ip, current_principal, pending_principal

router = APIRouter(prefix="/api/auth", tags=["auth"])

BAD_LOGIN = "Incorrect username or password."
PENDING_TTL = timedelta(minutes=10)


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class CodeIn(BaseModel):
    code: str = Field(min_length=6, max_length=8)


class PasswordIn(BaseModel):
    current: str = Field(max_length=256)
    new: str = Field(max_length=256)


def user_out(u: User) -> dict:
    return {
        "id": u.id,
        "username": u.username,
        "displayName": u.display_name or u.username,
        "role": u.role,
        "mfaEnabled": u.mfa_enabled,
        "mustChangePassword": u.must_change_password,
    }


def _mfa_step(u: User) -> str:
    """What the user must do after their password: nothing, enter a code,
    or set up an authenticator (required for admins)."""
    if u.mfa_enabled:
        return "verify"
    if u.role == "admin" and get_settings().require_mfa_for_admin:
        return "enroll"
    return "none"


def _complete_sign_in(s: Session, p: Principal) -> None:
    now = utcnow()
    p.session.mfa_pending = False
    p.session.expires_at = now + timedelta(hours=get_settings().session_max_hours)
    p.user.last_login_at = now
    audit.record(s, p.username, "login", ip=p.ip, mfa=True)


def _session_state(p: Principal) -> dict:
    step = _mfa_step(p.user) if p.session.mfa_pending else "none"
    return {"user": user_out(p.user), "mfa": step, "csrfToken": p.session.csrf_token}


def _throttled(s: Session, ip: str) -> bool:
    settings = get_settings()
    since = utcnow() - timedelta(seconds=settings.login_window_seconds)
    n = s.scalar(select(func.count()).select_from(LoginAttempt).where(LoginAttempt.ip == ip, LoginAttempt.at >= since))
    return (n or 0) >= settings.login_max_attempts


def _set_cookie(response: Response, token: str) -> None:
    settings = get_settings()
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=settings.session_max_hours * 3600,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
        path="/",
    )


@router.post("/login")
def login(body: LoginIn, request: Request, response: Response, s: Session = Depends(get_session)):
    ip = client_ip(request)
    settings = get_settings()
    if _throttled(s, ip):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many sign-in attempts. Wait a few minutes and try again.")

    u = s.scalar(select(User).where(User.username == body.username.strip().lower()))
    now = utcnow()
    # Always run the hash check, even for unknown users, so response time
    # doesn't reveal which usernames exist.
    ok = passwords.verify_password(body.password, u.password_hash if u else None)
    locked = bool(u and u.locked_until and u.locked_until > now)

    if not ok or locked or not u or not u.is_active:
        s.add(LoginAttempt(ip=ip))
        if u and not locked:
            u.failed_attempts += 1
            if u.failed_attempts >= settings.login_max_attempts:
                u.locked_until = now + timedelta(minutes=settings.account_lockout_minutes)
                u.failed_attempts = 0
                audit.record(s, u.username, "account_locked", "user", u.id, ip=ip)
        audit.record(s, body.username[:64], "login_failed", ip=ip)
        s.commit()
        # Locked or not, the message is the same: it mustn't confirm that
        # an account exists.
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, BAD_LOGIN)

    if passwords.needs_rehash(u.password_hash):
        u.password_hash = passwords.hash_password(body.password)
    u.failed_attempts = 0
    u.locked_until = None

    token = new_token()
    pending = _mfa_step(u) != "none"
    sess = AuthSession(
        token_hash=token_hash(token),
        user_id=u.id,
        csrf_token=new_token(),
        mfa_pending=pending,
        # A half-finished sign-in is only good for a few minutes.
        expires_at=now + (PENDING_TTL if pending else timedelta(hours=settings.session_max_hours)),
        ip=ip,
        user_agent=request.headers.get("user-agent", "")[:255],
    )
    s.add(sess)
    if not sess.mfa_pending:
        u.last_login_at = now
        audit.record(s, u.username, "login", ip=ip)
    s.commit()
    _set_cookie(response, token)
    sess.user = u
    return _session_state(Principal(user=u, session=sess, ip=ip))


@router.get("/me")
def me(p: Principal = Depends(pending_principal)):
    return _session_state(p)


@router.post("/mfa/verify")
def mfa_verify(body: CodeIn, p: Principal = Depends(pending_principal), s: Session = Depends(get_session)):
    if not p.session.mfa_pending or not p.user.mfa_enabled or not p.user.mfa_secret:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "No authenticator code is needed.")
    if _throttled(s, p.ip):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many attempts. Wait a few minutes and try again.")
    step = totp.verify(vault.decrypt(p.user.mfa_secret), body.code, p.user.mfa_last_step)
    if step is None:
        s.add(LoginAttempt(ip=p.ip))
        audit.record(s, p.username, "mfa_failed", ip=p.ip)
        s.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "That code didn't work. Check your authenticator app and try again.")
    p.user.mfa_last_step = step
    _complete_sign_in(s, p)
    s.commit()
    return _session_state(p)


@router.post("/mfa/enroll/start")
def mfa_enroll_start(p: Principal = Depends(pending_principal), s: Session = Depends(get_session)):
    """Begin setting up an authenticator. Allowed for a fully signed-in
    user, or one whose sign-in is waiting on enrolment."""
    if p.user.mfa_enabled:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "An authenticator is already set up.")
    if p.session.mfa_pending and _mfa_step(p.user) != "enroll":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Enter your authenticator code to continue.")
    secret = totp.new_secret()
    p.user.mfa_secret = vault.encrypt(secret)
    s.commit()
    uri = totp.provisioning_uri(p.username, secret)
    return {"secret": secret, "qr": totp.qr_svg_data_uri(uri)}


@router.post("/mfa/enroll/confirm")
def mfa_enroll_confirm(body: CodeIn, p: Principal = Depends(pending_principal), s: Session = Depends(get_session)):
    if p.user.mfa_enabled or not p.user.mfa_secret:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Start authenticator setup first.")
    step = totp.verify(vault.decrypt(p.user.mfa_secret), body.code, p.user.mfa_last_step)
    if step is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "That code didn't work. Check the time on your phone and try again.")
    p.user.mfa_enabled = True
    p.user.mfa_last_step = step
    if p.session.mfa_pending:
        _complete_sign_in(s, p)
    audit.record(s, p.username, "mfa_enrolled", "user", p.user.id, ip=p.ip)
    # Other sessions were opened without the new factor: end them.
    s.execute(delete(AuthSession).where(AuthSession.user_id == p.user.id, AuthSession.token_hash != p.session.token_hash))
    s.commit()
    return _session_state(p)


@router.post("/logout")
def logout(request: Request, response: Response, s: Session = Depends(get_session)):
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        sess = s.get(AuthSession, token_hash(token))
        if sess:
            audit.record(s, sess.user.username, "logout", ip=client_ip(request))
            s.delete(sess)
            s.commit()
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"ok": True}


@router.post("/password")
def change_password(body: PasswordIn, p: Principal = Depends(current_principal), s: Session = Depends(get_session)):
    if not passwords.verify_password(body.current, p.user.password_hash):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Your current password is incorrect.")
    problems = passwords.password_problems(body.new, p.username)
    if problems:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, " ".join(problems))
    p.user.password_hash = passwords.hash_password(body.new)
    p.user.must_change_password = False
    s.execute(delete(AuthSession).where(AuthSession.user_id == p.user.id, AuthSession.token_hash != p.session.token_hash))
    audit.record(s, p.username, "password_changed", "user", p.user.id, ip=p.ip)
    s.commit()
    return {"user": user_out(p.user)}
