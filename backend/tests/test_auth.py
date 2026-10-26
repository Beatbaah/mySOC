import time
from datetime import timedelta

import pyotp
from fastapi.testclient import TestClient
from sqlalchemy import select

from mysoc import db
from mysoc.models import AuditLog, AuthSession, LoginAttempt, User
from mysoc.security.passwords import password_problems

from .conftest import ADMIN_PW, PW, make_user, sign_in


def login(client, username, password):
    return client.post("/api/auth/login", json={"username": username, "password": password})


def test_session_cookie_is_httponly_and_strict(client):
    make_user("ana", "analyst")
    r = login(client, "ana", PW)
    assert r.status_code == 200
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie
    assert r.json()["mfa"] == "none"
    with db.session_scope() as s:
        token = r.cookies.get("mysoc_session")
        # Only a hash of the token is stored.
        assert s.get(AuthSession, token) is None
        assert s.scalar(select(AuthSession)) is not None


def test_wrong_password_and_unknown_user_look_the_same(client):
    make_user("ana", "analyst")
    a = login(client, "ana", "not-the-password")
    b = login(client, "nobody", "not-the-password")
    assert a.status_code == b.status_code == 401
    assert a.json() == b.json()


def test_account_locks_without_revealing_it(client, app):
    make_user("ana", "analyst")
    for _ in range(5):
        login(client, "ana", "wrong")
    with db.session_scope() as s:
        s.execute(LoginAttempt.__table__.delete())  # clear the IP throttle, keep the account lock
        assert s.scalar(select(User).where(User.username == "ana")).locked_until is not None
    r = login(client, "ana", PW)
    assert r.status_code == 401
    assert r.json()["detail"] == "Incorrect username or password."


def test_ip_throttle(client):
    for _ in range(5):
        login(client, "nobody", "wrong")
    assert login(client, "nobody", "wrong").status_code == 429


def test_mutations_need_csrf_token(app):
    make_user("ana", "analyst")
    api = sign_in(app, "ana")
    r = api.c.post("/api/cases", json={"title": "No token here"})
    assert r.status_code == 403
    assert api.post("/api/cases", json={"title": "With token"}).status_code == 201


def test_admin_must_enrol_authenticator_before_anything_else(app, client):
    r = login(client, "admin", ADMIN_PW)
    assert r.json()["mfa"] == "enroll"
    csrf = r.json()["csrfToken"]
    assert client.get("/api/overview").status_code == 401
    secret = client.post("/api/auth/mfa/enroll/start", headers={"X-CSRF-Token": csrf}).json()["secret"]
    bad = client.post("/api/auth/mfa/enroll/confirm", json={"code": "000000"}, headers={"X-CSRF-Token": csrf})
    assert bad.status_code == 400
    code = pyotp.TOTP(secret).now()
    ok = client.post("/api/auth/mfa/enroll/confirm", json={"code": code}, headers={"X-CSRF-Token": csrf})
    assert ok.status_code == 200 and ok.json()["mfa"] == "none"
    assert client.get("/api/overview").status_code == 200

    # The same code can't be used again on a new sign-in.
    c2 = TestClient(app)
    r = login(c2, "admin", ADMIN_PW)
    assert r.json()["mfa"] == "verify"
    replay = c2.post("/api/auth/mfa/verify", json={"code": code}, headers={"X-CSRF-Token": r.json()["csrfToken"]})
    assert replay.status_code == 401
    next_code = pyotp.TOTP(secret).at(time.time() + 30)
    fresh = c2.post("/api/auth/mfa/verify", json={"code": next_code}, headers={"X-CSRF-Token": r.json()["csrfToken"]})
    assert fresh.status_code == 200


def test_pending_mfa_session_cannot_use_the_api(client):
    secret = pyotp.random_base32()
    make_user("ana", "analyst", mfa_secret=secret)
    r = login(client, "ana", PW)
    assert r.json()["mfa"] == "verify"
    assert client.get("/api/alerts").status_code == 401


def test_viewer_cannot_change_things(viewer):
    assert viewer.get("/api/alerts").status_code == 200
    assert viewer.post("/api/cases", json={"title": "Not allowed"}).status_code == 403
    assert viewer.get("/api/users").status_code == 403


def test_must_change_password_blocks_work_until_changed(app):
    make_user("new", "analyst")
    with db.session_scope() as s:
        s.scalar(select(User).where(User.username == "new")).must_change_password = True
    api = sign_in(app, "new")
    assert api.post("/api/cases", json={"title": "Blocked"}).status_code == 403
    weak = api.post("/api/auth/password", json={"current": PW, "new": "short"})
    assert weak.status_code == 400
    ok = api.post("/api/auth/password", json={"current": PW, "new": "A-much-better-passphrase"})
    assert ok.status_code == 200
    assert api.post("/api/cases", json={"title": "Allowed now"}).status_code == 201


def test_idle_session_expires(app):
    make_user("ana", "analyst")
    api = sign_in(app, "ana")
    with db.session_scope() as s:
        sess = s.scalar(select(AuthSession))
        sess.last_seen_at = db.utcnow() - timedelta(hours=2)
    assert api.get("/api/alerts").status_code == 401


def test_logout_ends_session(app):
    make_user("ana", "analyst")
    api = sign_in(app, "ana")
    assert api.post("/api/auth/logout").status_code == 200
    assert api.get("/api/alerts").status_code == 401


def test_failed_logins_are_audited(client):
    login(client, "mallory", "guess")
    with db.session_scope() as s:
        assert s.scalar(select(AuditLog).where(AuditLog.action == "login_failed")).actor == "mallory"


def test_password_policy():
    assert password_problems("short")
    assert password_problems("Admin@SOC2024!")  # the old default
    assert password_problems("ana-password-long", "ana")
    assert not password_problems("A-much-better-passphrase")


def test_security_headers(client):
    r = client.get("/api/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["cache-control"] == "no-store"


def test_last_admin_cannot_be_demoted(admin):
    users = admin.get("/api/users").json()["items"]
    me = next(u for u in users if u["username"] == "admin")
    r = admin.patch(f"/api/users/{me['id']}", json={"role": "analyst"})
    assert r.status_code == 400
