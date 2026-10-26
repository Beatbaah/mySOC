import os
import tempfile

# Settings are read once, so configure before importing the app.
_tmp = tempfile.mkdtemp(prefix="mysoc-test-")
os.environ.update({
    "MYSOC_DATABASE_URL": f"sqlite:///{_tmp}/boot.db",
    "MYSOC_BOOTSTRAP_ADMIN_PASSWORD": "Correct-Horse-Battery-9",
    "MYSOC_VAULT_KEY": "x3R6c9yRj2l8bq0e9m3QpC1vXzG6yJcW5nVt4kLhA2s=",
    "MYSOC_PUBLIC_ORIGIN": "http://localhost:5173",
})

import pyotp  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from mysoc import db  # noqa: E402
from mysoc.api.app import create_app  # noqa: E402
from mysoc.bootstrap import create_user  # noqa: E402
from mysoc.models import User  # noqa: E402
from mysoc.security import vault  # noqa: E402

ADMIN_PW = "Correct-Horse-Battery-9"
PW = "Analyst-Password-123"


@pytest.fixture
def app(tmp_path):
    db.reset_engine(f"sqlite:///{tmp_path}/t.db")
    return create_app()


@pytest.fixture
def client(app):
    return TestClient(app)


class Api:
    """A signed-in client that sends the CSRF header automatically."""

    def __init__(self, client: TestClient, csrf: str):
        self.c, self.csrf = client, csrf

    def get(self, url, **kw):
        return self.c.get(url, **kw)

    def _send(self, method, url, **kw):
        headers = {"X-CSRF-Token": self.csrf, **kw.pop("headers", {})}
        return self.c.request(method, url, headers=headers, **kw)

    def post(self, url, **kw):
        return self._send("POST", url, **kw)

    def patch(self, url, **kw):
        return self._send("PATCH", url, **kw)

    def put(self, url, **kw):
        return self._send("PUT", url, **kw)

    def delete(self, url, **kw):
        return self._send("DELETE", url, **kw)


def make_user(username: str, role: str, password: str = PW, mfa_secret: str | None = None) -> None:
    with db.session_scope() as s:
        u = create_user(s, username, password, role)
        if mfa_secret:
            u.mfa_secret, u.mfa_enabled = vault.encrypt(mfa_secret), True


def sign_in(app, username: str, password: str = PW, totp_secret: str | None = None) -> Api:
    c = TestClient(app)
    r = c.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    body = r.json()
    api = Api(c, body["csrfToken"])
    if body["mfa"] == "verify":
        r = api.post("/api/auth/mfa/verify", json={"code": pyotp.TOTP(totp_secret).now()})
        assert r.status_code == 200, r.text
    elif body["mfa"] == "enroll":
        secret = api.post("/api/auth/mfa/enroll/start").json()["secret"]
        r = api.post("/api/auth/mfa/enroll/confirm", json={"code": pyotp.TOTP(secret).now()})
        assert r.status_code == 200, r.text
    return api


@pytest.fixture
def analyst(app):
    make_user("ana", "analyst")
    return sign_in(app, "ana")


@pytest.fixture
def viewer(app):
    make_user("vic", "viewer")
    return sign_in(app, "vic")


@pytest.fixture
def admin(app):
    secret = pyotp.random_base32()
    with db.session_scope() as s:
        u = s.query(User).filter_by(username="admin").one()
        u.mfa_secret, u.mfa_enabled = vault.encrypt(secret), True
    return sign_in(app, "admin", ADMIN_PW, secret)
