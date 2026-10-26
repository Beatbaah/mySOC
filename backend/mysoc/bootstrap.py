"""First-run setup: tables, the first admin and the built-in rules."""

import logging
import secrets

from sqlalchemy import func, select

from .config import get_settings
from .db import init_db, session_scope
from .models import User
from .security.passwords import hash_password, password_problems

log = logging.getLogger("mysoc")


def create_user(s, username: str, password: str, role: str, display_name: str = "", must_change: bool = False) -> User:
    u = User(
        username=username.strip().lower(),
        display_name=display_name,
        password_hash=hash_password(password),
        role=role,
        must_change_password=must_change,
    )
    s.add(u)
    s.flush()
    return u


def ensure_first_admin() -> None:
    """Create the first admin when there are no users. Uses
    MYSOC_BOOTSTRAP_ADMIN_PASSWORD if set (it must pass the password
    policy); otherwise generates a random one, logs it once and requires a
    change at first sign-in. There is never a default password."""
    settings = get_settings()
    with session_scope() as s:
        if s.scalar(select(func.count()).select_from(User)):
            return
        password = settings.bootstrap_admin_password
        generated = not password
        if generated:
            password = secrets.token_urlsafe(15)
        elif problems := password_problems(password, settings.bootstrap_admin_username):
            raise RuntimeError("MYSOC_BOOTSTRAP_ADMIN_PASSWORD is too weak: " + " ".join(problems))
        create_user(s, settings.bootstrap_admin_username, password, "admin", "Administrator", must_change=generated)
        if generated:
            log.warning(
                "\n\n  First admin created.\n  Username: %s\n  One-time password: %s\n"
                "  You'll be asked to change it and set up an authenticator app at first sign-in.\n",
                settings.bootstrap_admin_username,
                password,
            )


def bootstrap() -> None:
    from .sensor.detection.catalog import ensure_builtin_rules

    init_db()
    ensure_first_admin()
    ensure_builtin_rules()
