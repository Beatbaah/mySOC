"""
auth/authenticator.py — Bcrypt login, account lockout, RBAC for MY SOC
"""
import sys as _sys
from pathlib import Path as _Path
_PROJECT_ROOT = str(_Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in _sys.path:
    _sys.path.insert(0, _PROJECT_ROOT)


import time
from typing import Optional, Tuple

import bcrypt

import config
from db import database as db
from utils.logger import get_logger

log = get_logger(__name__)


# ─── Password helpers ──────────────────────────────────────────────────────────

def hash_password(plain: str) -> str:
    return bcrypt.hashpw(
        plain.encode(), bcrypt.gensalt(rounds=config.BCRYPT_ROUNDS)
    ).decode()


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except Exception:
        return False


# ─── User management ───────────────────────────────────────────────────────────

def create_user(username: str, password: str, role: str = "viewer") -> bool:
    if role not in config.ROLES:
        log.warning("Unknown role '%s' for user '%s'", role, username)
        return False
    try:
        db.insert("users", {
            "username": username,
            "password_hash": hash_password(password),
            "role": role,
        })
        log.info("User created: %s (%s)", username, role)
        db.audit("system", "user_created", f"username={username}, role={role}")
        return True
    except Exception as e:
        log.error("Failed to create user %s: %s", username, e)
        return False


def ensure_default_admin():
    """Create default admin account if no users exist."""
    row = db.fetchone("SELECT COUNT(*) as cnt FROM users")
    if row and row["cnt"] == 0:
        create_user(
            config.DEFAULT_ADMIN_USER,
            config.DEFAULT_ADMIN_PASSWORD,
            "admin",
        )
        log.warning(
            "Default admin created — CHANGE THE PASSWORD IMMEDIATELY: %s",
            config.DEFAULT_ADMIN_USER,
        )


# ─── Login / lockout ───────────────────────────────────────────────────────────

def _is_locked(row) -> bool:
    if row["failed_attempts"] >= config.MAX_LOGIN_ATTEMPTS:
        if time.time() < row["locked_until"]:
            return True
        # lockout expired — reset
        db.execute(
            "UPDATE users SET failed_attempts=0, locked_until=0 WHERE username=?",
            (row["username"],),
        )
    return False


def authenticate(username: str, password: str) -> Tuple[bool, str, Optional[dict]]:
    """
    Returns (success, message, user_info_dict | None)
    user_info_dict has keys: id, username, role
    """
    row = db.fetchone("SELECT * FROM users WHERE username=?", (username,))

    if not row:
        log.warning("Login attempt for unknown user: %s", username)
        return False, "Invalid credentials.", None

    if _is_locked(row):
        remaining = int((row["locked_until"] - time.time()) / 60) + 1
        return False, f"Account locked. Try again in {remaining} min.", None

    if not verify_password(password, row["password_hash"]):
        new_attempts = row["failed_attempts"] + 1
        locked_until = 0.0
        if new_attempts >= config.MAX_LOGIN_ATTEMPTS:
            locked_until = time.time() + config.LOCKOUT_MINUTES * 60
            log.warning("Account LOCKED: %s (%d failures)", username, new_attempts)
        db.execute(
            "UPDATE users SET failed_attempts=?, locked_until=? WHERE username=?",
            (new_attempts, locked_until, username),
        )
        return False, "Invalid credentials.", None

    # Successful login
    db.execute(
        "UPDATE users SET failed_attempts=0, locked_until=0, last_login=datetime('now') WHERE username=?",
        (username,),
    )
    db.audit(username, "login_success")
    log.info("Login success: %s (%s)", username, row["role"])

    user = {"id": row["id"], "username": username, "role": row["role"]}
    return True, "Welcome back!", user


def logout(username: str) -> None:
    db.audit(username, "logout")
    log.info("Logout: %s", username)


# ─── RBAC helpers ──────────────────────────────────────────────────────────────

def get_role_level(role: str) -> int:
    return config.ROLES.get(role, {}).get("level", 0)


def has_permission(user: dict, min_role: str) -> bool:
    if not user:
        return False
    return get_role_level(user.get("role", "")) >= get_role_level(min_role)


def require_role(user: dict, min_role: str, action: str = "perform this action"):
    """Raises PermissionError if user lacks the required role."""
    if not has_permission(user, min_role):
        raise PermissionError(
            f"Role '{user.get('role')}' cannot {action}. "
            f"Requires '{min_role}' or higher."
        )


# ─── User CRUD (admin only) ────────────────────────────────────────────────────

def list_users() -> list:
    return db.fetchall(
        "SELECT id, username, role, failed_attempts, last_login, created_at FROM users"
    )


def delete_user(username: str) -> bool:
    db.execute("DELETE FROM users WHERE username=?", (username,))
    db.audit("system", "user_deleted", f"username={username}")
    return True


def change_password(username: str, new_password: str) -> bool:
    db.execute(
        "UPDATE users SET password_hash=? WHERE username=?",
        (hash_password(new_password), username),
    )
    db.audit(username, "password_changed")
    return True


def unlock_user(username: str) -> None:
    db.execute(
        "UPDATE users SET failed_attempts=0, locked_until=0 WHERE username=?",
        (username,),
    )
    db.audit("admin", "user_unlocked", f"username={username}")
