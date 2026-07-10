"""
auth/totp.py — TOTP-based two-factor authentication (RFC 6238)
Uses pyotp for token generation/verification and qrcode for enrollment QR codes.
"""

import base64
import io
import time
from typing import Optional, Tuple

import pyotp

from db import database as db
from utils.logger import get_logger

log = get_logger(__name__)

ISSUER_NAME = "MY SOC"
TOTP_WINDOW = 1  # allow ±1 period (30s each) for clock drift


# ── Enrolment ──────────────────────────────────────────────────────────────────

def generate_secret() -> str:
    """Generate a fresh base32 TOTP secret."""
    return pyotp.random_base32()


def get_provisioning_uri(username: str, secret: str) -> str:
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=ISSUER_NAME)


def generate_qr_b64(username: str, secret: str) -> Optional[str]:
    """
    Return a base64-encoded PNG of the QR code for the authenticator app,
    or None if qrcode/Pillow is not installed.
    """
    try:
        import qrcode  # type: ignore

        uri = get_provisioning_uri(username, secret)
        img = qrcode.make(uri)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return base64.b64encode(buf.getvalue()).decode()
    except ImportError:
        log.warning("qrcode package not installed — QR generation skipped")
        return None
    except Exception as e:
        log.error("QR generation failed: %s", e)
        return None


# ── Verification ───────────────────────────────────────────────────────────────

def verify_token(secret: str, token: str) -> bool:
    """Return True if the 6-digit token is valid for the given secret."""
    if not secret or not token:
        return False
    try:
        totp = pyotp.TOTP(secret)
        return totp.verify(token.strip(), valid_window=TOTP_WINDOW)
    except Exception as e:
        log.debug("TOTP verify error: %s", e)
        return False


# ── DB helpers ─────────────────────────────────────────────────────────────────

def enroll_user(username: str) -> Tuple[str, str]:
    """
    Create a new TOTP secret for a user, store it (unconfirmed),
    and return (secret, provisioning_uri).
    """
    secret = generate_secret()
    # Store as pending (confirmed=0) so it only activates after first verify
    db.execute(
        """INSERT OR REPLACE INTO totp_secrets
               (username, secret, confirmed, enrolled_at)
           VALUES (?, ?, 0, datetime('now'))""",
        (username, secret),
    )
    uri = get_provisioning_uri(username, secret)
    log.info("TOTP enrolment started for %s", username)
    return secret, uri


def confirm_enrollment(username: str, token: str) -> bool:
    """User proves they scanned the QR by entering their first valid token."""
    row = db.fetchone(
        "SELECT secret FROM totp_secrets WHERE username=? AND confirmed=0",
        (username,),
    )
    if not row:
        return False
    if verify_token(row["secret"], token):
        db.execute(
            "UPDATE totp_secrets SET confirmed=1 WHERE username=?",
            (username,),
        )
        log.info("TOTP confirmed for %s", username)
        return True
    return False


def is_enrolled(username: str) -> bool:
    row = db.fetchone(
        "SELECT confirmed FROM totp_secrets WHERE username=? AND confirmed=1",
        (username,),
    )
    return row is not None


def get_secret(username: str) -> Optional[str]:
    row = db.fetchone(
        "SELECT secret FROM totp_secrets WHERE username=? AND confirmed=1",
        (username,),
    )
    return row["secret"] if row else None


def revoke(username: str) -> None:
    db.execute("DELETE FROM totp_secrets WHERE username=?", (username,))
    log.info("TOTP revoked for %s", username)


def check_totp_login(username: str, token: str) -> bool:
    """Full login check — only valid if enrolled and token is correct."""
    secret = get_secret(username)
    if not secret:
        return False  # not enrolled → bypass (backward compat)
    return verify_token(secret, token)
