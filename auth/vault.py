"""
auth/vault.py — Encrypted credential vault using Fernet symmetric encryption.

API keys, SMTP passwords, Telegram tokens are stored encrypted in the DB.
The vault master key is derived from an environment variable (VAULT_MASTER_KEY).
If no master key is set, vault falls back to plaintext storage with a warning.
"""

import base64
import hashlib
import json
import os
from typing import Any, Dict, Optional

from utils.logger import get_logger
from db import database as db

log = get_logger(__name__)

_MASTER_KEY_ENV = "VAULT_MASTER_KEY"
_fernet = None


def _get_fernet():
    global _fernet
    if _fernet is not None:
        return _fernet
    try:
        from cryptography.fernet import Fernet  # type: ignore

        raw = os.getenv(_MASTER_KEY_ENV, "")
        if not raw:
            log.warning(
                "VAULT_MASTER_KEY not set — credentials stored as plaintext. "
                "Set this env var to enable encryption."
            )
            return None

        # Derive a 32-byte key from the master key using SHA-256
        key_bytes = hashlib.sha256(raw.encode()).digest()
        fernet_key = base64.urlsafe_b64encode(key_bytes)
        _fernet = Fernet(fernet_key)
        return _fernet
    except ImportError:
        log.warning("cryptography package not installed — vault encryption disabled")
        return None
    except Exception as e:
        log.error("Vault init failed: %s", e)
        return None


def _encrypt(value: str) -> str:
    f = _get_fernet()
    if f:
        return f.encrypt(value.encode()).decode()
    return value  # plaintext fallback


def _decrypt(value: str) -> str:
    f = _get_fernet()
    if f:
        try:
            return f.decrypt(value.encode()).decode()
        except Exception:
            # May be stored as plaintext from before encryption was enabled
            return value
    return value


# ── Public API ─────────────────────────────────────────────────────────────────

def set_secret(key: str, value: str) -> None:
    """Store an encrypted secret under the given key."""
    encrypted = _encrypt(value)
    db.execute(
        """INSERT OR REPLACE INTO vault (key, value, updated_at)
           VALUES (?, ?, datetime('now'))""",
        (key, encrypted),
    )
    log.debug("Vault: stored secret '%s'", key)


def get_secret(key: str, default: str = "") -> str:
    """Retrieve and decrypt a secret. Returns default if not found."""
    row = db.fetchone("SELECT value FROM vault WHERE key=?", (key,))
    if not row:
        return default
    return _decrypt(row["value"])


def delete_secret(key: str) -> None:
    db.execute("DELETE FROM vault WHERE key=?", (key,))


def list_keys() -> list:
    rows = db.fetchall("SELECT key, updated_at FROM vault ORDER BY key")
    return [dict(r) for r in rows]


def set_secrets_bulk(mapping: Dict[str, str]) -> None:
    for k, v in mapping.items():
        if v:
            set_secret(k, v)


def get_all_api_keys() -> Dict[str, str]:
    """Return all known API key vault entries (decrypted)."""
    keys = [
        "abuseipdb_api_key",
        "alienvault_api_key",
        "virustotal_api_key",
        "smtp_password",
        "telegram_bot_token",
    ]
    return {k: get_secret(k) for k in keys}


def is_encrypted() -> bool:
    return _get_fernet() is not None
