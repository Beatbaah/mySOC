"""Encryption for secrets stored in the database (Fernet: AES-128-CBC with
HMAC-SHA256).

The key comes from MYSOC_VAULT_KEY. In development, if it isn't set, a key
is generated once and kept in a local file readable only by this user, so
secrets are never stored in plain text. Production refuses to start
without the variable (see config.check_production).
"""

import os
from functools import lru_cache
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from ..config import get_settings

_DEV_KEY_FILE = Path(os.getenv("MYSOC_DEV_KEY_FILE", ".mysoc-dev-vault.key"))


@lru_cache
def _fernet() -> Fernet:
    key = get_settings().vault_key
    if not key:
        if _DEV_KEY_FILE.exists():
            key = _DEV_KEY_FILE.read_text().strip()
        else:
            key = Fernet.generate_key().decode()
            fd = os.open(_DEV_KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(key)
    return Fernet(key.encode())


def encrypt(plain: str) -> str:
    return _fernet().encrypt(plain.encode()).decode()


def decrypt(token: str) -> str:
    try:
        return _fernet().decrypt(token.encode()).decode()
    except InvalidToken as e:
        raise ValueError("Secret can't be decrypted with the current vault key") from e
