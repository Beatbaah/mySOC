"""Password hashing (Argon2id) and the password policy."""

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

_hasher = PasswordHasher()  # Argon2id, library defaults (RFC 9106 low-memory profile)

# A hash to verify against when the username doesn't exist, so a login for
# an unknown account takes as long as one for a real account.
_DUMMY_HASH = _hasher.hash("timing-equaliser-not-a-real-password")

MIN_LENGTH = 12
_COMMON = {
    "password1234", "123456789012", "qwertyuiop12", "admin@soc2024!", "changeme1234",
    "letmein12345", "welcome12345", "password123!", "administrator",
}


def hash_password(plain: str) -> str:
    return _hasher.hash(plain)


def verify_password(plain: str, hashed: str | None) -> bool:
    try:
        return _hasher.verify(hashed or _DUMMY_HASH, plain) and hashed is not None
    except (VerificationError, InvalidHashError):
        return False


def needs_rehash(hashed: str) -> bool:
    return _hasher.check_needs_rehash(hashed)


def password_problems(plain: str, username: str = "") -> list[str]:
    """Why a new password is unacceptable; empty when it's fine. Length
    over complexity rules, per NIST SP 800-63B."""
    problems = []
    if len(plain) < MIN_LENGTH:
        problems.append(f"Use at least {MIN_LENGTH} characters.")
    if len(plain) > 256:
        problems.append("Use at most 256 characters.")
    if plain.lower() in _COMMON:
        problems.append("This password is too common.")
    if username and username.lower() in plain.lower():
        problems.append("Don't include your username.")
    if len(set(plain)) < 5:
        problems.append("Use more varied characters.")
    return problems
