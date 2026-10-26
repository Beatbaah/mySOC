"""Small portable SQL helpers (SQLite and PostgreSQL)."""

from datetime import UTC, datetime

from sqlalchemy import Integer, cast, func
from sqlalchemy.orm import Session


def bucket(s: Session, column, seconds: int):
    """Integer bucket number (epoch // seconds) for a datetime column."""
    if s.get_bind().dialect.name == "sqlite":
        epoch = cast(func.strftime("%s", column), Integer)
    else:
        epoch = cast(func.extract("epoch", column), Integer)
    # // renders integer division; / would be true division in SQLAlchemy 2.
    return (epoch // seconds).label("bucket")


def bucket_time(n: int, seconds: int) -> str:
    return datetime.fromtimestamp(int(n) * seconds, UTC).isoformat().replace("+00:00", "Z")


def safe_like(q: str) -> str:
    return "%" + q.replace("\\", "").replace("%", "").replace("_", "") + "%"
