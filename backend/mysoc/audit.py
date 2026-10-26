"""Audit trail: who did what, from where."""

from sqlalchemy.orm import Session

from .models import AuditLog


def record(s: Session, actor: str, action: str, target_type: str = "", target_id: object = "", ip: str = "", **detail) -> None:
    s.add(AuditLog(actor=actor, action=action, target_type=target_type, target_id=str(target_id), detail=detail, ip=ip))
