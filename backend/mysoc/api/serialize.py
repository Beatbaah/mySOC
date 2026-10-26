"""JSON shapes the console receives. camelCase, ISO-8601 UTC times."""

from datetime import datetime

from ..models import Alert, Asset, AuditLog, Case, CaseEvent, Flow, Handover, Indicator, LogEvent, Rule, User


def iso(dt: datetime | None) -> str | None:
    return dt.isoformat().replace("+00:00", "Z") if dt else None


def user_ref(u: User | None) -> dict | None:
    return {"id": u.id, "username": u.username, "displayName": u.display_name or u.username} if u else None


def alert(a: Alert) -> dict:
    return {
        "id": a.id,
        "ruleId": a.rule_id,
        "title": a.title,
        "description": a.description,
        "severity": a.severity,
        "riskScore": a.risk_score,
        "status": a.status,
        "disposition": a.disposition,
        "srcIp": a.src_ip,
        "dstIp": a.dst_ip,
        "dstPort": a.dst_port,
        "protocol": a.protocol,
        "srcCountry": a.src_country,
        "mitreTactic": a.mitre_tactic,
        "mitreTechnique": a.mitre_technique,
        "evidence": a.evidence,
        "count": a.count,
        "firstSeen": iso(a.first_seen),
        "lastSeen": iso(a.last_seen),
        "assignee": user_ref(a.assignee),
        "caseId": a.case_id,
        "closedAt": iso(a.closed_at),
        "closedBy": a.closed_by,
    }


def case(c: Case, alert_count: int | None = None) -> dict:
    return {
        "id": c.id,
        "title": c.title,
        "summary": c.summary,
        "severity": c.severity,
        "status": c.status,
        "owner": user_ref(c.owner),
        "createdBy": c.created_by,
        "tags": c.tags or [],
        "createdAt": iso(c.created_at),
        "updatedAt": iso(c.updated_at),
        "resolvedAt": iso(c.resolved_at),
        "alertCount": alert_count,
    }


def case_event(e: CaseEvent) -> dict:
    return {"id": e.id, "at": iso(e.at), "actor": e.actor, "kind": e.kind, "body": e.body, "data": e.data}


def flow(f: Flow) -> dict:
    return {
        "id": f.id,
        "start": iso(f.start),
        "end": iso(f.end),
        "srcIp": f.src_ip,
        "srcPort": f.src_port,
        "dstIp": f.dst_ip,
        "dstPort": f.dst_port,
        "protocol": f.protocol,
        "packets": f.packets,
        "bytes": f.bytes,
        "tcpFlags": f.tcp_flags,
        "srcCountry": f.src_country,
        "dstCountry": f.dst_country,
    }


def log_event(e: LogEvent) -> dict:
    return {
        "id": e.id,
        "at": iso(e.received_at),
        "sourceIp": e.source_ip,
        "host": e.host,
        "app": e.app,
        "severity": e.severity,
        "message": e.message,
    }


def asset(a: Asset) -> dict:
    return {
        "id": a.id,
        "ip": a.ip,
        "hostname": a.hostname,
        "owner": a.owner,
        "criticality": a.criticality,
        "os": a.os,
        "tags": a.tags or [],
        "firstSeen": iso(a.first_seen),
        "lastSeen": iso(a.last_seen),
    }


def indicator(i: Indicator) -> dict:
    return {
        "id": i.id,
        "kind": i.kind,
        "value": i.value,
        "threat": i.threat,
        "source": i.source,
        "confidence": i.confidence,
        "addedBy": i.added_by,
        "createdAt": iso(i.created_at),
        "expiresAt": iso(i.expires_at),
    }


def rule(r: Rule, stats: dict | None = None) -> dict:
    return {
        "id": r.id,
        "name": r.name,
        "kind": r.kind,
        "enabled": r.enabled,
        "severity": r.severity,
        "description": r.description,
        "mitreTactic": r.mitre_tactic,
        "mitreTechnique": r.mitre_technique,
        "params": r.params,
        "updatedAt": iso(r.updated_at),
        "updatedBy": r.updated_by,
        "stats": stats or {},
    }


def user(u: User) -> dict:
    return {
        "id": u.id,
        "username": u.username,
        "displayName": u.display_name or u.username,
        "role": u.role,
        "isActive": u.is_active,
        "mfaEnabled": u.mfa_enabled,
        "mustChangePassword": u.must_change_password,
        "locked": bool(u.locked_until and u.locked_until > datetime.now(u.locked_until.tzinfo)),
        "createdAt": iso(u.created_at),
        "lastLoginAt": iso(u.last_login_at),
    }


def audit_entry(a: AuditLog) -> dict:
    return {
        "id": a.id,
        "at": iso(a.at),
        "actor": a.actor,
        "action": a.action,
        "targetType": a.target_type,
        "targetId": a.target_id,
        "detail": a.detail,
        "ip": a.ip,
    }


def handover(h: Handover) -> dict:
    return {
        "id": h.id,
        "author": h.author,
        "incoming": h.incoming,
        "shift": h.shift,
        "notes": h.notes,
        "snapshot": h.snapshot,
        "createdAt": iso(h.created_at),
    }
