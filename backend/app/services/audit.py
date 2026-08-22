"""
Central audit logging. Every authentication/authorization-relevant event in
the platform goes through `log_audit_event` so app/models/audit.py::AuditLog
is a complete, append-only WHO / WHAT / WHEN / FROM WHERE / AGAINST WHAT /
RESULT record — see docs/SECURITY.md ("Audit architecture").

Deliberately synchronous and part of the same DB transaction as the action
it's recording where practical: an audit entry that silently failed to
write would defeat the point.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.models.audit import AuditLog


def log_audit_event(
    db: Session,
    *,
    action: str,
    actor_id: uuid.UUID | None = None,
    actor_label: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    outcome: str = "success",
    source_ip: str | None = None,
    details: dict[str, Any] | None = None,
    commit: bool = True,
) -> AuditLog:
    entry = AuditLog(
        timestamp=datetime.now(timezone.utc),
        actor_id=actor_id,
        actor_label=actor_label,
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id is not None else None,
        outcome=outcome,
        source_ip=source_ip,
        details=details or {},
    )
    db.add(entry)
    if commit:
        db.commit()
    else:
        db.flush()
    return entry
