r"""
The human-in-the-loop approval state machine for privileged response
actions. This is the only path by which anything in
app.ai.tools.registry.PRIVILEGED_ACTION_CATALOG can ever happen, and it is
deliberately impossible for anything to reach `executed` without a human
who holds `response.approve` calling `approve_response_action` first —
there is no "auto-approve if AI confidence is high" branch anywhere in this
module, on purpose.

State machine: pending -> approved -> executed
                       \-> rejected

Phase 9 adds one thing and changes none of the above: an action carrying
an `incident_id` now also writes a read-only entry onto that incident's
timeline at each transition (`_mirror_to_incident_timeline`). The case
file gains visibility of containment; containment gains nothing from the
case file. In particular an incident reaching status `contained` does not
approve, execute, or create anything here — it is a human recording that
containment happened, and the only function that can execute is still
`execute_response_action`, still gated on `status == approved`.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.ai.tools.registry import PRIVILEGED_ACTION_CATALOG
from app.models.automation import ResponseAction
from app.models.enums import ApprovalStatus, IncidentTimelineKind
from app.models.user import User
from app.services.audit import log_audit_event
from app.services.incident_timeline import record_timeline_event


class ResponseActionError(Exception):
    def __init__(self, message: str, *, status_code: int = 400):
        self.status_code = status_code
        super().__init__(message)


def _mirror_to_incident_timeline(
    db: Session, action: ResponseAction, *, phase: str, actor: str | None, extra: dict | None = None
) -> None:
    """
    Phase 9: an action attached to an incident also appears on that
    incident's timeline.

    This is *reporting only*. It runs after the state transition it
    describes has already been decided and committed to `action.status`,
    and it cannot influence that decision — adding an incident to the
    picture must not be able to change whether something gets approved.
    Actions with no `incident_id` (the common case for an investigation
    that has not been promoted yet) simply have nowhere to mirror to.
    """
    if action.incident_id is None:
        return
    record_timeline_event(
        db,
        incident_id=action.incident_id,
        kind=IncidentTimelineKind.RESPONSE_ACTION,
        actor=actor,
        details={
            "phase": phase,
            "response_action_id": str(action.id),
            "action_type": action.action_type,
            "target": action.target,
            "status": action.status,
            **(extra or {}),
        },
        commit=False,
    )


def create_response_action_request(
    db: Session,
    *,
    organization_id: uuid.UUID,
    action_type: str,
    target: str,
    justification: str,
    requested_by_user: User | None = None,
    requested_by_agent_type: str | None = None,
    investigation_id: uuid.UUID | None = None,
    incident_id: uuid.UUID | None = None,
    source_ip: str | None = None,
) -> ResponseAction:
    if action_type not in PRIVILEGED_ACTION_CATALOG:
        raise ResponseActionError(f"Unknown action_type '{action_type}'.", status_code=422)
    if not requested_by_user and not requested_by_agent_type:
        raise ResponseActionError("A response action must have a human or agent requester.", status_code=422)

    if incident_id is not None:
        # Phase 9: `incident_id` was accepted unchecked before this phase,
        # which was harmless only while nothing read it. It is now a write
        # target — the action is mirrored onto that incident's timeline —
        # so an unvalidated id would let a caller append an entry to
        # another tenant's case file. Resolved within the requester's own
        # organization, and reported as "unknown" rather than "forbidden"
        # so the existence of another tenant's incident stays unconfirmed.
        from app.models.incident import Incident  # local: avoids an import cycle via the tool registry

        owned = (
            db.query(Incident.id)
            .filter(Incident.id == incident_id, Incident.organization_id == organization_id)
            .first()
        )
        if owned is None:
            raise ResponseActionError("Unknown incident_id for this organization.", status_code=422)

    action = ResponseAction(
        organization_id=organization_id,
        action_type=action_type,
        target=target,
        justification=justification,
        status=ApprovalStatus.PENDING.value,
        requested_by_id=requested_by_user.id if requested_by_user else None,
        requested_by_agent_type=requested_by_agent_type,
        investigation_id=investigation_id,
        incident_id=incident_id,
    )
    db.add(action)
    db.flush()
    _mirror_to_incident_timeline(
        db,
        action,
        phase="requested",
        actor=requested_by_user.email if requested_by_user else f"ai_agent:{requested_by_agent_type}",
        extra={"justification": justification, "requires_human_approval": True},
    )
    db.commit()
    db.refresh(action)

    log_audit_event(
        db,
        action="approval_request",
        actor_id=requested_by_user.id if requested_by_user else None,
        actor_label=requested_by_user.email if requested_by_user else f"ai_agent:{requested_by_agent_type}",
        resource_type="response_action",
        resource_id=str(action.id),
        outcome="success",
        source_ip=source_ip,
        details={"action_type": action_type, "target": target},
    )
    return action


def approve_response_action(
    db: Session, action: ResponseAction, *, approver: User, source_ip: str | None = None
) -> ResponseAction:
    if action.status != ApprovalStatus.PENDING.value:
        raise ResponseActionError(f"Cannot approve action in status '{action.status}'.", status_code=409)

    action.status = ApprovalStatus.APPROVED.value
    action.approved_by_id = approver.id
    action.approved_at = datetime.now(timezone.utc)
    db.add(action)
    db.flush()
    _mirror_to_incident_timeline(db, action, phase="approved", actor=approver.email)
    db.commit()
    db.refresh(action)

    log_audit_event(
        db, action="approval_decision", actor_id=approver.id, actor_label=approver.email,
        resource_type="response_action", resource_id=str(action.id), outcome="success",
        source_ip=source_ip, details={"decision": "approved", "action_type": action.action_type},
    )
    return action


def reject_response_action(
    db: Session, action: ResponseAction, *, approver: User, reason: str, source_ip: str | None = None
) -> ResponseAction:
    if action.status != ApprovalStatus.PENDING.value:
        raise ResponseActionError(f"Cannot reject action in status '{action.status}'.", status_code=409)

    action.status = ApprovalStatus.REJECTED.value
    action.rejected_by_id = approver.id
    action.rejected_at = datetime.now(timezone.utc)
    action.rejection_reason = reason
    db.add(action)
    db.flush()
    _mirror_to_incident_timeline(db, action, phase="rejected", actor=approver.email, extra={"reason": reason})
    db.commit()
    db.refresh(action)

    log_audit_event(
        db, action="approval_decision", actor_id=approver.id, actor_label=approver.email,
        resource_type="response_action", resource_id=str(action.id), outcome="success",
        source_ip=source_ip, details={"decision": "rejected", "reason": reason, "action_type": action.action_type},
    )
    return action


def execute_response_action(
    db: Session, action: ResponseAction, *, executor: User, source_ip: str | None = None
) -> ResponseAction:
    """
    Phase 2 executes in *simulated* mode only — there is no real EDR/IAM/
    firewall integration wired up yet, and pretending otherwise would be
    dishonest about what this platform can currently do. The important
    guarantee being demonstrated here is the state machine and the audit
    trail, not a live integration: `result.simulated` is always True until
    a real executor is registered for an action_type.
    """
    if action.status != ApprovalStatus.APPROVED.value:
        raise ResponseActionError(f"Cannot execute action in status '{action.status}'.", status_code=409)

    action.status = ApprovalStatus.EXECUTED.value
    action.executed_by_id = executor.id
    action.executed_at = datetime.now(timezone.utc)
    action.result = {
        "simulated": True,
        "description": PRIVILEGED_ACTION_CATALOG[action.action_type],
        "target": action.target,
        "executed_by": executor.email,
    }
    db.add(action)
    db.flush()
    _mirror_to_incident_timeline(db, action, phase="executed", actor=executor.email, extra={"simulated": True})
    db.commit()
    db.refresh(action)

    log_audit_event(
        db, action="privileged_action_executed", actor_id=executor.id, actor_label=executor.email,
        resource_type="response_action", resource_id=str(action.id), outcome="success",
        source_ip=source_ip, details={"action_type": action.action_type, "target": action.target, "simulated": True},
    )
    return action
