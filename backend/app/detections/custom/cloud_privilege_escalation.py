"""
The exact identity-attack chain the master spec calls out as one of the
strongest parts of the platform: Compromised Identity -> AssumeRole ->
Excessive Permission -> Privilege Escalation -> Cloud Resource ->
Sensitive Action. This detection catches the middle-to-end of that
chain — an AssumeRole immediately followed by a sensitive action from
the same actor — which is the observable signal in event data. The
full attack-path graph reconstruction (identity -> role chain ->
resource, rendered visually) is Phase 11's job; this detection is what
feeds it a starting point.
"""
from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from app.detections.base import DetectionMatch
from app.detections.custom._helpers import events_in_window
from app.models.event import Event

WINDOW_MINUTES = 15
_SENSITIVE_ACTION_MARKERS = (
    "putuserpolicy",
    "putrolepolicy",
    "attachuserpolicy",
    "attachrolepolicy",
    "createuser",
    "createaccesskey",
    "deletetrail",
    "stoplogging",
    "putbucketpolicy",
    "putbucketacl",
    "putobjectacl",
    "disablekey",
    "updateassumerolepolicy",
    "deletebucketpolicy",
)


class CloudPrivilegeEscalationDetection:
    rule_id = "custom_cloud_privilege_escalation_chain"
    title = "AssumeRole Followed by a Sensitive Action (Privilege Escalation Chain)"
    description = (
        "The same actor performed an AssumeRole and then a sensitive "
        f"permission/logging/resource-policy action within {WINDOW_MINUTES} "
        "minutes — the observable signature of Compromised Identity -> "
        "AssumeRole -> Excessive Permission -> Sensitive Action."
    )
    engine = "custom_python"
    level = "critical"
    base_risk_score = 90
    mitre_technique_ids = ["T1078.004", "T1548", "T1550.001"]
    relevant_categories = {"iam", "cloud"}

    def run(self, db: Session, *, organization_id: uuid.UUID, triggering_event: Event) -> list[DetectionMatch]:
        action = (triggering_event.action or "").lower()
        if not any(marker in action for marker in _SENSITIVE_ACTION_MARKERS):
            return []
        if not triggering_event.user:
            return []

        window = events_in_window(
            db,
            organization_id=organization_id,
            category=None,
            before=triggering_event.event_timestamp,
            minutes=WINDOW_MINUTES,
            user=triggering_event.user,
            exclude_event_id=triggering_event.id,
        )
        assume_roles = [e for e in window if (e.action or "").lower() == "assumerole"]
        if not assume_roles:
            return []

        assume_role_event = assume_roles[-1]
        return [
            DetectionMatch(
                matched_event_ids=[assume_role_event.id, triggering_event.id],
                fired_at=triggering_event.event_timestamp,
                host_name=triggering_event.host_name_raw,
                user=triggering_event.user,
                evidence_summary={
                    "pattern": "assume_role_then_sensitive_action",
                    "actor": triggering_event.user,
                    "assumed_role": assume_role_event.iam_role,
                    "assume_role_at": assume_role_event.event_timestamp.isoformat(),
                    "sensitive_action": triggering_event.action,
                    "sensitive_action_at": triggering_event.event_timestamp.isoformat(),
                    "cloud_account": triggering_event.cloud_account,
                    "window_minutes": WINDOW_MINUTES,
                },
            )
        ]
