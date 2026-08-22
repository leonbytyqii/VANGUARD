"""
Flags IAM policy/permission-modification API calls outright. Unlike the
entropy or fan-out heuristics elsewhere in this package, this one isn't
a statistical proxy — a PutUserPolicy/AttachRolePolicy/CreateUser call is
inherently high-signal for a SOC regardless of frequency, because
legitimate use is rare, deliberate, and usually change-managed. Cheap to
compute, easy to defend in an interview: "why does this fire on every
policy change?" — "because every policy change is worth a human glance,
and the false-positive cost of that is low compared to the cost of
missing one."
"""
from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from app.detections.base import DetectionMatch
from app.models.event import Event

_SENSITIVE_ACTION_MARKERS = (
    "putuserpolicy",
    "putrolepolicy",
    "attachuserpolicy",
    "attachrolepolicy",
    "detachrolepolicy",
    "detachuserpolicy",
    "createpolicyversion",
    "deleteuserpolicy",
    "deleterolepolicy",
    "createuser",
    "deleteuser",
    "creategroup",
    "addusertogroup",
    "updateassumerolepolicy",
)


class UnusualIAMActivityDetection:
    rule_id = "custom_unusual_iam_activity"
    title = "IAM Policy or Permission Modification"
    description = (
        "An IAM API call that modifies user/role/group permissions was "
        "observed. Legitimate use exists (deliberate access-management "
        "changes) but the base rate should be low and change-managed, so "
        "every occurrence is surfaced for review."
    )
    engine = "custom_python"
    level = "high"
    base_risk_score = 70
    mitre_technique_ids = ["T1098", "T1078.004"]
    relevant_categories = {"iam"}

    def run(self, db: Session, *, organization_id: uuid.UUID, triggering_event: Event) -> list[DetectionMatch]:
        action = (triggering_event.action or "").lower()
        if not any(marker in action for marker in _SENSITIVE_ACTION_MARKERS):
            return []

        return [
            DetectionMatch(
                matched_event_ids=[triggering_event.id],
                fired_at=triggering_event.event_timestamp,
                host_name=triggering_event.host_name_raw,
                user=triggering_event.user,
                evidence_summary={
                    "pattern": "iam_permission_modification",
                    "event_action": triggering_event.action,
                    "actor": triggering_event.user,
                    "iam_role": triggering_event.iam_role,
                    "cloud_account": triggering_event.cloud_account,
                },
            )
        ]
