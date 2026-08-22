"""
CreateAccessKey followed by usage from an unexpected source shortly
after — a common pattern when a static access key is created and
immediately handed to (or stolen by) tooling running somewhere other
than wherever the creating principal normally operates from.
"""
from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from app.detections.base import DetectionMatch
from app.detections.custom._helpers import events_in_window
from app.models.event import Event

WINDOW_MINUTES = 60


class SuspiciousAPIKeyUsageDetection:
    rule_id = "custom_suspicious_api_key_usage"
    title = "New Access Key Used From a Different Source Shortly After Creation"
    description = (
        f"An IAM access key was created and then used from a different "
        f"source IP within {WINDOW_MINUTES} minutes — consistent with key "
        "material being immediately exfiltrated/reused elsewhere, rather "
        "than adopted by the creating principal's own tooling."
    )
    engine = "custom_python"
    level = "high"
    base_risk_score = 70
    mitre_technique_ids = ["T1098.001", "T1078.004"]
    relevant_categories = {"iam", "cloud"}

    def run(self, db: Session, *, organization_id: uuid.UUID, triggering_event: Event) -> list[DetectionMatch]:
        action = (triggering_event.action or "").lower()
        if action == "createaccesskey" or not triggering_event.user:
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
        creations = [e for e in window if (e.action or "").lower() == "createaccesskey"]
        if not creations:
            return []

        creation = creations[-1]
        if creation.src_ip and triggering_event.src_ip and creation.src_ip == triggering_event.src_ip:
            return []  # same source as the creator — expected, not suspicious

        return [
            DetectionMatch(
                matched_event_ids=[creation.id, triggering_event.id],
                fired_at=triggering_event.event_timestamp,
                host_name=triggering_event.host_name_raw,
                user=triggering_event.user,
                evidence_summary={
                    "pattern": "new_access_key_used_from_new_source",
                    "user": triggering_event.user,
                    "key_created_at": creation.event_timestamp.isoformat(),
                    "creation_src_ip": creation.src_ip,
                    "usage_action": triggering_event.action,
                    "usage_src_ip": triggering_event.src_ip,
                    "window_minutes": WINDOW_MINUTES,
                },
            )
        ]
