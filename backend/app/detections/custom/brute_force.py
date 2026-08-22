"""
The exact correlation example from the master spec: N failed logins
followed by one success, optionally followed by a privileged action
(sudo / new session), is a behavior a single-event Sigma rule cannot
express — this is why custom Python detections exist alongside Sigma.
"""
from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from app.detections.base import DetectionMatch
from app.detections.custom._helpers import events_in_window
from app.models.event import Event

FAILED_ACTIONS = {"failed_password", "failed_publickey"}
SUCCESS_ACTIONS = {"accepted_password", "accepted_publickey"}
PRIVILEGED_ACTIONS = {"sudo_command", "new_session"}

WINDOW_MINUTES = 15
FAILURE_THRESHOLD = 5


class BruteForceDetection:
    rule_id = "custom_brute_force_login"
    title = "Brute-Force Login Followed by Success"
    description = (
        f"{FAILURE_THRESHOLD}+ failed authentication attempts for the same "
        "user/host within a 15-minute window, immediately followed by a "
        "successful login — and, if present, a subsequent privileged "
        "action (sudo / new session) — indicating a credential-guessing "
        "attack that succeeded."
    )
    engine = "custom_python"
    level = "high"
    base_risk_score = 80
    mitre_technique_ids = ["T1110", "T1078"]
    relevant_categories = {"authentication"}

    def run(self, db: Session, *, organization_id: uuid.UUID, triggering_event: Event) -> list[DetectionMatch]:
        action = (triggering_event.action or "").lower()

        if action in SUCCESS_ACTIONS:
            return self._check_success_after_failures(db, organization_id, triggering_event)
        if action in PRIVILEGED_ACTIONS:
            return self._check_privileged_after_brute_force(db, organization_id, triggering_event)
        return []

    def _preceding_failures(self, db: Session, organization_id: uuid.UUID, ref_event: Event) -> list[Event]:
        window = events_in_window(
            db,
            organization_id=organization_id,
            category="authentication",
            before=ref_event.event_timestamp,
            minutes=WINDOW_MINUTES,
            host_name=ref_event.host_name_raw,
            user=ref_event.user,
            exclude_event_id=ref_event.id,
        )
        return [e for e in window if (e.action or "").lower() in FAILED_ACTIONS]

    def _check_success_after_failures(self, db, organization_id, success_event: Event) -> list[DetectionMatch]:
        failures = self._preceding_failures(db, organization_id, success_event)
        if len(failures) < FAILURE_THRESHOLD:
            return []

        return [
            DetectionMatch(
                matched_event_ids=[e.id for e in failures] + [success_event.id],
                fired_at=success_event.event_timestamp,
                host_name=success_event.host_name_raw,
                user=success_event.user,
                evidence_summary={
                    "pattern": "brute_force_then_success",
                    "failed_attempt_count": len(failures),
                    "window_minutes": WINDOW_MINUTES,
                    "first_failure_at": failures[0].event_timestamp.isoformat(),
                    "success_at": success_event.event_timestamp.isoformat(),
                    "source_ips": sorted({e.src_ip for e in failures if e.src_ip}),
                },
            )
        ]

    def _check_privileged_after_brute_force(self, db, organization_id, priv_event: Event) -> list[DetectionMatch]:
        # Find the most recent successful login for this user/host, then
        # check whether *that* success was itself preceded by a
        # brute-force pattern. If so, this privileged action is the
        # "escalation after a guessed credential" tail of the same chain.
        recent = events_in_window(
            db,
            organization_id=organization_id,
            category="authentication",
            before=priv_event.event_timestamp,
            minutes=WINDOW_MINUTES,
            host_name=priv_event.host_name_raw,
            user=priv_event.user,
            exclude_event_id=priv_event.id,
        )
        successes = [e for e in recent if (e.action or "").lower() in SUCCESS_ACTIONS]
        if not successes:
            return []
        success_event = successes[-1]

        failures = self._preceding_failures(db, organization_id, success_event)
        if len(failures) < FAILURE_THRESHOLD:
            return []

        return [
            DetectionMatch(
                matched_event_ids=[e.id for e in failures] + [success_event.id, priv_event.id],
                fired_at=priv_event.event_timestamp,
                host_name=priv_event.host_name_raw,
                user=priv_event.user,
                risk_score_override=95,  # escalated: brute force -> success -> privileged action
                evidence_summary={
                    "pattern": "brute_force_then_success_then_privileged_action",
                    "failed_attempt_count": len(failures),
                    "success_at": success_event.event_timestamp.isoformat(),
                    "privileged_action": priv_event.action,
                    "privileged_action_at": priv_event.event_timestamp.isoformat(),
                },
            )
        ]
