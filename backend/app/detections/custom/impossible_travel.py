"""
"Impossible travel" heuristic, simplified. A real implementation would
GeoIP-resolve both source IPs, compute great-circle distance and the
implied minimum travel speed between the two login timestamps, and flag
only when that speed exceeds any real-world transport (the classic
"logged in from New York, then Tokyo, nine minutes later" check). SOC-AI
does not have a GeoIP database wired in yet (planned alongside real
threat-intel provider integration in Phase 10), so this is deliberately
downgraded to a proxy signal: the same user authenticating successfully
from two *different* source IPs within a short window. This will produce
false positives for users on VPNs or switching networks — documented
here rather than glossed over, and a good example in an interview of
"ship an honest simplification with a stated upgrade path" rather than
faking precision the system doesn't have.
"""
from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from app.detections.base import DetectionMatch
from app.detections.custom._helpers import events_in_window
from app.models.event import Event

SUCCESS_ACTIONS = {"accepted_password", "accepted_publickey"}
WINDOW_MINUTES = 30


class ImpossibleTravelDetection:
    rule_id = "custom_impossible_travel_proxy"
    title = "Same User, Multiple Source IPs in a Short Window (Impossible-Travel Proxy)"
    description = (
        "The same user successfully authenticated from two different "
        f"source IPs within {WINDOW_MINUTES} minutes. A simplified proxy "
        "for GeoIP-based impossible-travel analysis (no GeoIP database is "
        "wired in yet) — see module docstring for the false-positive "
        "tradeoff (VPNs, network switches)."
    )
    engine = "custom_python"
    level = "medium"
    base_risk_score = 50
    mitre_technique_ids = ["T1078"]
    relevant_categories = {"authentication"}

    def run(self, db: Session, *, organization_id: uuid.UUID, triggering_event: Event) -> list[DetectionMatch]:
        action = (triggering_event.action or "").lower()
        if action not in SUCCESS_ACTIONS or not triggering_event.src_ip or not triggering_event.user:
            return []

        window = events_in_window(
            db,
            organization_id=organization_id,
            category="authentication",
            before=triggering_event.event_timestamp,
            minutes=WINDOW_MINUTES,
            user=triggering_event.user,
            exclude_event_id=triggering_event.id,
        )
        prior_successes = [
            e for e in window if (e.action or "").lower() in SUCCESS_ACTIONS and e.src_ip and e.src_ip != triggering_event.src_ip
        ]
        if not prior_successes:
            return []

        other = prior_successes[-1]
        return [
            DetectionMatch(
                matched_event_ids=[other.id, triggering_event.id],
                fired_at=triggering_event.event_timestamp,
                host_name=triggering_event.host_name_raw,
                user=triggering_event.user,
                evidence_summary={
                    "pattern": "multi_ip_short_window_login",
                    "user": triggering_event.user,
                    "first_login_ip": other.src_ip,
                    "first_login_at": other.event_timestamp.isoformat(),
                    "second_login_ip": triggering_event.src_ip,
                    "second_login_at": triggering_event.event_timestamp.isoformat(),
                    "window_minutes": WINDOW_MINUTES,
                },
            )
        ]
