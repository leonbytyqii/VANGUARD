"""
Single-event heuristic: destination ports strongly associated with C2
frameworks / reverse shells rather than legitimate business traffic.
Documented as a heuristic, not a guarantee — plenty of malware uses 443
to blend in, which this cannot catch; that's a job for TLS
fingerprinting / TI-based IOC matching (Phase 10), not a port list.
"""
from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from app.detections.base import DetectionMatch
from app.models.event import Event

# Common default ports for C2 frameworks (Metasploit/Cobalt Strike
# defaults), IRC-based botnet C2, and other historically abused ports.
SUSPICIOUS_PORTS = {4444, 4445, 1337, 31337, 6667, 6666, 12345, 54321}


class SuspiciousOutboundConnectionDetection:
    rule_id = "custom_suspicious_outbound_port"
    title = "Outbound Connection to a Known C2-Associated Port"
    description = (
        "A connection was made to a destination port commonly associated "
        "with command-and-control frameworks or IRC-based botnets "
        f"({sorted(SUSPICIOUS_PORTS)}). Heuristic only — legitimate use of "
        "these ports is rare but not impossible; confirm with additional "
        "evidence before treating as conclusive."
    )
    engine = "custom_python"
    level = "medium"
    base_risk_score = 60
    mitre_technique_ids = ["T1071", "T1571"]
    relevant_categories = {"network", "firewall"}

    def run(self, db: Session, *, organization_id: uuid.UUID, triggering_event: Event) -> list[DetectionMatch]:
        if triggering_event.dst_port not in SUSPICIOUS_PORTS:
            return []
        if (triggering_event.action or "").lower() in {"deny", "drop", "reset"}:
            return []

        return [
            DetectionMatch(
                matched_event_ids=[triggering_event.id],
                fired_at=triggering_event.event_timestamp,
                host_name=triggering_event.host_name_raw,
                user=triggering_event.user,
                evidence_summary={
                    "pattern": "suspicious_outbound_port",
                    "dst_ip": triggering_event.dst_ip,
                    "dst_port": triggering_event.dst_port,
                    "src_ip": triggering_event.src_ip,
                },
            )
        ]
