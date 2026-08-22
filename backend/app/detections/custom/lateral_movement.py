"""
Heuristic lateral-movement detection: the same source host reaching out
to several *distinct* destination hosts on lateral-movement-associated
ports (SMB/445, WinRM/5985-5986, RDP/3389) in a short window. A single
connection to 445 is completely normal (file shares); fanning out to
several different hosts on those ports quickly is the anomalous signal
this simplification targets. A production system would also weigh
process ancestry (psexec.exe, wmic.exe, PsExec service creation) — noted
here as a documented next-iteration improvement, not implemented in
Phase 4 to keep the heuristic auditable and false-positive-aware.
"""
from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from app.detections.base import DetectionMatch
from app.detections.custom._helpers import events_in_window
from app.models.event import Event

LATERAL_PORTS = {445, 3389, 5985, 5986}
WINDOW_MINUTES = 10
DISTINCT_HOST_THRESHOLD = 3


class LateralMovementDetection:
    rule_id = "custom_lateral_movement_fanout"
    title = "Possible Lateral Movement (Multi-Host SMB/WinRM/RDP Fan-Out)"
    description = (
        f"The same source IP connected to {DISTINCT_HOST_THRESHOLD}+ distinct "
        "destination IPs on SMB (445), WinRM (5985/5986), or RDP (3389) "
        "within a 10-minute window — consistent with an attacker moving "
        "host-to-host after an initial compromise."
    )
    engine = "behavioral_correlation"
    level = "high"
    base_risk_score = 75
    mitre_technique_ids = ["T1021.002", "T1021.001", "T1021.006"]
    relevant_categories = {"network", "firewall"}

    def run(self, db: Session, *, organization_id: uuid.UUID, triggering_event: Event) -> list[DetectionMatch]:
        if triggering_event.dst_port not in LATERAL_PORTS or not triggering_event.src_ip:
            return []
        if (triggering_event.action or "").lower() in {"deny", "drop", "reset"}:
            return []  # only allowed/successful connections count as movement

        window = events_in_window(
            db,
            organization_id=organization_id,
            category=None,
            before=triggering_event.event_timestamp,
            minutes=WINDOW_MINUTES,
        )
        related = [
            e
            for e in window
            if e.src_ip == triggering_event.src_ip
            and e.dst_port in LATERAL_PORTS
            and (e.action or "").lower() not in {"deny", "drop", "reset"}
        ]
        if triggering_event not in related:
            related.append(triggering_event)

        distinct_hosts = {e.dst_ip for e in related if e.dst_ip}
        if len(distinct_hosts) < DISTINCT_HOST_THRESHOLD:
            return []

        return [
            DetectionMatch(
                matched_event_ids=[e.id for e in related],
                fired_at=triggering_event.event_timestamp,
                host_name=triggering_event.host_name_raw,
                user=triggering_event.user,
                evidence_summary={
                    "pattern": "lateral_movement_fanout",
                    "source_ip": triggering_event.src_ip,
                    "distinct_destination_hosts": sorted(distinct_hosts),
                    "ports_used": sorted({e.dst_port for e in related}),
                    "window_minutes": WINDOW_MINUTES,
                },
            )
        ]
