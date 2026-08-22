"""
Turns fired Detections (Phase 4) into Alerts, with three deliberate
behaviors on top of a naive "one detection -> one alert" mapping:

1. **Dedup / reinforcement** — the same rule re-firing against the same
   asset within a short window doesn't flood the queue with near-
   duplicate alerts; it reinforces the existing open one (merges evidence,
   raises the score if warranted, refreshes the timestamp) instead of
   creating a new row. This is standard SIEM alert-fatigue mitigation.
2. **Context-aware risk scoring** — app/services/risk_scoring.py's pure
   formula is fed asset criticality (from the Host record) and a
   repeat-offender signal (does this asset already have an open alert
   from a *different* rule recently?) gathered here.
3. **Relational MITRE tagging** (Phase 6) — every alert's
   `mitre_techniques` M2M is populated from its rule's linked
   `MitreTechnique` rows (app/mitre/seed.py), so alerts can be queried
   "show me everything tagged Credential Access" via a join rather than
   string-matching the JSON evidence field.

Called synchronously right after app/detections/engine.py::run_detections_for_event
persists its Detection rows (see app/services/ingestion/service.py) — same
"simple and synchronous for now, one documented seam to a queue later"
posture as detection execution itself.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta

import structlog
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.detection import Detection, DetectionRule
from app.models.enums import AlertStatus
from app.models.host import Host
from app.services.risk_scoring import (
    REPEAT_OFFENDER_DISTINCT_RULE_THRESHOLD,
    REPEAT_OFFENDER_LOOKBACK_HOURS,
    compute_alert_risk_score,
    risk_score_to_severity,
)

log = structlog.get_logger()

# Alerts in these statuses are considered "closed" for dedup/repeat-
# offender purposes — a re-firing after an analyst already closed an
# alert should open a fresh one, not silently reinforce a decision the
# analyst already made.
_OPEN_STATUSES = {
    AlertStatus.NEW.value,
    AlertStatus.TRIAGED.value,
    AlertStatus.INVESTIGATING.value,
    AlertStatus.ESCALATED.value,
}

# Re-firings of the *same rule* against the *same asset* within this
# window reinforce one alert instead of creating a new one.
DEDUP_WINDOW_MINUTES = 30

ALERT_SOURCE = "detection_engine"


def _host_criticality(db: Session, organization_id: uuid.UUID, host_name: str | None) -> str:
    if not host_name:
        return "standard"
    host = db.query(Host).filter(Host.organization_id == organization_id, Host.hostname == host_name).one_or_none()
    return host.criticality if host else "standard"


def _is_repeat_offender(
    db: Session, organization_id: uuid.UUID, *, rule_id: uuid.UUID, host_name: str | None, user: str | None, before: datetime
) -> bool:
    """
    True if this asset (host, or user when host is unknown — e.g. IAM
    events) already has an open alert from a *different* rule within the
    lookback window. See risk_scoring.py's module docstring for why this
    is keyed on distinct-rule count rather than same-rule repeats.
    """
    if not host_name and not user:
        return False

    q = db.query(Alert).filter(
        Alert.organization_id == organization_id,
        Alert.status.in_(_OPEN_STATUSES),
        Alert.alert_timestamp > before - timedelta(hours=REPEAT_OFFENDER_LOOKBACK_HOURS),
        Alert.alert_timestamp <= before,
    )
    if host_name:
        q = q.filter(Alert.host_name == host_name)
    else:
        q = q.filter(Alert.user == user)

    existing_detection_ids = {a.detection_id for a in q.all() if a.detection_id}
    if not existing_detection_ids:
        return False

    # Alert.detection_id points at the *Detection* firing, not the rule
    # directly; resolve to rule ids via the Detection rows so "different
    # rule" is measured correctly rather than counting several Detection
    # instances of the *same* rule as distinct signals.
    other_rule_ids = {
        row.rule_id
        for row in db.query(Detection.rule_id).filter(Detection.id.in_(existing_detection_ids)).all()
        if row.rule_id != rule_id
    }
    return len(other_rule_ids) >= REPEAT_OFFENDER_DISTINCT_RULE_THRESHOLD


def _find_dedup_candidate(
    db: Session, organization_id: uuid.UUID, *, rule_id: uuid.UUID, host_name: str | None, user: str | None, fired_at: datetime
) -> Alert | None:
    q = db.query(Alert).join(Detection, Alert.detection_id == Detection.id).filter(
        Alert.organization_id == organization_id,
        Detection.rule_id == rule_id,
        Alert.status.in_(_OPEN_STATUSES),
        Alert.alert_timestamp > fired_at - timedelta(minutes=DEDUP_WINDOW_MINUTES),
    )
    if host_name:
        q = q.filter(Alert.host_name == host_name)
    elif user:
        q = q.filter(Alert.user == user)
    else:
        return None  # nothing to key dedup on — always create a fresh alert
    return q.order_by(Alert.alert_timestamp.desc()).first()


def generate_alerts_for_detections(db: Session, *, organization_id: uuid.UUID, detections: list[Detection]) -> list[Alert]:
    """
    One Alert (created or reinforced) per Detection. Every fired
    detection becomes an alert today — Phase 4's detections are already
    reasonably high-precision (no purely-informational/telemetry-only
    rules exist yet), so a minimum-severity-to-alert filter isn't needed
    yet; documented here as the natural next lever if low-value alert
    volume ever becomes a problem.
    """
    results: list[Alert] = []
    for detection in detections:
        rule: DetectionRule = detection.rule  # relationship, already loaded via FK
        host_criticality = _host_criticality(db, organization_id, detection.host_name)
        repeat_offender = _is_repeat_offender(
            db,
            organization_id,
            rule_id=rule.id,
            host_name=detection.host_name,
            user=detection.user,
            before=detection.fired_at,
        )
        score = compute_alert_risk_score(
            base_risk_score=detection.risk_score, host_criticality=host_criticality, repeat_offender=repeat_offender
        )
        severity = risk_score_to_severity(score)

        existing = _find_dedup_candidate(
            db,
            organization_id,
            rule_id=rule.id,
            host_name=detection.host_name,
            user=detection.user,
            fired_at=detection.fired_at,
        )

        if existing:
            existing.risk_score = max(existing.risk_score, score)
            existing.severity = risk_score_to_severity(existing.risk_score)
            existing.alert_timestamp = detection.fired_at
            merged_events = set(existing.related_event_ids) | {str(i) for i in detection.matched_event_ids}
            existing.related_event_ids = sorted(merged_events)
            existing.evidence = {
                **existing.evidence,
                "reinforced_by_detection_ids": list(
                    {*existing.evidence.get("reinforced_by_detection_ids", []), str(detection.id)}
                ),
                "reinforcement_count": existing.evidence.get("reinforcement_count", 0) + 1,
            }
            # Phase 6: merge in any MITRE techniques the reinforcing rule
            # declares that the existing alert doesn't already carry
            # (relevant when two different Sigma/custom rules dedup onto
            # the same alert via repeat_offender... in practice dedup is
            # same-rule-only today, but this keeps the tag set correct
            # if that ever changes).
            existing.mitre_techniques = list({*existing.mitre_techniques, *rule.mitre_techniques})
            db.add(existing)
            results.append(existing)
            log.info("alert_reinforced", alert_id=str(existing.id), detection_id=str(detection.id), risk_score=existing.risk_score)
            continue

        alert = Alert(
            organization_id=organization_id,
            title=rule.title,
            description=rule.description,
            severity=severity,
            risk_score=score,
            status=AlertStatus.NEW.value,
            source=ALERT_SOURCE,
            detection_id=detection.id,
            host_name=detection.host_name,
            user=detection.user,
            evidence={
                "detection_rule_id": rule.rule_id,
                "detection_engine": rule.engine,
                "base_risk_score": detection.risk_score,
                "host_criticality": host_criticality,
                "repeat_offender": repeat_offender,
                "mitre_technique_ids": rule.mitre_technique_ids,
                "detection_evidence": detection.evidence_summary,
            },
            related_event_ids=[str(i) for i in detection.matched_event_ids],
            # Phase 6: relational MITRE tagging, in addition to the raw ID
            # strings kept in evidence above (kept for cheap access without
            # a join — see app/models/mitre.py::MitreTechnique's docstring).
            mitre_techniques=list(rule.mitre_techniques),
            alert_timestamp=detection.fired_at,
        )
        db.add(alert)
        results.append(alert)
        log.info("alert_created", rule_id=rule.rule_id, risk_score=score, severity=severity)

    if results:
        db.commit()
        for a in results:
            db.refresh(a)
    return results
