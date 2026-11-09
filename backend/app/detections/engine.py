"""
Detection engine: syncs the DETECTION_REGISTRY into the `detection_rules`
table (so the DB — and the UI — always reflects exactly what's loaded in
code/YAML, with provenance), and runs detections against events.

Two entry points:
- `run_detections_for_event` — called synchronously right after an event
  is ingested (see app/services/ingestion/service.py::ingest_event).
  Only detections whose `relevant_categories` include the event's
  category are invoked, so a DNS-only detection is never even called for
  a process-creation event.
- `run_all_detections` — a full sweep over a time range, for the manual
  "/detections/run" endpoint and for replaying lab-simulated telemetry.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import structlog
from sqlalchemy.orm import Session

from app.detections.base import DetectionDefinition, DetectionMatch
from app.detections.registry import DETECTION_REGISTRY
from app.models.detection import Detection, DetectionRule
from app.models.event import Event

log = structlog.get_logger()


def sync_detection_rules(db: Session, registry: list[DetectionDefinition] | None = None) -> dict[str, DetectionRule]:
    """
    Idempotent upsert of DETECTION_REGISTRY into `detection_rules`,
    mirroring the pattern app/db/seed.py uses for agent identities: the
    DB row is always brought in line with what's in code/YAML rather than
    being hand-edited, so there's exactly one source of truth for "what
    detections exist."
    """
    registry = registry if registry is not None else DETECTION_REGISTRY
    existing = {r.rule_id: r for r in db.query(DetectionRule).all()}

    for definition in registry:
        row = existing.get(definition.rule_id)
        if row is None:
            row = DetectionRule(rule_id=definition.rule_id)
            db.add(row)

        row.title = definition.title
        row.description = definition.description
        row.engine = definition.engine
        row.level = definition.level
        row.base_risk_score = definition.base_risk_score
        row.mitre_technique_ids = list(definition.mitre_technique_ids)
        row.source_path = getattr(definition, "source_path", None)
        row.logsource = getattr(definition, "logsource", {}) or {}
        row.detection_definition = {"relevant_categories": sorted(definition.relevant_categories)}
        # A rule that no longer appears in the registry keeps whatever
        # `enabled` state an admin last set — sync never silently
        # re-enables/disables rules a human explicitly toggled.
        existing[definition.rule_id] = row

    db.commit()
    log.info("detection_rules_synced", rule_count=len(registry))
    return {r.rule_id: r for r in db.query(DetectionRule).all()}


def _dispatch_table(registry: list[DetectionDefinition]) -> dict[str, list[DetectionDefinition]]:
    table: dict[str, list[DetectionDefinition]] = {}
    for definition in registry:
        for category in definition.relevant_categories:
            table.setdefault(category, []).append(definition)
    return table


_DISPATCH_TABLE = _dispatch_table(DETECTION_REGISTRY)


def run_detections_for_event(
    db: Session,
    *,
    organization_id: uuid.UUID,
    event: Event,
    rules_by_id: dict[str, DetectionRule] | None = None,
) -> list[Detection]:
    """
    Runs every detection relevant to `event.category` against it, persists
    a `Detection` row per match, and returns the created rows. Detections
    whose corresponding DetectionRule is disabled are skipped. Errors in
    one detection are logged and do not prevent the others from running —
    a bug in one behavioral heuristic must not silently blind the rest of
    the detection engine.
    """
    candidates = _DISPATCH_TABLE.get(event.category, [])
    if not candidates:
        return []

    if rules_by_id is None:
        rules_by_id = {r.rule_id: r for r in db.query(DetectionRule).all()}

    created: list[Detection] = []
    for definition in candidates:
        rule_row = rules_by_id.get(definition.rule_id)
        if rule_row is not None and not rule_row.enabled:
            continue
        if rule_row is None:
            # Rule hasn't been synced to the DB yet (e.g. fresh test DB
            # that hasn't run seed/sync) — sync on demand so detections
            # still fire rather than silently no-op.
            rule_row = _sync_single_rule(db, definition)
            rules_by_id[definition.rule_id] = rule_row

        try:
            matches: list[DetectionMatch] = definition.run(db, organization_id=organization_id, triggering_event=event)
        except Exception:  # noqa: BLE001 — one bad detection must not blind the rest
            log.exception("detection_run_failed", rule_id=definition.rule_id, event_id=str(event.id))
            continue

        for match in matches:
            detection = Detection(
                organization_id=organization_id,
                rule_id=rule_row.id,
                matched_event_ids=[str(i) for i in match.matched_event_ids],
                host_name=match.host_name,
                user=match.user,
                fired_at=match.fired_at,
                evidence_summary=match.evidence_summary,
                risk_score=match.risk_score_override if match.risk_score_override is not None else definition.base_risk_score,
            )
            db.add(detection)
            created.append(detection)
            log.info(
                "detection_fired",
                rule_id=definition.rule_id,
                event_id=str(event.id),
                risk_score=detection.risk_score,
            )

    if created:
        db.commit()
        for d in created:
            db.refresh(d)
    return created


def _sync_single_rule(db: Session, definition: DetectionDefinition) -> DetectionRule:
    row = DetectionRule(
        rule_id=definition.rule_id,
        title=definition.title,
        description=definition.description,
        engine=definition.engine,
        level=definition.level,
        base_risk_score=definition.base_risk_score,
        mitre_technique_ids=list(definition.mitre_technique_ids),
        source_path=getattr(definition, "source_path", None),
        logsource=getattr(definition, "logsource", {}) or {},
        detection_definition={"relevant_categories": sorted(definition.relevant_categories)},
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


_SWEEP_PAGE_SIZE = 500


def run_all_detections(
    db: Session,
    *,
    organization_id: uuid.UUID,
    since: datetime | None = None,
) -> list[Detection]:
    """
    Full sweep: re-evaluate every relevant event in [since, now] against
    the full registry. Used by the manual "/detections/run" endpoint and
    for replaying attack-simulation-lab telemetry after the fact — not on
    the ingestion hot path.

    Events are fetched in pages of _SWEEP_PAGE_SIZE rather than loading
    the entire result set into memory — a common failure mode on deployments
    with large event tables and a wide `since` window.
    """
    since = since or (datetime.now(timezone.utc) - timedelta(hours=24))
    rules_by_id = {r.rule_id: r for r in db.query(DetectionRule).all()}

    created: list[Detection] = []
    offset = 0
    while True:
        events = (
            db.query(Event)
            .filter(Event.organization_id == organization_id, Event.event_timestamp >= since)
            .order_by(Event.event_timestamp.asc())
            .offset(offset)
            .limit(_SWEEP_PAGE_SIZE)
            .all()
        )
        if not events:
            break
        for event in events:
            created.extend(run_detections_for_event(db, organization_id=organization_id, event=event, rules_by_id=rules_by_id))
        if len(events) < _SWEEP_PAGE_SIZE:
            break
        offset += _SWEEP_PAGE_SIZE
    return created
