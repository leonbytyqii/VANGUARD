"""
Running an attack-simulation scenario (Phase 14).

`run_scenario` replays a scenario's synthetic telemetry through
`app.services.ingestion.service.ingest_event` — the real ingestion path.
Adapters normalize it, the detection engine sweeps it synchronously, risk
scoring runs, alerts are created or reinforced, and CloudTrail-shaped
steps get their Phase 11 cloud projection. Nothing is written directly
into `detections` or `alerts`.

Two consequences worth naming:

1. **A scenario run is an end-to-end test with a UI.** If a detection
   silently stops firing, the scenario stops producing it, and both the
   test suite and anyone clicking "Run" can see that immediately.
2. **The results are honest about partial success.** The response reports
   which of the scenario's `expected_detections` actually fired and which
   did not, rather than reporting "success" because events were accepted.
   Ingestion succeeding tells you nothing about whether detection worked.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.lab.scenarios import Scenario
from app.models.alert import Alert
from app.models.detection import Detection, DetectionRule
from app.models.user import User
from app.schemas.event import EventIngestRequest
from app.services.audit import log_audit_event
from app.services.ingestion.service import IngestionError, ingest_event


class LabError(Exception):
    def __init__(self, message: str, *, status_code: int = 400):
        self.status_code = status_code
        super().__init__(message)


@dataclass
class ScenarioRunResult:
    scenario_id: str
    name: str
    started_at: datetime
    events_ingested: int
    event_ids: list[uuid.UUID]
    detections_fired: list[str]
    expected_detections: list[str]
    missing_detections: list[str]
    unexpected_detections: list[str]
    alerts_created: int
    alert_ids: list[uuid.UUID]
    errors: list[str] = field(default_factory=list)

    @property
    def fully_detected(self) -> bool:
        return not self.missing_detections and not self.errors


def run_scenario(
    db: Session,
    scenario: Scenario,
    *,
    organization_id: uuid.UUID | None,
    actor: User | None = None,
    start_time: datetime | None = None,
    source_ip: str | None = None,
) -> ScenarioRunResult:
    """
    Replay `scenario` as if its telemetry had just arrived.

    `start_time` defaults to "so the scenario finishes now", rather than
    "starts now". Detections correlate over lookback windows ending at the
    present, so a scenario whose events are all in the future — or spread
    forward over the next twenty minutes — would not correlate. Anchoring
    the *end* is what makes a run behave the way real telemetry would.
    """
    span = max((step.offset_minutes for step in scenario.steps), default=0.0)
    anchor = start_time or (datetime.now(timezone.utc) - timedelta(minutes=span))

    started_at = datetime.now(timezone.utc)
    event_ids: list[uuid.UUID] = []
    errors: list[str] = []

    for index, step in enumerate(scenario.steps):
        payload = dict(step.payload)
        payload["timestamp"] = (anchor + timedelta(minutes=step.offset_minutes)).isoformat()
        # Marked in the raw payload so a synthetic event is always
        # distinguishable from real telemetry after the fact. `raw_event`
        # preserves this verbatim.
        extra = dict(payload.get("extra") or {})
        extra.update({"simulated": True, "scenario_id": scenario.scenario_id, "scenario_step": index})
        payload["extra"] = extra

        try:
            event = ingest_event(
                db, organization_id=organization_id, payload=EventIngestRequest.model_validate(payload)
            )
            event_ids.append(event.id)
        except IngestionError as exc:
            errors.append(f"step {index}: {exc}")
        except Exception as exc:  # noqa: BLE001 - one bad step must not abort the whole scenario
            errors.append(f"step {index}: unexpected {type(exc).__name__}: {exc}")

    # `Detection.rule_id` is a UUID foreign key into `detection_rules`;
    # the human-readable rule identifier a scenario declares lives on
    # `DetectionRule.rule_id`. Joining is what makes the comparison
    # meaningful — reading `Detection.rule_id` directly would silently
    # compare UUIDs against rule-name strings and never match.
    fired = sorted(
        {
            row[0]
            for row in db.query(DetectionRule.rule_id)
            .join(Detection, Detection.rule_id == DetectionRule.id)
            .filter(
                Detection.organization_id == organization_id,
                Detection.fired_at >= anchor - timedelta(minutes=1),
            )
            .all()
        }
    )

    alerts = (
        db.query(Alert)
        .filter(Alert.organization_id == organization_id, Alert.created_at >= started_at)
        .all()
    )

    expected = list(scenario.expected_detections)
    result = ScenarioRunResult(
        scenario_id=scenario.scenario_id,
        name=scenario.name,
        started_at=started_at,
        events_ingested=len(event_ids),
        event_ids=event_ids,
        detections_fired=fired,
        expected_detections=expected,
        missing_detections=[r for r in expected if r not in fired],
        unexpected_detections=[r for r in fired if r not in expected],
        alerts_created=len(alerts),
        alert_ids=[a.id for a in alerts],
        errors=errors,
    )

    log_audit_event(
        db,
        action="lab_scenario_run",
        actor_id=actor.id if actor else None,
        actor_label=actor.email if actor else "system",
        resource_type="lab_scenario",
        resource_id=scenario.scenario_id,
        outcome="success" if result.fully_detected else "error",
        source_ip=source_ip,
        details={
            "events_ingested": result.events_ingested,
            "detections_fired": fired,
            "missing_detections": result.missing_detections,
            "alerts_created": result.alerts_created,
            "errors": errors,
        },
    )
    return result


def serialize_scenario(scenario: Scenario) -> dict[str, Any]:
    return {
        "scenario_id": scenario.scenario_id,
        "name": scenario.name,
        "description": scenario.description,
        "expected_detections": list(scenario.expected_detections),
        "mitre_technique_ids": list(scenario.mitre_technique_ids),
        "step_count": len(scenario.steps),
        "sources": sorted({s.payload["source"] for s in scenario.steps}),
        "span_minutes": max((s.offset_minutes for s in scenario.steps), default=0.0),
    }
