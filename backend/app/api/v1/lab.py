"""
Attack-simulation lab API (Phase 14).

Gated on `events.ingest`, which by default only `admin` holds. That is
deliberate: a scenario run injects telemetry that produces real
detections, real alerts, and real incidents-worth of noise in the same
tables an analyst is working from. Letting any analyst manufacture alerts
would make the alert queue untrustworthy as a record of what actually
happened.

Every event a scenario creates is tagged `simulated: true` with its
scenario id in `raw_event`, so synthetic telemetry stays distinguishable
from real telemetry forever after.
"""
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.deps import get_client_ip, require_permission
from app.db.session import get_db
from app.lab.scenarios import SCENARIOS, SCENARIOS_BY_ID
from app.models.user import User
from app.schemas.lab import ScenarioOut, ScenarioRunOut, ScenarioRunRequest
from app.services.lab import run_scenario, serialize_scenario

router = APIRouter(prefix="/lab", tags=["lab"])


@router.get("/scenarios", response_model=list[ScenarioOut])
def list_scenarios(
    _: User = Depends(require_permission("events.ingest")),
):
    return [ScenarioOut(**serialize_scenario(s)) for s in SCENARIOS]


@router.post("/scenarios/{scenario_id}/run", response_model=ScenarioRunOut, status_code=201)
def run_lab_scenario(
    scenario_id: str,
    payload: ScenarioRunRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("events.ingest")),
):
    scenario = SCENARIOS_BY_ID.get(scenario_id)
    if scenario is None:
        raise HTTPException(status_code=404, detail=f"Unknown scenario '{scenario_id}'.")

    result = run_scenario(
        db,
        scenario,
        organization_id=current_user.organization_id,
        actor=current_user,
        start_time=payload.start_time,
        source_ip=get_client_ip(request),
    )

    return ScenarioRunOut(
        scenario_id=result.scenario_id,
        name=result.name,
        started_at=result.started_at,
        events_ingested=result.events_ingested,
        detections_fired=result.detections_fired,
        expected_detections=result.expected_detections,
        missing_detections=result.missing_detections,
        unexpected_detections=result.unexpected_detections,
        alerts_created=result.alerts_created,
        alert_ids=result.alert_ids,
        fully_detected=result.fully_detected,
        errors=result.errors,
    )
