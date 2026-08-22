"""Attack-simulation lab contracts (Phase 14)."""
import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class ScenarioOut(BaseModel):
    scenario_id: str
    name: str
    description: str
    expected_detections: list[str]
    mitre_technique_ids: list[str]
    step_count: int
    sources: list[str]
    span_minutes: float


class ScenarioRunRequest(BaseModel):
    """
    `start_time` is exposed for reproducible runs in tests. Left unset,
    the scenario is anchored so its last event lands now, which is what
    makes correlation windows behave the way they would for real
    telemetry.
    """
    start_time: datetime | None = None


class ScenarioRunOut(BaseModel):
    scenario_id: str
    name: str
    started_at: datetime
    events_ingested: int
    detections_fired: list[str]
    expected_detections: list[str]
    #: Expected rules that did NOT fire. A non-empty list is a real
    #: finding about the detection stack, not a cosmetic warning.
    missing_detections: list[str]
    unexpected_detections: list[str]
    alerts_created: int
    alert_ids: list[uuid.UUID]
    fully_detected: bool
    errors: list[str] = Field(default_factory=list)
