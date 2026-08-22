import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class AlertOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID | None
    title: str
    description: str
    severity: str
    risk_score: int
    status: str
    source: str
    detection_id: uuid.UUID | None
    host_name: str | None
    user: str | None
    evidence: dict
    related_event_ids: list[str]
    mitre_technique_ids: list[str] = Field(
        default_factory=list, description="Relational MITRE tags (Phase 6) — populated separately, not via from_attributes"
    )
    assigned_to_id: uuid.UUID | None
    alert_timestamp: datetime
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class AlertUpdateRequest(BaseModel):
    """
    All fields optional — a PATCH updates only what's provided. Status
    transitions aren't validated against a strict state machine here (see
    docs/RISK_SCORING.md's known-limitations note); the human-in-the-loop
    approval *state machine* that must never be bypassed lives in
    ResponseAction (Phase 2), not here — alert status is analyst
    triage bookkeeping, not a privileged-action gate.
    """
    status: str | None = None
    severity: str | None = None
    assigned_to_id: uuid.UUID | None = None
    analyst_note: str | None = Field(None, description="Appended to evidence['analyst_notes'], not a separate table yet (Phase 9)")
