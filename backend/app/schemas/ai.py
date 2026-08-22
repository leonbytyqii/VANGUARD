import uuid
from datetime import datetime

from pydantic import BaseModel


class AIInvestigationCreateRequest(BaseModel):
    alert_id: uuid.UUID


class AIInvestigationOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID | None
    alert_id: uuid.UUID
    status: str
    requested_by_id: uuid.UUID | None
    blueprint_id: uuid.UUID | None
    ai_provider: str
    ai_model: str
    started_at: datetime | None
    completed_at: datetime | None
    result: dict | None
    error: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class AgentEvidenceOut(BaseModel):
    id: uuid.UUID
    step_id: uuid.UUID
    claim: str
    source_tool: str
    source_event_id: uuid.UUID | None
    source_table: str | None
    confidence: float

    model_config = {"from_attributes": True}


class AgentStepOut(BaseModel):
    id: uuid.UUID
    investigation_id: uuid.UUID
    step_number: int
    agent_type: str
    action: str
    tool_input: dict
    tool_output: dict
    reasoning_note: str
    step_started_at: datetime
    step_completed_at: datetime | None
    evidence: list[AgentEvidenceOut] = []

    model_config = {"from_attributes": True}
