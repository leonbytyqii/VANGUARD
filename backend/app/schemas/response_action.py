import uuid
from datetime import datetime

from pydantic import BaseModel


class ResponseActionCreateRequest(BaseModel):
    action_type: str
    target: str
    justification: str
    incident_id: uuid.UUID | None = None


class ResponseActionRejectRequest(BaseModel):
    reason: str


class ResponseActionOut(BaseModel):
    id: uuid.UUID
    action_type: str
    target: str
    justification: str
    status: str
    requested_by_id: uuid.UUID | None
    requested_by_agent_type: str | None
    approved_by_id: uuid.UUID | None
    approved_at: datetime | None
    rejected_by_id: uuid.UUID | None
    rejected_at: datetime | None
    rejection_reason: str | None
    executed_by_id: uuid.UUID | None
    executed_at: datetime | None
    result: dict
    created_at: datetime

    model_config = {"from_attributes": True}
