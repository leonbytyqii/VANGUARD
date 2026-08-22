import uuid
from datetime import datetime

from pydantic import BaseModel


class AuditLogOut(BaseModel):
    id: uuid.UUID
    timestamp: datetime
    actor_id: uuid.UUID | None
    actor_label: str | None
    action: str
    resource_type: str | None
    resource_id: str | None
    outcome: str
    source_ip: str | None
    details: dict

    model_config = {"from_attributes": True}
