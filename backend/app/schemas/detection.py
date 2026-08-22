import uuid
from datetime import datetime

from pydantic import BaseModel


class DetectionRuleOut(BaseModel):
    id: uuid.UUID
    rule_id: str
    title: str
    description: str
    engine: str
    level: str
    status: str
    enabled: bool
    mitre_technique_ids: list[str]
    base_risk_score: int
    source_path: str | None

    model_config = {"from_attributes": True}


class DetectionOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID | None
    rule_id: uuid.UUID
    matched_event_ids: list[str]
    host_name: str | None
    user: str | None
    fired_at: datetime
    evidence_summary: dict
    risk_score: int

    model_config = {"from_attributes": True}


class DetectionRunResponse(BaseModel):
    detections_fired: int
    detection_ids: list[uuid.UUID]
