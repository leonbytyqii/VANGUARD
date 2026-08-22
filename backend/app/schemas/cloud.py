"""Cloud / IAM request-response contracts (Phase 11)."""
import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class CloudIdentityOut(BaseModel):
    id: uuid.UUID
    provider: str
    account_id: str
    identity_type: str
    identity_name: str
    arn: str | None
    #: Heuristic, inferred from naming — the platform has no IAM policy
    #: fetch, so this is a hint for triage ordering, not an authoritative
    #: statement about effective permissions. See docs/CLOUD_IAM.md.
    is_privileged: bool
    attached_policies: list[str]
    effective_permissions: list[str]
    first_seen_at: datetime | None
    last_seen_at: datetime | None

    model_config = {"from_attributes": True}


class CloudEventOut(BaseModel):
    id: uuid.UUID
    event_id: uuid.UUID | None
    event_timestamp: datetime
    provider: str
    account_id: str
    region: str | None
    event_name: str
    event_source: str
    actor_identity: str | None
    actor_arn: str | None
    assumed_role_arn: str | None
    source_ip: str | None
    user_agent: str | None
    error_code: str | None
    request_parameters: dict[str, Any]
    response_elements: dict[str, Any]

    model_config = {"from_attributes": True}


class CloudIdentityDetailOut(CloudIdentityOut):
    recent_activity: list[CloudEventOut] = Field(default_factory=list)
    roles_assumed: list[str] = Field(default_factory=list)


class AttackPathBuildRequest(BaseModel):
    account_id: str = Field(min_length=1, max_length=64)
    seed_identity: str = Field(min_length=1, max_length=255)
    #: Defaults to "the last `window_hours`" when omitted.
    start_time: datetime | None = None
    window_hours: int = Field(default=24, ge=1, le=168)
    alert_id: uuid.UUID | None = None
    incident_id: uuid.UUID | None = None


class AttackPathOut(BaseModel):
    id: uuid.UUID
    title: str
    severity: str
    #: Nodes are identities, roles, and resources; edges carry the
    #: `cloud_event_id` they were derived from, so nothing in the graph is
    #: an inference without a citable row behind it.
    path_nodes: list[dict[str, Any]]
    path_edges: list[dict[str, Any]]
    privilege_escalation_detected: bool
    #: Plain-language rendering of the chain, including an explicit
    #: TRUNCATED warning when the walk hit its bounds.
    explanation: str
    alert_id: uuid.UUID | None
    incident_id: uuid.UUID | None
    investigation_id: uuid.UUID | None
    created_at: datetime

    model_config = {"from_attributes": True}
