import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class HuntQueryCreate(BaseModel):
    name: str
    description: str = ""
    query_definition: dict
    default_lookback_hours: int = Field(24, ge=1, le=24 * 30)
    mitre_technique_ids: list[str] = Field(default_factory=list)


class HuntQueryUpdate(BaseModel):
    """All fields optional — a PATCH updates only what's provided. Never allowed against a builtin query (see api/v1/hunting.py)."""
    name: str | None = None
    description: str | None = None
    query_definition: dict | None = None
    default_lookback_hours: int | None = Field(None, ge=1, le=24 * 30)
    mitre_technique_ids: list[str] | None = None


class HuntQueryOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID | None
    name: str
    description: str
    is_builtin: bool
    query_definition: dict
    default_lookback_hours: int
    mitre_technique_ids: list[str]
    created_by_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class HuntRunRequest(BaseModel):
    """Run a saved HuntQuery. Omit the time range to use `now - default_lookback_hours .. now`."""
    time_range_start: datetime | None = None
    time_range_end: datetime | None = None
    category_filter: str | None = None


class AdHocHuntRequest(BaseModel):
    """Execute an unsaved query_definition directly — never persisted as a HuntQuery, only as the resulting HuntExecution's snapshot."""
    query_definition: dict
    time_range_start: datetime
    time_range_end: datetime
    category_filter: str | None = None


class IOCHuntRequest(BaseModel):
    """
    Convenience wrapper: builds a query_definition server-side from an
    IOC type + value (see app/api/v1/hunting.py::_build_ioc_selection)
    rather than requiring the caller to hand-write a selection dict for
    the common "has this indicator shown up anywhere?" case.
    """
    ioc_type: str  # IOCType: ip | domain | url | file_hash
    value: str
    time_range_start: datetime
    time_range_end: datetime


class HuntExecutionOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID | None
    hunt_query_id: uuid.UUID | None
    query_definition_snapshot: dict
    executed_by_id: uuid.UUID | None
    category_filter: str | None
    time_range_start: datetime
    time_range_end: datetime
    status: str
    scanned_event_count: int
    matched_event_count: int
    matched_event_ids: list[str]
    truncated_scan: bool
    truncated_results: bool
    error: str | None
    started_at: datetime
    completed_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}
