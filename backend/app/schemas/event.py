import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class EventIngestRequest(BaseModel):
    """
    The ingestion API's request shape. Deliberately "semi-normalized" —
    close to what a lightweight forwarder (Sysmon-to-JSON, journald, a
    firewall syslog relay, a CloudTrail subscriber) can produce without
    itself understanding VANGUARD's internal schema — while still requiring
    a `source` field that selects which adapter
    (app/services/ingestion/adapters/) interprets `event_type`/`action`
    and fills in the normalized `category`.

    Every field below is optional except `source` and `timestamp` because
    different sources populate different subsets (a DNS query has no
    `process`; a Sysmon process-creation event has no `domain`). Adapters
    validate that *their* required fields are present and raise a 422 with
    a clear message if not.
    """

    source: str = Field(..., description="One of: windows_sysmon, linux_auth, dns, firewall, cloudtrail, synthetic_lab")
    timestamp: datetime
    event_type: str | None = Field(None, description="Source-specific event type, e.g. 'process_creation', 'AssumeRole'")
    action: str | None = None

    host: str | None = None
    user: str | None = None

    process: str | None = None
    parent_process: str | None = None
    command_line: str | None = None
    process_guid: str | None = None
    parent_process_guid: str | None = None
    file_hash: str | None = None

    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None

    domain: str | None = None
    url: str | None = None

    cloud_account: str | None = None
    cloud_region: str | None = None
    iam_role: str | None = None

    # Anything an adapter needs that isn't modeled above (e.g. raw
    # CloudTrail requestParameters/responseElements). Always preserved
    # verbatim in Event.raw_event alongside every other field, regardless
    # of whether the adapter reads it.
    extra: dict = Field(default_factory=dict)


class EventBatchIngestRequest(BaseModel):
    events: list[EventIngestRequest] = Field(..., max_length=500)


class EventIngestResult(BaseModel):
    index: int
    event_id: uuid.UUID | None = None
    error: str | None = None


class EventBatchIngestResponse(BaseModel):
    accepted: int
    rejected: int
    results: list[EventIngestResult]


class EventOut(BaseModel):
    id: uuid.UUID
    event_timestamp: datetime
    source: str
    category: str
    action: str | None
    event_type: str | None
    host_name_raw: str | None
    user: str | None
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    process: str | None
    parent_process: str | None
    command_line: str | None
    file_hash: str | None
    domain: str | None
    url: str | None
    cloud_account: str | None
    cloud_region: str | None
    iam_role: str | None
    ingested_at: datetime

    model_config = {"from_attributes": True}


class EventDetailOut(EventOut):
    raw_event: dict
