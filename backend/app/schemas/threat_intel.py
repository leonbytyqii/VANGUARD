"""
Threat-intelligence request/response contracts (Phase 10).

`reputation`, `threat_score` and `last_enriched_at` appear on output
models only. They are derived from the provider rows by
`app/threat_intel/registry.py::aggregate` and cannot be supplied by a
caller — a verdict somebody typed in is not intelligence, and letting an
analyst hand-set `threat_score` would make ordering by it meaningless.
"""
import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

IOCTypeLiteral = Literal["ip", "domain", "url", "file_hash"]
ReputationLiteral = Literal["malicious", "suspicious", "clean", "unknown"]


class IOCCreateRequest(BaseModel):
    ioc_type: IOCTypeLiteral
    value: str = Field(min_length=1, max_length=512)
    tags: list[str] = Field(default_factory=list)
    notes: str = ""
    #: Enrich immediately on creation. Default True — an indicator added
    #: without a verdict is an indicator nobody can act on.
    enrich: bool = True


class IOCLookupRequest(BaseModel):
    ioc_type: IOCTypeLiteral
    value: str = Field(min_length=1, max_length=512)
    #: Bypass the cache. Costs a real provider call, so it is opt-in.
    force_refresh: bool = False


class IOCUpdateRequest(BaseModel):
    tags: list[str] | None = None
    notes: str | None = None
    #: Retire an indicator without deleting it — deleting would orphan
    #: the incidents that cite it.
    is_active: bool | None = None


class EnrichmentOut(BaseModel):
    provider: str
    reputation: str
    confidence: float
    queried_at: datetime
    expires_at: datetime | None
    lookup_failed: bool
    error: str | None
    raw_response: dict[str, Any]

    model_config = {"from_attributes": True}


class IOCOut(BaseModel):
    id: uuid.UUID
    ioc_type: str
    value: str
    reputation: str
    threat_score: int
    is_active: bool
    tags: list[str]
    notes: str
    first_seen_at: datetime
    last_seen_at: datetime
    last_enriched_at: datetime | None
    related_alert_ids: list[str]
    related_incident_ids: list[str]
    created_at: datetime

    model_config = {"from_attributes": True}


class IOCDetailOut(IOCOut):
    enrichments: list[EnrichmentOut] = Field(default_factory=list)


class IOCLookupResponse(BaseModel):
    """
    `from_cache` is part of the contract, not an implementation detail: an
    analyst acting on a verdict is entitled to know whether a provider was
    just asked or whether this is a reused answer up to
    `ENRICHMENT_TTL_HOURS` old.
    """
    ioc: IOCDetailOut
    from_cache: bool


class AlertEnrichmentResponse(BaseModel):
    alert_id: uuid.UUID
    #: Indicators extracted from the events the alert actually cites —
    #: not from every event on the host. See
    #: app/threat_intel/extraction.py.
    extracted: int
    malicious: int
    suspicious: int
    iocs: list[IOCOut] = Field(default_factory=list)


class IncidentIOCAttachRequest(BaseModel):
    ioc_id: uuid.UUID
