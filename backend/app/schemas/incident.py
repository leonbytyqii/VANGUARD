"""
Incident-response request/response contracts (Phase 9).

Note what is absent from every *request* model here: `detected_at`,
`triaged_at`, `contained_at`, `closed_at`, `incident_number`, and
`is_ai_generated`. Those are all server-derived, and leaving them out of
the input schemas is what makes that guarantee structural rather than a
line in a route handler that a later edit could drop. An IR metric a
caller can set is not a measurement, and a note-provenance flag a caller
can set is not provenance.
"""
import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

IncidentSeverityLiteral = Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
IncidentStatusLiteral = Literal[
    "new", "triaged", "investigating", "contained", "eradicated", "recovered", "closed"
]
ClosureClassificationLiteral = Literal[
    "true_positive", "false_positive", "benign_true_positive", "duplicate"
]
TaskCategoryLiteral = Literal[
    "detection_analysis", "containment", "eradication", "recovery", "post_incident"
]


def format_incident_reference(incident_number: int | None) -> str | None:
    """`42 -> "INC-000042"`. Six digits carries a tenant to a million cases."""
    return None if incident_number is None else f"INC-{incident_number:06d}"


# --------------------------------------------------------------------------
# Incident
# --------------------------------------------------------------------------


class IncidentCreateRequest(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    summary: str = ""
    # Optional *only* when alert_ids are supplied — the service derives it
    # from the linked alerts' highest severity in that case. Enforced in
    # app/services/incidents.py::create_incident, not here, because the
    # rule depends on the alerts resolving in the caller's tenant.
    severity: IncidentSeverityLiteral | None = None
    alert_ids: list[uuid.UUID] = Field(default_factory=list)
    seed_checklist: bool = True


class IncidentUpdateRequest(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=255)
    summary: str | None = None
    severity: IncidentSeverityLiteral | None = None


class IncidentStatusUpdateRequest(BaseModel):
    status: IncidentStatusLiteral
    # Required by the service when status == "closed"; validated there so
    # the error message can name the legal classifications.
    closure_classification: ClosureClassificationLiteral | None = None
    closure_summary: str | None = None


class IncidentAssignRequest(BaseModel):
    assigned_to_id: uuid.UUID


class IncidentLinkAlertsRequest(BaseModel):
    alert_ids: list[uuid.UUID] = Field(min_length=1)


class IncidentFromInvestigationRequest(BaseModel):
    investigation_id: uuid.UUID
    title: str | None = Field(default=None, min_length=1, max_length=255)


class IncidentOut(BaseModel):
    id: uuid.UUID
    incident_number: int | None
    reference: str | None = None
    title: str
    summary: str
    status: str
    severity: str
    assigned_to_id: uuid.UUID | None
    created_by_id: uuid.UUID | None = None
    detected_at: datetime | None = None
    triaged_at: datetime | None = None
    contained_at: datetime | None = None
    closed_at: datetime | None = None
    closure_classification: str | None = None
    closure_summary: str | None = None
    created_at: datetime
    updated_at: datetime | None = None
    alert_ids: list[uuid.UUID] = Field(default_factory=list)
    mitre_technique_ids: list[str] = Field(default_factory=list)

    model_config = {"from_attributes": True}


class IncidentMetricsOut(BaseModel):
    """
    Every duration is measured from `detected_at` (first evidence), and is
    `null` — never 0 — where the milestone has not been reached, so an
    un-triaged case is visibly distinct from one triaged instantly.
    """
    detected_at: datetime | None
    triaged_at: datetime | None
    contained_at: datetime | None
    closed_at: datetime | None
    time_to_triage_seconds: int | None
    time_to_contain_seconds: int | None
    time_to_close_seconds: int | None
    open_duration_seconds: int | None
    is_open: bool
    tasks_total: int
    tasks_completed: int
    alert_count: int


class IncidentDetailOut(IncidentOut):
    metrics: IncidentMetricsOut


# --------------------------------------------------------------------------
# Notes / tasks / timeline
# --------------------------------------------------------------------------


class IncidentNoteCreateRequest(BaseModel):
    """
    Deliberately has no `is_ai_generated` field. The route hard-codes it to
    False; the only writer that sets it True is the internal
    investigation-promotion path. See app/models/incident.py::IncidentNote.
    """
    body: str = Field(min_length=1)


class IncidentNoteOut(BaseModel):
    id: uuid.UUID
    incident_id: uuid.UUID
    author_id: uuid.UUID | None
    body: str
    is_ai_generated: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class IncidentTaskCreateRequest(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    description: str = ""
    category: TaskCategoryLiteral = "detection_analysis"
    assigned_to_id: uuid.UUID | None = None
    sort_order: int | None = None


class IncidentTaskUpdateRequest(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = None
    category: TaskCategoryLiteral | None = None
    done: bool | None = None
    assigned_to_id: uuid.UUID | None = None
    # Explicit, because `assigned_to_id: None` is indistinguishable from
    # "field omitted" once the model is built with exclude_unset off.
    clear_assignee: bool = False


class IncidentTaskOut(BaseModel):
    id: uuid.UUID
    incident_id: uuid.UUID
    title: str
    description: str
    category: str
    done: bool
    sort_order: int
    is_from_template: bool
    assigned_to_id: uuid.UUID | None
    completed_at: datetime | None
    completed_by_id: uuid.UUID | None
    created_at: datetime

    model_config = {"from_attributes": True}


class IncidentTimelineEntryOut(BaseModel):
    id: uuid.UUID
    incident_id: uuid.UUID
    event_timestamp: datetime
    kind: str
    actor: str | None
    details: dict[str, Any]

    model_config = {"from_attributes": True}


class IncidentPromotionOut(BaseModel):
    """
    The result of promoting an AI investigation into a case.

    `evidence_rejected` and `rejected_details` are part of the response
    rather than a log line on purpose: a citation that did not resolve to
    a real database row is exactly the thing this platform refuses to let
    pass silently, so the caller is told, in the same response, what was
    dropped and why.
    """
    incident: IncidentDetailOut
    investigation_id: uuid.UUID
    evidence_recorded: int
    evidence_rejected: int
    rejected_details: list[dict[str, Any]] = Field(default_factory=list)
    response_actions_attached: int
    hypotheses: int
