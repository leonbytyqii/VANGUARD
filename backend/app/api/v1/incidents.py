"""
Incident-response API (Phase 9).

RBAC mapping, and why it is what it is:

| route group                     | permission          |
|---------------------------------|---------------------|
| read anything                   | `incidents.read`    |
| create / promote                | `incidents.create`  |
| edit fields, status, notes,     | `incidents.update`  |
| tasks, alert links              |                     |
| assign, **reopen a closed case**| `incidents.assign`  |

Reopening is gated on `incidents.assign` rather than `incidents.update`
deliberately. Closing a case with a classification is line-analyst work;
overturning a closure verdict that has already been recorded — and that
the SOC's false-positive metrics are computed from — is a supervisory
act. Putting it behind the permission SOC Managers already hold gets that
without inventing a permission that would need its own migration and role
grants.

There is **no** POST/PATCH/DELETE for the timeline. Timeline entries are
written only by the service layer, from inside the operation they
describe (`app/services/incident_timeline.py`), which is what stops the
case file being editable after the fact by whoever is holding the
incident.
"""
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from app.core.deps import get_client_ip, require_permission
from app.core.scope import scoped_query
from app.db.session import get_db
from app.models.ai import AIInvestigation
from app.models.automation import ResponseAction
from app.models.incident import Incident, IncidentEvent, IncidentNote, IncidentTask
from app.models.threat_intel import IOC
from app.models.user import User
from app.schemas.incident import (
    IncidentAssignRequest,
    IncidentCreateRequest,
    IncidentDetailOut,
    IncidentFromInvestigationRequest,
    IncidentLinkAlertsRequest,
    IncidentMetricsOut,
    IncidentNoteCreateRequest,
    IncidentNoteOut,
    IncidentOut,
    IncidentPromotionOut,
    IncidentStatusUpdateRequest,
    IncidentTaskCreateRequest,
    IncidentTaskOut,
    IncidentTaskUpdateRequest,
    IncidentTimelineEntryOut,
    IncidentUpdateRequest,
    format_incident_reference,
)
from app.schemas.response_action import ResponseActionOut
from app.schemas.threat_intel import IncidentIOCAttachRequest, IOCOut
from app.services.incidents import (
    IncidentError,
    add_note,
    assign_incident,
    compute_incident_metrics,
    create_incident,
    create_task,
    delete_task,
    link_alerts,
    promote_investigation_to_incident,
    transition_incident_status,
    unlink_alert,
    update_incident_fields,
    update_task,
)
from app.services.threat_intel import (
    ThreatIntelError,
    attach_ioc_to_incident,
    detach_ioc_from_incident,
)

router = APIRouter(prefix="/incidents", tags=["incidents"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_scoped_incident(db: Session, incident_id: uuid.UUID, current_user: User) -> Incident:
    incident = scoped_query(db, Incident, current_user).filter(Incident.id == incident_id).one_or_none()
    if incident is None:
        # 404 (not 403) whether the id doesn't exist or belongs to another
        # organization — see app/core/scope.py's docstring on why.
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


def _get_scoped_task(db: Session, incident: Incident, task_id: uuid.UUID) -> IncidentTask:
    """
    Tasks are reached only *through* an already-tenant-checked incident, so
    a task id from another org cannot be operated on by pairing it with an
    incident id from the caller's own org.
    """
    task = (
        db.query(IncidentTask)
        .filter(IncidentTask.id == task_id, IncidentTask.incident_id == incident.id)
        .one_or_none()
    )
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    return task


def _resolve_org_user(db: Session, user_id: uuid.UUID, current_user: User) -> User:
    """
    `User` carries `organization_id` directly rather than via
    TenantScopedMixin, so it is scoped explicitly here instead of through
    `scoped_query`.
    """
    user = (
        db.query(User)
        .filter(User.id == user_id, User.organization_id == current_user.organization_id)
        .one_or_none()
    )
    if user is None:
        raise HTTPException(status_code=422, detail="User not found in your organization")
    return user


def _serialize(incident: Incident) -> IncidentOut:
    out = IncidentOut.model_validate(incident)
    out.reference = format_incident_reference(incident.incident_number)
    out.alert_ids = [a.id for a in incident.alerts]
    out.mitre_technique_ids = sorted(t.technique_id for t in incident.mitre_techniques)
    return out


def _serialize_detail(db: Session, incident: Incident) -> IncidentDetailOut:
    base = _serialize(incident)
    return IncidentDetailOut(
        **base.model_dump(),
        metrics=IncidentMetricsOut(**compute_incident_metrics(db, incident)),
    )


def _raise(exc: IncidentError) -> None:
    raise HTTPException(status_code=exc.status_code, detail=str(exc))


# ---------------------------------------------------------------------------
# Incident CRUD + lifecycle
# ---------------------------------------------------------------------------


@router.get("", response_model=list[IncidentOut])
def list_incidents(
    status: str | None = None,
    severity: str | None = None,
    assigned_to_id: uuid.UUID | None = None,
    open_only: bool = False,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("incidents.read")),
):
    q = scoped_query(db, Incident, current_user)
    if status:
        q = q.filter(Incident.status == status)
    if severity:
        q = q.filter(Incident.severity == severity)
    if assigned_to_id:
        q = q.filter(Incident.assigned_to_id == assigned_to_id)
    if open_only:
        q = q.filter(Incident.status != "closed")
    incidents = q.order_by(Incident.created_at.desc()).offset(offset).limit(limit).all()
    return [_serialize(i) for i in incidents]


@router.post("", response_model=IncidentDetailOut, status_code=201)
def create_incident_endpoint(
    payload: IncidentCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("incidents.create")),
):
    try:
        incident = create_incident(
            db,
            organization_id=current_user.organization_id,
            title=payload.title,
            summary=payload.summary,
            severity=payload.severity,
            created_by=current_user,
            alert_ids=payload.alert_ids,
            seed_checklist=payload.seed_checklist,
            source_ip=get_client_ip(request),
        )
    except IncidentError as exc:
        _raise(exc)
    return _serialize_detail(db, incident)


@router.post("/from-investigation", response_model=IncidentPromotionOut, status_code=201)
def create_incident_from_investigation(
    payload: IncidentFromInvestigationRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("incidents.create")),
):
    """
    Promote a completed AI investigation into a case file.

    Requires `ai.read` in addition to `incidents.create`: this reads an AI
    investigation's stored conclusion, so a role that is not allowed to
    see investigation output must not be able to launder it into an
    incident it *is* allowed to read.
    """
    if not current_user.has_permission("ai.read"):
        raise HTTPException(status_code=403, detail="Missing required permission: ai.read")

    investigation = (
        scoped_query(db, AIInvestigation, current_user)
        .filter(AIInvestigation.id == payload.investigation_id)
        .one_or_none()
    )
    if investigation is None:
        raise HTTPException(status_code=404, detail="Investigation not found")

    try:
        incident, report = promote_investigation_to_incident(
            db,
            investigation,
            actor=current_user,
            title=payload.title,
            source_ip=get_client_ip(request),
        )
    except IncidentError as exc:
        _raise(exc)

    return IncidentPromotionOut(
        incident=_serialize_detail(db, incident),
        investigation_id=investigation.id,
        evidence_recorded=report["evidence_recorded"],
        evidence_rejected=report["evidence_rejected"],
        rejected_details=report["rejected_details"],
        response_actions_attached=report["response_actions_attached"],
        hypotheses=report["hypotheses"],
    )


@router.get("/{incident_id}", response_model=IncidentDetailOut)
def get_incident(
    incident_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("incidents.read")),
):
    incident = _get_scoped_incident(db, incident_id, current_user)
    return _serialize_detail(db, incident)


@router.get("/{incident_id}/metrics", response_model=IncidentMetricsOut)
def get_incident_metrics(
    incident_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("incidents.read")),
):
    incident = _get_scoped_incident(db, incident_id, current_user)
    return IncidentMetricsOut(**compute_incident_metrics(db, incident))


@router.patch("/{incident_id}", response_model=IncidentDetailOut)
def update_incident(
    incident_id: uuid.UUID,
    payload: IncidentUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("incidents.update")),
):
    incident = _get_scoped_incident(db, incident_id, current_user)
    try:
        incident = update_incident_fields(
            db,
            incident,
            actor=current_user,
            title=payload.title,
            summary=payload.summary,
            severity=payload.severity,
            source_ip=get_client_ip(request),
        )
    except IncidentError as exc:
        _raise(exc)
    return _serialize_detail(db, incident)


@router.patch("/{incident_id}/status", response_model=IncidentDetailOut)
def update_incident_status(
    incident_id: uuid.UUID,
    payload: IncidentStatusUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("incidents.update")),
):
    incident = _get_scoped_incident(db, incident_id, current_user)

    # Reopening a closed case is a supervisory act — see this module's
    # docstring. The permission is resolved here and handed to the service
    # as an explicit flag rather than the service reaching for the request
    # context, so the service stays callable from non-HTTP code paths.
    reopen_authorized = current_user.has_permission("incidents.assign")
    if incident.status == "closed" and not reopen_authorized:
        raise HTTPException(
            status_code=403,
            detail="Reopening a closed incident requires the 'incidents.assign' permission",
        )

    try:
        incident = transition_incident_status(
            db,
            incident,
            new_status=payload.status,
            actor=current_user,
            closure_classification=payload.closure_classification,
            closure_summary=payload.closure_summary,
            reopen_authorized=reopen_authorized,
            source_ip=get_client_ip(request),
        )
    except IncidentError as exc:
        _raise(exc)
    return _serialize_detail(db, incident)


@router.patch("/{incident_id}/assign", response_model=IncidentDetailOut)
def assign_incident_endpoint(
    incident_id: uuid.UUID,
    payload: IncidentAssignRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("incidents.assign")),
):
    incident = _get_scoped_incident(db, incident_id, current_user)
    assignee = _resolve_org_user(db, payload.assigned_to_id, current_user)
    incident = assign_incident(
        db, incident, assignee=assignee, actor=current_user, source_ip=get_client_ip(request)
    )
    return _serialize_detail(db, incident)


# ---------------------------------------------------------------------------
# Alert linkage
# ---------------------------------------------------------------------------


@router.post("/{incident_id}/alerts", response_model=IncidentDetailOut)
def link_incident_alerts(
    incident_id: uuid.UUID,
    payload: IncidentLinkAlertsRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("incidents.update")),
):
    incident = _get_scoped_incident(db, incident_id, current_user)
    try:
        link_alerts(
            db,
            incident,
            alert_ids=payload.alert_ids,
            actor=current_user,
            source_ip=get_client_ip(request),
        )
    except IncidentError as exc:
        _raise(exc)
    return _serialize_detail(db, incident)


@router.delete("/{incident_id}/alerts/{alert_id}", response_model=IncidentDetailOut)
def unlink_incident_alert(
    incident_id: uuid.UUID,
    alert_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("incidents.update")),
):
    incident = _get_scoped_incident(db, incident_id, current_user)
    try:
        unlink_alert(
            db, incident, alert_id=alert_id, actor=current_user, source_ip=get_client_ip(request)
        )
    except IncidentError as exc:
        _raise(exc)
    return _serialize_detail(db, incident)


# ---------------------------------------------------------------------------
# Notes
# ---------------------------------------------------------------------------


@router.get("/{incident_id}/notes", response_model=list[IncidentNoteOut])
def list_incident_notes(
    incident_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("incidents.read")),
):
    incident = _get_scoped_incident(db, incident_id, current_user)
    notes = (
        db.query(IncidentNote)
        .filter(IncidentNote.incident_id == incident.id)
        .order_by(IncidentNote.created_at.asc())
        .all()
    )
    return [IncidentNoteOut.model_validate(n) for n in notes]


@router.post("/{incident_id}/notes", response_model=IncidentNoteOut, status_code=201)
def add_incident_note(
    incident_id: uuid.UUID,
    payload: IncidentNoteCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("incidents.update")),
):
    incident = _get_scoped_incident(db, incident_id, current_user)
    note = add_note(
        db,
        incident,
        body=payload.body,
        author=current_user,
        # Hard-coded, never read from the request. A human-authored note
        # cannot be made to render as AI-authored, and AI narrative cannot
        # be posted through this route at all.
        is_ai_generated=False,
        source_ip=get_client_ip(request),
    )
    return IncidentNoteOut.model_validate(note)


# ---------------------------------------------------------------------------
# Tasks
# ---------------------------------------------------------------------------


@router.get("/{incident_id}/tasks", response_model=list[IncidentTaskOut])
def list_incident_tasks(
    incident_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("incidents.read")),
):
    incident = _get_scoped_incident(db, incident_id, current_user)
    tasks = (
        db.query(IncidentTask)
        .filter(IncidentTask.incident_id == incident.id)
        .order_by(IncidentTask.sort_order.asc(), IncidentTask.created_at.asc())
        .all()
    )
    return [IncidentTaskOut.model_validate(t) for t in tasks]


@router.post("/{incident_id}/tasks", response_model=IncidentTaskOut, status_code=201)
def create_incident_task(
    incident_id: uuid.UUID,
    payload: IncidentTaskCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("incidents.update")),
):
    incident = _get_scoped_incident(db, incident_id, current_user)
    assignee = (
        _resolve_org_user(db, payload.assigned_to_id, current_user) if payload.assigned_to_id else None
    )
    try:
        task = create_task(
            db,
            incident,
            title=payload.title,
            description=payload.description,
            category=payload.category,
            assignee=assignee,
            sort_order=payload.sort_order,
            actor=current_user,
            source_ip=get_client_ip(request),
        )
    except IncidentError as exc:
        _raise(exc)
    return IncidentTaskOut.model_validate(task)


@router.patch("/{incident_id}/tasks/{task_id}", response_model=IncidentTaskOut)
def update_incident_task(
    incident_id: uuid.UUID,
    task_id: uuid.UUID,
    payload: IncidentTaskUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("incidents.update")),
):
    incident = _get_scoped_incident(db, incident_id, current_user)
    task = _get_scoped_task(db, incident, task_id)
    assignee = (
        _resolve_org_user(db, payload.assigned_to_id, current_user) if payload.assigned_to_id else None
    )
    try:
        task = update_task(
            db,
            incident,
            task,
            actor=current_user,
            title=payload.title,
            description=payload.description,
            category=payload.category,
            done=payload.done,
            assignee=assignee,
            clear_assignee=payload.clear_assignee,
            source_ip=get_client_ip(request),
        )
    except IncidentError as exc:
        _raise(exc)
    return IncidentTaskOut.model_validate(task)


@router.delete("/{incident_id}/tasks/{task_id}", status_code=204)
def delete_incident_task(
    incident_id: uuid.UUID,
    task_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("incidents.update")),
):
    incident = _get_scoped_incident(db, incident_id, current_user)
    task = _get_scoped_task(db, incident, task_id)
    delete_task(db, incident, task, actor=current_user, source_ip=get_client_ip(request))
    return None


# ---------------------------------------------------------------------------
# Timeline + response actions (read-only)
# ---------------------------------------------------------------------------


@router.get("/{incident_id}/timeline", response_model=list[IncidentTimelineEntryOut])
def get_incident_timeline(
    incident_id: uuid.UUID,
    kind: str | None = None,
    limit: int = Query(200, ge=1, le=1000),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("incidents.read")),
):
    """
    Read-only by design. There is no companion POST/PATCH/DELETE — see
    this module's docstring and app/services/incident_timeline.py.
    """
    incident = _get_scoped_incident(db, incident_id, current_user)
    q = db.query(IncidentEvent).filter(IncidentEvent.incident_id == incident.id)
    if kind:
        q = q.filter(IncidentEvent.kind == kind)
    entries = q.order_by(IncidentEvent.event_timestamp.asc(), IncidentEvent.created_at.asc()).limit(limit).all()
    return [IncidentTimelineEntryOut.model_validate(e) for e in entries]


@router.get("/{incident_id}/response-actions", response_model=list[ResponseActionOut])
def list_incident_response_actions(
    incident_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("incidents.read")),
):
    """
    Surfacing the containment actions attached to a case. Read-only:
    requesting, approving, and executing all stay on `/api/v1/response/*`
    behind `response.request` / `response.approve`, so nothing about
    reading a case file widens what its reader can cause to happen.
    """
    incident = _get_scoped_incident(db, incident_id, current_user)
    actions = (
        db.query(ResponseAction)
        .filter(
            ResponseAction.incident_id == incident.id,
            ResponseAction.organization_id == current_user.organization_id,
        )
        .order_by(ResponseAction.created_at.desc())
        .all()
    )
    return [ResponseActionOut.model_validate(a) for a in actions]


# ---------------------------------------------------------------------------
# Indicators attached to a case (Phase 10)
# ---------------------------------------------------------------------------


@router.get("/{incident_id}/iocs", response_model=list[IOCOut])
def list_incident_iocs(
    incident_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("incidents.read")),
):
    incident = _get_scoped_incident(db, incident_id, current_user)
    return [IOCOut.model_validate(i) for i in incident.iocs]


@router.post("/{incident_id}/iocs", response_model=list[IOCOut], status_code=201)
def attach_incident_ioc(
    incident_id: uuid.UUID,
    payload: IncidentIOCAttachRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("incidents.update")),
):
    """
    Both objects are resolved through `scoped_query` before they meet, so
    a cross-tenant attachment cannot be assembled by pairing an incident
    id from your org with an IOC id from another.
    """
    incident = _get_scoped_incident(db, incident_id, current_user)
    ioc = scoped_query(db, IOC, current_user).filter(IOC.id == payload.ioc_id).one_or_none()
    if ioc is None:
        raise HTTPException(status_code=404, detail="IOC not found")

    try:
        attach_ioc_to_incident(
            db, incident, ioc, actor=current_user, source_ip=get_client_ip(request)
        )
    except ThreatIntelError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc))

    db.refresh(incident)
    return [IOCOut.model_validate(i) for i in incident.iocs]


@router.delete("/{incident_id}/iocs/{ioc_id}", status_code=204)
def detach_incident_ioc(
    incident_id: uuid.UUID,
    ioc_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("incidents.update")),
):
    incident = _get_scoped_incident(db, incident_id, current_user)
    ioc = scoped_query(db, IOC, current_user).filter(IOC.id == ioc_id).one_or_none()
    if ioc is None:
        raise HTTPException(status_code=404, detail="IOC not found")
    try:
        detach_ioc_from_incident(db, incident, ioc, actor=current_user, source_ip=get_client_ip(request))
    except ThreatIntelError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc))
    return None
