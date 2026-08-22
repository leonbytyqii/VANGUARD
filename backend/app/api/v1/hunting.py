import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.core.deps import get_client_ip, require_permission
from app.core.scope import scoped_query
from app.db.session import get_db
from app.hunting.engine import HuntQueryError, run_hunt, validate_query_definition
from app.models.enums import IOCType
from app.models.event import Event
from app.models.hunting import HuntExecution, HuntQuery
from app.models.user import User
from app.schemas.event import EventOut
from app.schemas.hunting import (
    AdHocHuntRequest,
    HuntExecutionOut,
    HuntQueryCreate,
    HuntQueryOut,
    HuntQueryUpdate,
    HuntRunRequest,
    IOCHuntRequest,
)
from app.services.audit import log_audit_event

router = APIRouter(prefix="/hunting", tags=["hunting"])


def _visible_hunt_queries_query(db: Session, current_user: User):
    """
    Builtin (org-independent, `organization_id IS NULL`) queries union the
    caller's own org's custom queries. `HuntQuery` is deliberately not run
    through `scoped_query` — that helper filters by exact organization_id
    match and would hide the shared builtin library entirely (the same
    reason app/api/v1/mitre.py and app/api/v1/detections.py's rule-catalog
    endpoint don't use it either).
    """
    return db.query(HuntQuery).filter(
        or_(HuntQuery.organization_id.is_(None), HuntQuery.organization_id == current_user.organization_id)
    )


def _get_visible_hunt_query_or_404(db: Session, hunt_query_id: uuid.UUID, current_user: User) -> HuntQuery:
    query = _visible_hunt_queries_query(db, current_user).filter(HuntQuery.id == hunt_query_id).one_or_none()
    if query is None:
        # 404 whether the id doesn't exist or belongs to another org's
        # custom query — see app/core/scope.py's docstring on why
        # confirming cross-tenant existence is itself an IDOR leak.
        raise HTTPException(status_code=404, detail="Hunt query not found")
    return query


@router.get("/queries", response_model=list[HuntQueryOut])
def list_hunt_queries(
    is_builtin: bool | None = None,
    q: str | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("threat_hunting.read")),
):
    query = _visible_hunt_queries_query(db, current_user)
    if is_builtin is not None:
        query = query.filter(HuntQuery.is_builtin == is_builtin)
    if q:
        query = query.filter(HuntQuery.name.ilike(f"%{q}%"))
    rows = query.order_by(HuntQuery.is_builtin.desc(), HuntQuery.name.asc()).all()
    return [HuntQueryOut.model_validate(r) for r in rows]


@router.post("/queries", response_model=HuntQueryOut, status_code=201)
def create_hunt_query(
    payload: HuntQueryCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("threat_hunting.write")),
):
    try:
        validate_query_definition(payload.query_definition)
    except HuntQueryError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    hunt_query = HuntQuery(
        organization_id=current_user.organization_id,
        name=payload.name,
        description=payload.description,
        is_builtin=False,
        query_definition=payload.query_definition,
        default_lookback_hours=payload.default_lookback_hours,
        mitre_technique_ids=list(payload.mitre_technique_ids),
        created_by_id=current_user.id,
    )
    db.add(hunt_query)
    db.commit()
    db.refresh(hunt_query)

    log_audit_event(
        db, action="hunt_query_created", actor_id=current_user.id, actor_label=current_user.email,
        resource_type="hunt_query", resource_id=str(hunt_query.id), outcome="success",
        source_ip=get_client_ip(request), details={"name": hunt_query.name},
    )
    return HuntQueryOut.model_validate(hunt_query)


@router.get("/queries/{hunt_query_id}", response_model=HuntQueryOut)
def get_hunt_query(
    hunt_query_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("threat_hunting.read")),
):
    return HuntQueryOut.model_validate(_get_visible_hunt_query_or_404(db, hunt_query_id, current_user))


@router.patch("/queries/{hunt_query_id}", response_model=HuntQueryOut)
def update_hunt_query(
    hunt_query_id: uuid.UUID,
    payload: HuntQueryUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("threat_hunting.write")),
):
    hunt_query = _get_visible_hunt_query_or_404(db, hunt_query_id, current_user)
    if hunt_query.is_builtin:
        raise HTTPException(status_code=403, detail="Built-in hunt queries cannot be edited")
    if hunt_query.organization_id != current_user.organization_id:
        # Unreachable given _get_visible_hunt_query_or_404's own filter,
        # but kept explicit: never edit another org's custom query.
        raise HTTPException(status_code=404, detail="Hunt query not found")

    updates = payload.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(status_code=422, detail="No fields to update")

    if "query_definition" in updates:
        try:
            validate_query_definition(updates["query_definition"])
        except HuntQueryError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    changes: dict = {}
    for field, value in updates.items():
        changes[field] = True if field == "query_definition" else {"from": getattr(hunt_query, field), "to": value}
        setattr(hunt_query, field, value)

    db.add(hunt_query)
    db.commit()
    db.refresh(hunt_query)

    log_audit_event(
        db, action="hunt_query_updated", actor_id=current_user.id, actor_label=current_user.email,
        resource_type="hunt_query", resource_id=str(hunt_query.id), outcome="success",
        source_ip=get_client_ip(request), details=changes,
    )
    return HuntQueryOut.model_validate(hunt_query)


@router.delete("/queries/{hunt_query_id}", status_code=204)
def delete_hunt_query(
    hunt_query_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("threat_hunting.write")),
):
    hunt_query = _get_visible_hunt_query_or_404(db, hunt_query_id, current_user)
    if hunt_query.is_builtin:
        raise HTTPException(status_code=403, detail="Built-in hunt queries cannot be deleted")
    if hunt_query.organization_id != current_user.organization_id:
        raise HTTPException(status_code=404, detail="Hunt query not found")

    db.delete(hunt_query)
    db.commit()

    log_audit_event(
        db, action="hunt_query_deleted", actor_id=current_user.id, actor_label=current_user.email,
        resource_type="hunt_query", resource_id=str(hunt_query_id), outcome="success",
        source_ip=get_client_ip(request),
    )
    return None


@router.post("/queries/{hunt_query_id}/run", response_model=HuntExecutionOut, status_code=201)
def run_saved_hunt_query(
    hunt_query_id: uuid.UUID,
    payload: HuntRunRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("threat_hunting.execute")),
):
    hunt_query = _get_visible_hunt_query_or_404(db, hunt_query_id, current_user)

    now = datetime.now(timezone.utc)
    time_range_end = payload.time_range_end or now
    time_range_start = payload.time_range_start or (time_range_end - timedelta(hours=hunt_query.default_lookback_hours))

    try:
        execution = run_hunt(
            db,
            organization_id=current_user.organization_id,
            query_definition=hunt_query.query_definition,
            time_range_start=time_range_start,
            time_range_end=time_range_end,
            category_filter=payload.category_filter,
            executed_by_id=current_user.id,
            hunt_query_id=hunt_query.id,
        )
    except HuntQueryError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return HuntExecutionOut.model_validate(execution)


@router.post("/run", response_model=HuntExecutionOut, status_code=201)
def run_ad_hoc_hunt(
    payload: AdHocHuntRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("threat_hunting.execute")),
):
    """
    Execute an unsaved query_definition directly — never persisted as a
    HuntQuery, only recorded as the resulting HuntExecution's snapshot.
    The natural "test a hypothesis before saving it" entry point; a
    caller who likes the result can POST /hunting/queries afterward.
    """
    try:
        execution = run_hunt(
            db,
            organization_id=current_user.organization_id,
            query_definition=payload.query_definition,
            time_range_start=payload.time_range_start,
            time_range_end=payload.time_range_end,
            category_filter=payload.category_filter,
            executed_by_id=current_user.id,
            hunt_query_id=None,
        )
    except HuntQueryError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return HuntExecutionOut.model_validate(execution)


def _build_ioc_selection(ioc_type: str, value: str) -> dict:
    """
    Translates an IOC type + value into the Sigma-shaped selection the
    engine expects, so a caller pivoting off an indicator doesn't have to
    hand-write field/modifier syntax for the common "has this indicator
    shown up anywhere?" case. IOC-vs-Event field mapping mirrors
    app/detections/sigma_engine/matcher.py::FIELD_MAP.
    """
    if ioc_type == IOCType.IP.value:
        return {
            "selection_src": {"SourceIp": value},
            "selection_dst": {"DestinationIp": value},
            "condition": "selection_src or selection_dst",
        }
    if ioc_type == IOCType.DOMAIN.value:
        return {"selection": {"QueryName": value}, "condition": "selection"}
    if ioc_type == IOCType.URL.value:
        return {"selection": {"url|contains": value}, "condition": "selection"}
    if ioc_type == IOCType.FILE_HASH.value:
        return {"selection": {"Hashes": value}, "condition": "selection"}
    raise HuntQueryError(f"Unsupported ioc_type '{ioc_type}'. Must be one of: {[t.value for t in IOCType]}")


@router.post("/ioc-search", response_model=HuntExecutionOut, status_code=201)
def hunt_by_ioc(
    payload: IOCHuntRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("threat_hunting.execute")),
):
    try:
        query_definition = _build_ioc_selection(payload.ioc_type, payload.value)
        execution = run_hunt(
            db,
            organization_id=current_user.organization_id,
            query_definition=query_definition,
            time_range_start=payload.time_range_start,
            time_range_end=payload.time_range_end,
            executed_by_id=current_user.id,
            hunt_query_id=None,
        )
    except HuntQueryError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return HuntExecutionOut.model_validate(execution)


@router.get("/executions", response_model=list[HuntExecutionOut])
def list_hunt_executions(
    hunt_query_id: uuid.UUID | None = None,
    status: str | None = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("threat_hunting.read")),
):
    q = scoped_query(db, HuntExecution, current_user)
    if hunt_query_id:
        q = q.filter(HuntExecution.hunt_query_id == hunt_query_id)
    if status:
        q = q.filter(HuntExecution.status == status)
    rows = q.order_by(HuntExecution.started_at.desc()).offset(offset).limit(limit).all()
    return [HuntExecutionOut.model_validate(r) for r in rows]


@router.get("/executions/{execution_id}", response_model=HuntExecutionOut)
def get_hunt_execution(
    execution_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("threat_hunting.read")),
):
    execution = scoped_query(db, HuntExecution, current_user).filter(HuntExecution.id == execution_id).one_or_none()
    if execution is None:
        raise HTTPException(status_code=404, detail="Hunt execution not found")
    return HuntExecutionOut.model_validate(execution)


@router.get("/executions/{execution_id}/events", response_model=list[EventOut])
def get_hunt_execution_events(
    execution_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("threat_hunting.read")),
):
    """Resolves a completed run's matched_event_ids back into full Event rows, so an analyst can actually review the hits, not just their IDs."""
    execution = scoped_query(db, HuntExecution, current_user).filter(HuntExecution.id == execution_id).one_or_none()
    if execution is None:
        raise HTTPException(status_code=404, detail="Hunt execution not found")
    if not execution.matched_event_ids:
        return []

    ids = [uuid.UUID(i) for i in execution.matched_event_ids]
    rows = scoped_query(db, Event, current_user).filter(Event.id.in_(ids)).order_by(Event.event_timestamp.asc()).all()
    return [EventOut.model_validate(r) for r in rows]
