import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.deps import require_permission
from app.core.scope import scoped_query
from app.db.session import get_db
from app.models.event import Event
from app.models.user import User
from app.schemas.event import (
    EventBatchIngestRequest,
    EventBatchIngestResponse,
    EventDetailOut,
    EventIngestRequest,
    EventIngestResult,
    EventOut,
)
from app.services.ingestion.service import IngestionError, ingest_event

router = APIRouter(prefix="/events", tags=["events"])


@router.post("", response_model=EventOut, status_code=201)
def create_event(
    payload: EventIngestRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("events.ingest")),
):
    try:
        event = ingest_event(db, organization_id=current_user.organization_id, payload=payload)
    except IngestionError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc))
    return EventOut.model_validate(event)


@router.post("/batch", response_model=EventBatchIngestResponse, status_code=201)
def create_events_batch(
    payload: EventBatchIngestRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("events.ingest")),
):
    results: list[EventIngestResult] = []
    accepted = 0
    for idx, event_payload in enumerate(payload.events):
        try:
            event = ingest_event(db, organization_id=current_user.organization_id, payload=event_payload)
            results.append(EventIngestResult(index=idx, event_id=event.id))
            accepted += 1
        except IngestionError as exc:
            db.rollback()
            results.append(EventIngestResult(index=idx, error=str(exc)))

    return EventBatchIngestResponse(accepted=accepted, rejected=len(payload.events) - accepted, results=results)


@router.get("", response_model=list[EventOut])
def list_events(
    host: str | None = None,
    user: str | None = None,
    process: str | None = None,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    domain: str | None = None,
    file_hash: str | None = None,
    category: str | None = None,
    source: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("events.read")),
):
    q = scoped_query(db, Event, current_user)
    if host:
        q = q.filter(Event.host_name_raw == host)
    if user:
        q = q.filter(Event.user == user)
    if process:
        q = q.filter(Event.process == process)
    if src_ip:
        q = q.filter(Event.src_ip == src_ip)
    if dst_ip:
        q = q.filter(Event.dst_ip == dst_ip)
    if domain:
        q = q.filter(Event.domain == domain)
    if file_hash:
        q = q.filter(Event.file_hash == file_hash)
    if category:
        q = q.filter(Event.category == category)
    if source:
        q = q.filter(Event.source == source)
    if start_time:
        q = q.filter(Event.event_timestamp >= start_time)
    if end_time:
        q = q.filter(Event.event_timestamp <= end_time)

    events = q.order_by(Event.event_timestamp.desc()).offset(offset).limit(limit).all()
    return [EventOut.model_validate(e) for e in events]


@router.get("/{event_id}", response_model=EventDetailOut)
def get_event(
    event_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("events.read")),
):
    event = scoped_query(db, Event, current_user).filter(Event.id == event_id).one_or_none()
    if event is None:
        raise HTTPException(status_code=404, detail="Event not found")
    return EventDetailOut.model_validate(event)
