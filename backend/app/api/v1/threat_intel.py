"""
Threat-intelligence API (Phase 10).

`threat_intel.lookup` (every role) covers reading indicators and running
an enrichment. `threat_intel.manage` (SOC Analyst and up) covers adding,
editing, and retiring them — because an indicator an analyst adds by hand
becomes evidence other people act on, and a viewer should not be able to
inject one.

`force_refresh` is deliberately gated behind `threat_intel.manage` as
well: a cache bypass is the one operation here that spends real money and
consumes a shared rate limit, so it needs an actor who is accountable for
it rather than being available to anyone who can read.
"""
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from app.core.deps import get_client_ip, require_permission
from app.core.scope import scoped_query
from app.db.session import get_db
from app.models.alert import Alert
from app.models.threat_intel import IOC
from app.models.user import User
from app.schemas.threat_intel import (
    AlertEnrichmentResponse,
    IOCCreateRequest,
    IOCDetailOut,
    IOCLookupRequest,
    IOCLookupResponse,
    IOCOut,
    IOCUpdateRequest,
)
from app.services.audit import log_audit_event
from app.services.threat_intel import (
    ThreatIntelError,
    enrich_alert_indicators,
    enrich_ioc,
    get_or_create_ioc,
    lookup_and_enrich,
)

router = APIRouter(prefix="/threat-intel", tags=["threat-intel"])


def _get_scoped_ioc(db: Session, ioc_id: uuid.UUID, current_user: User) -> IOC:
    ioc = scoped_query(db, IOC, current_user).filter(IOC.id == ioc_id).one_or_none()
    if ioc is None:
        raise HTTPException(status_code=404, detail="IOC not found")
    return ioc


def _detail(ioc: IOC) -> IOCDetailOut:
    return IOCDetailOut.model_validate(ioc)


@router.get("/iocs", response_model=list[IOCOut])
def list_iocs(
    ioc_type: str | None = None,
    reputation: str | None = None,
    min_score: int | None = Query(None, ge=0, le=100),
    active_only: bool = True,
    search: str | None = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("threat_intel.lookup")),
):
    q = scoped_query(db, IOC, current_user)
    if ioc_type:
        q = q.filter(IOC.ioc_type == ioc_type)
    if reputation:
        q = q.filter(IOC.reputation == reputation)
    if min_score is not None:
        q = q.filter(IOC.threat_score >= min_score)
    if active_only:
        q = q.filter(IOC.is_active.is_(True))
    if search:
        q = q.filter(IOC.value.ilike(f"%{search.strip().lower()}%"))
    rows = q.order_by(IOC.threat_score.desc(), IOC.last_seen_at.desc()).offset(offset).limit(limit).all()
    return [IOCOut.model_validate(r) for r in rows]


@router.post("/iocs", response_model=IOCDetailOut, status_code=201)
def create_ioc(
    payload: IOCCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("threat_intel.manage")),
):
    try:
        ioc = get_or_create_ioc(
            db,
            organization_id=current_user.organization_id,
            ioc_type=payload.ioc_type,
            value=payload.value,
            added_by=current_user,
            tags=payload.tags,
            notes=payload.notes,
        )
        if payload.enrich:
            ioc, _ = enrich_ioc(db, ioc, actor=current_user, source_ip=get_client_ip(request))
    except ThreatIntelError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc))

    log_audit_event(
        db,
        action="ioc_created",
        actor_id=current_user.id,
        actor_label=current_user.email,
        resource_type="ioc",
        resource_id=str(ioc.id),
        outcome="success",
        source_ip=get_client_ip(request),
        details={"ioc_type": ioc.ioc_type, "value": ioc.value},
    )
    return _detail(ioc)


@router.post("/lookup", response_model=IOCLookupResponse)
def lookup_ioc(
    payload: IOCLookupRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("threat_intel.lookup")),
):
    if payload.force_refresh and not current_user.has_permission("threat_intel.manage"):
        raise HTTPException(
            status_code=403,
            detail="Bypassing the enrichment cache requires the 'threat_intel.manage' permission",
        )
    try:
        ioc, from_cache = lookup_and_enrich(
            db,
            organization_id=current_user.organization_id,
            ioc_type=payload.ioc_type,
            value=payload.value,
            force_refresh=payload.force_refresh,
            actor=current_user,
            source_ip=get_client_ip(request),
        )
    except ThreatIntelError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc))
    return IOCLookupResponse(ioc=_detail(ioc), from_cache=from_cache)


@router.get("/iocs/{ioc_id}", response_model=IOCDetailOut)
def get_ioc(
    ioc_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("threat_intel.lookup")),
):
    return _detail(_get_scoped_ioc(db, ioc_id, current_user))


@router.patch("/iocs/{ioc_id}", response_model=IOCDetailOut)
def update_ioc(
    ioc_id: uuid.UUID,
    payload: IOCUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("threat_intel.manage")),
):
    ioc = _get_scoped_ioc(db, ioc_id, current_user)
    changed = {}
    if payload.tags is not None:
        ioc.tags = sorted(set(payload.tags))
        changed["tags"] = ioc.tags
    if payload.notes is not None:
        ioc.notes = payload.notes
        changed["notes"] = True
    if payload.is_active is not None and payload.is_active != ioc.is_active:
        ioc.is_active = payload.is_active
        changed["is_active"] = payload.is_active
    if changed:
        db.add(ioc)
        db.commit()
        db.refresh(ioc)
        log_audit_event(
            db,
            action="ioc_updated",
            actor_id=current_user.id,
            actor_label=current_user.email,
            resource_type="ioc",
            resource_id=str(ioc.id),
            outcome="success",
            source_ip=get_client_ip(request),
            details=changed,
        )
    return _detail(ioc)


@router.post("/iocs/{ioc_id}/refresh", response_model=IOCLookupResponse)
def refresh_ioc(
    ioc_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("threat_intel.manage")),
):
    ioc = _get_scoped_ioc(db, ioc_id, current_user)
    ioc, from_cache = enrich_ioc(
        db, ioc, force_refresh=True, actor=current_user, source_ip=get_client_ip(request)
    )
    return IOCLookupResponse(ioc=_detail(ioc), from_cache=from_cache)


@router.post("/alerts/{alert_id}/enrich", response_model=AlertEnrichmentResponse)
def enrich_alert(
    alert_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("threat_intel.lookup")),
):
    """
    Extract and enrich every indicator the alert's cited events contain.

    Scoped to `alert.related_event_ids` — the evidence the detection
    engine actually used — so an enriched indicator always traces back to
    something the alert rests on.
    """
    alert = scoped_query(db, Alert, current_user).filter(Alert.id == alert_id).one_or_none()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    iocs = enrich_alert_indicators(db, alert, actor=current_user, source_ip=get_client_ip(request))
    return AlertEnrichmentResponse(
        alert_id=alert.id,
        extracted=len(iocs),
        malicious=sum(1 for i in iocs if i.reputation == "malicious"),
        suspicious=sum(1 for i in iocs if i.reputation == "suspicious"),
        iocs=[IOCOut.model_validate(i) for i in iocs],
    )
