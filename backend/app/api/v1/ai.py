import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.ai.orchestrator import run_investigation
from app.core.config import settings
from app.core.deps import get_client_ip, require_permission
from app.core.scope import scoped_query
from app.db.session import get_db
from app.models.ai import AgentStep, AIInvestigation
from app.models.alert import Alert
from app.models.enums import InvestigationStatus
from app.models.user import User
from app.schemas.ai import AgentStepOut, AIInvestigationCreateRequest, AIInvestigationOut

router = APIRouter(prefix="/ai", tags=["ai"])


@router.post("/investigations", response_model=AIInvestigationOut, status_code=201)
def create_investigation(
    payload: AIInvestigationCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("ai.investigate")),
):
    """
    Validates the alert exists in the caller's organization, then runs
    the full agent pipeline synchronously (Triage -> Investigation ->
    handoffs — see app/ai/orchestrator.py) before returning. This is a
    deliberately simple, documented seam: a slow real LLM provider makes
    this a slow HTTP request today; queueing it behind a background
    worker is a natural next step that doesn't change this endpoint's
    contract, only how quickly it responds.
    """
    alert = scoped_query(db, Alert, current_user).filter(Alert.id == payload.alert_id).one_or_none()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    investigation = AIInvestigation(
        organization_id=current_user.organization_id,
        alert_id=alert.id,
        status=InvestigationStatus.PENDING.value,
        requested_by_id=current_user.id,
        ai_provider=settings.AI_PROVIDER,
        ai_model=settings.AI_MODEL if settings.AI_PROVIDER != "mock" else "mock-deterministic-analyst",
    )
    db.add(investigation)
    db.commit()
    db.refresh(investigation)

    investigation = run_investigation(db, investigation, source_ip=get_client_ip(request))
    return AIInvestigationOut.model_validate(investigation)


@router.get("/investigations", response_model=list[AIInvestigationOut])
def list_investigations(
    alert_id: uuid.UUID | None = None,
    status: str | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("ai.read")),
):
    q = scoped_query(db, AIInvestigation, current_user)
    if alert_id:
        q = q.filter(AIInvestigation.alert_id == alert_id)
    if status:
        q = q.filter(AIInvestigation.status == status)
    rows = q.order_by(AIInvestigation.created_at.desc()).all()
    return [AIInvestigationOut.model_validate(r) for r in rows]


@router.get("/investigations/{investigation_id}", response_model=AIInvestigationOut)
def get_investigation(
    investigation_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("ai.read")),
):
    investigation = scoped_query(db, AIInvestigation, current_user).filter(AIInvestigation.id == investigation_id).one_or_none()
    if investigation is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return AIInvestigationOut.model_validate(investigation)


@router.get("/investigations/{investigation_id}/steps", response_model=list[AgentStepOut])
def get_investigation_steps(
    investigation_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("ai.read")),
):
    """The full replayable trace (docs/ARCHITECTURE.md §4.3 step 8) — every tool call and its evidence, in order."""
    investigation = scoped_query(db, AIInvestigation, current_user).filter(AIInvestigation.id == investigation_id).one_or_none()
    if investigation is None:
        raise HTTPException(status_code=404, detail="Investigation not found")

    steps = (
        db.query(AgentStep)
        .filter(AgentStep.investigation_id == investigation.id)
        .order_by(AgentStep.step_number.asc())
        .all()
    )
    return [AgentStepOut.model_validate(s) for s in steps]
