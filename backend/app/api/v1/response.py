import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.deps import get_client_ip, require_permission
from app.core.scope import scoped_query
from app.db.session import get_db
from app.models.automation import ResponseAction
from app.models.user import User
from app.schemas.response_action import (
    ResponseActionCreateRequest,
    ResponseActionOut,
    ResponseActionRejectRequest,
)
from app.services.response_actions import (
    ResponseActionError,
    approve_response_action,
    create_response_action_request,
    execute_response_action,
    reject_response_action,
)

router = APIRouter(prefix="/response", tags=["response"])


def _get_scoped_action(db: Session, action_id: uuid.UUID, current_user: User) -> ResponseAction:
    action = scoped_query(db, ResponseAction, current_user).filter(ResponseAction.id == action_id).one_or_none()
    if action is None:
        raise HTTPException(status_code=404, detail="Response action not found")
    return action


@router.get("/actions", response_model=list[ResponseActionOut])
def list_response_actions(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("response.request")),
):
    actions = scoped_query(db, ResponseAction, current_user).order_by(ResponseAction.created_at.desc()).all()
    return [ResponseActionOut.model_validate(a) for a in actions]


@router.post("/actions", response_model=ResponseActionOut, status_code=201)
def request_response_action(
    payload: ResponseActionCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("response.request")),
):
    """
    Human-initiated request path. AI-agent-initiated requests do not come
    through this HTTP endpoint at all — agents have no user session or JWT
    to authenticate with here; they call
    app.ai.tools.registry: `request_response_approval`, which invokes
    app.services.response_actions.create_response_action_request directly
    with requested_by_agent_type set instead of requested_by_user. Both
    paths land in the same table with the same pending->approved->executed
    state machine.
    """
    try:
        action = create_response_action_request(
            db,
            organization_id=current_user.organization_id,
            action_type=payload.action_type,
            target=payload.target,
            justification=payload.justification,
            requested_by_user=current_user,
            incident_id=payload.incident_id,
            source_ip=get_client_ip(request),
        )
    except ResponseActionError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc))
    return ResponseActionOut.model_validate(action)


@router.patch("/actions/{action_id}/approve", response_model=ResponseActionOut)
def approve_action(
    action_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("response.approve")),
):
    action = _get_scoped_action(db, action_id, current_user)
    try:
        action = approve_response_action(db, action, approver=current_user, source_ip=get_client_ip(request))
    except ResponseActionError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc))
    return ResponseActionOut.model_validate(action)


@router.patch("/actions/{action_id}/reject", response_model=ResponseActionOut)
def reject_action(
    action_id: uuid.UUID,
    payload: ResponseActionRejectRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("response.approve")),
):
    action = _get_scoped_action(db, action_id, current_user)
    try:
        action = reject_response_action(
            db, action, approver=current_user, reason=payload.reason, source_ip=get_client_ip(request)
        )
    except ResponseActionError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc))
    return ResponseActionOut.model_validate(action)


@router.post("/actions/{action_id}/execute", response_model=ResponseActionOut)
def execute_action(
    action_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("response.approve")),
):
    action = _get_scoped_action(db, action_id, current_user)
    try:
        action = execute_response_action(db, action, executor=current_user, source_ip=get_client_ip(request))
    except ResponseActionError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc))
    return ResponseActionOut.model_validate(action)
