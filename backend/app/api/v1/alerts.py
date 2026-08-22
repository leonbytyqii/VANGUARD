import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from app.core.deps import get_client_ip, require_permission
from app.core.scope import scoped_query
from app.db.session import get_db
from app.models.alert import Alert
from app.models.enums import AlertStatus, Severity
from app.models.user import User
from app.schemas.alert import AlertOut, AlertUpdateRequest
from app.services.audit import log_audit_event

router = APIRouter(prefix="/alerts", tags=["alerts"])

_VALID_STATUSES = {s.value for s in AlertStatus}
_VALID_SEVERITIES = {s.value for s in Severity}


def _serialize_alert(alert: Alert) -> AlertOut:
    out = AlertOut.model_validate(alert)
    out.mitre_technique_ids = [t.technique_id for t in alert.mitre_techniques]
    return out


@router.get("", response_model=list[AlertOut])
def list_alerts(
    status: str | None = None,
    severity: str | None = None,
    host: str | None = None,
    user: str | None = None,
    assigned_to_id: uuid.UUID | None = None,
    min_risk_score: int | None = Query(None, ge=0, le=100),
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("alerts.read")),
):
    q = scoped_query(db, Alert, current_user)
    if status:
        q = q.filter(Alert.status == status)
    if severity:
        q = q.filter(Alert.severity == severity)
    if host:
        q = q.filter(Alert.host_name == host)
    if user:
        q = q.filter(Alert.user == user)
    if assigned_to_id:
        q = q.filter(Alert.assigned_to_id == assigned_to_id)
    if min_risk_score is not None:
        q = q.filter(Alert.risk_score >= min_risk_score)
    if start_time:
        q = q.filter(Alert.alert_timestamp >= start_time)
    if end_time:
        q = q.filter(Alert.alert_timestamp <= end_time)

    alerts = q.order_by(Alert.risk_score.desc(), Alert.alert_timestamp.desc()).offset(offset).limit(limit).all()
    return [_serialize_alert(a) for a in alerts]


@router.get("/{alert_id}", response_model=AlertOut)
def get_alert(
    alert_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("alerts.read")),
):
    alert = scoped_query(db, Alert, current_user).filter(Alert.id == alert_id).one_or_none()
    if alert is None:
        # 404 (not 403) whether the id doesn't exist or belongs to another
        # organization — see app/core/scope.py docstring on why.
        raise HTTPException(status_code=404, detail="Alert not found")
    return _serialize_alert(alert)


@router.patch("/{alert_id}", response_model=AlertOut)
def update_alert(
    alert_id: uuid.UUID,
    payload: AlertUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("alerts.update")),
):
    """
    Single PATCH covers status/severity/assignment/analyst-note updates —
    the standard analyst triage actions on an alert. Note: this is
    ordinary triage bookkeeping, not a privileged-action gate; the
    human-in-the-loop *approval* state machine that must never be
    bypassed lives in ResponseAction (Phase 2) and is untouched by this
    endpoint.
    """
    alert = scoped_query(db, Alert, current_user).filter(Alert.id == alert_id).one_or_none()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    changes: dict = {}

    if payload.status is not None:
        if payload.status not in _VALID_STATUSES:
            raise HTTPException(status_code=422, detail=f"Invalid status. Must be one of: {sorted(_VALID_STATUSES)}")
        changes["status"] = {"from": alert.status, "to": payload.status}
        alert.status = payload.status

    if payload.severity is not None:
        if payload.severity not in _VALID_SEVERITIES:
            raise HTTPException(status_code=422, detail=f"Invalid severity. Must be one of: {sorted(_VALID_SEVERITIES)}")
        changes["severity"] = {"from": alert.severity, "to": payload.severity}
        alert.severity = payload.severity

    if payload.assigned_to_id is not None:
        assignee = (
            db.query(User)
            .filter(User.id == payload.assigned_to_id, User.organization_id == current_user.organization_id)
            .one_or_none()
        )
        if assignee is None:
            raise HTTPException(status_code=422, detail="Assignee not found in your organization")
        changes["assigned_to_id"] = {"from": str(alert.assigned_to_id) if alert.assigned_to_id else None, "to": str(assignee.id)}
        alert.assigned_to_id = assignee.id
        if alert.status == AlertStatus.NEW.value and payload.status is None:
            alert.status = AlertStatus.TRIAGED.value  # picking up a NEW alert implicitly triages it

    if payload.analyst_note is not None:
        notes = list(alert.evidence.get("analyst_notes", []))
        notes.append(
            {"by": current_user.email, "at": datetime.now(timezone.utc).isoformat(), "note": payload.analyst_note}
        )
        alert.evidence = {**alert.evidence, "analyst_notes": notes}
        changes["analyst_note_added"] = True

    if not changes:
        raise HTTPException(status_code=422, detail="No fields to update")

    db.add(alert)
    db.commit()
    db.refresh(alert)

    log_audit_event(
        db, action="alert_updated", actor_id=current_user.id, actor_label=current_user.email,
        resource_type="alert", resource_id=str(alert.id), outcome="success",
        source_ip=get_client_ip(request), details=changes,
    )
    return _serialize_alert(alert)
