"""
Cloud / IAM security API (Phase 11).

`cloud.read` gates cloud event search; `iam.read` gates identities and
attack paths. Both are granted to every role — this is read-only
visibility, and a viewer being unable to see which identity did what
would make the attack-path view useless to exactly the people who most
often need to look at it.

Building an attack path is `iam.read` as well, not a write permission,
because reconstruction is a pure read over already-ingested telemetry: it
derives a graph, it does not change the account. The row it persists is a
cached view of that derivation, not new evidence.
"""
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from app.cloud_iam.attack_paths import reconstruct_attack_path, scoped_cloud_events
from app.core.deps import get_client_ip, require_permission
from app.core.scope import scoped_query
from app.db.session import get_db
from app.models.cloud import CloudEvent, CloudIdentity, IAMAttackPath
from app.models.user import User
from app.schemas.cloud import (
    AttackPathBuildRequest,
    AttackPathOut,
    CloudEventOut,
    CloudIdentityDetailOut,
    CloudIdentityOut,
)
from app.services.audit import log_audit_event

router = APIRouter(prefix="/cloud", tags=["cloud-iam"])


@router.get("/identities", response_model=list[CloudIdentityOut])
def list_identities(
    account_id: str | None = None,
    identity_type: str | None = None,
    privileged_only: bool = False,
    search: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("iam.read")),
):
    q = scoped_query(db, CloudIdentity, current_user)
    if account_id:
        q = q.filter(CloudIdentity.account_id == account_id)
    if identity_type:
        q = q.filter(CloudIdentity.identity_type == identity_type)
    if privileged_only:
        q = q.filter(CloudIdentity.is_privileged.is_(True))
    if search:
        q = q.filter(CloudIdentity.identity_name.ilike(f"%{search.strip()}%"))
    rows = q.order_by(CloudIdentity.last_seen_at.desc().nullslast()).offset(offset).limit(limit).all()
    return [CloudIdentityOut.model_validate(r) for r in rows]


@router.get("/identities/{identity_id}", response_model=CloudIdentityDetailOut)
def get_identity(
    identity_id: uuid.UUID,
    activity_limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("iam.read")),
):
    identity = scoped_query(db, CloudIdentity, current_user).filter(CloudIdentity.id == identity_id).one_or_none()
    if identity is None:
        raise HTTPException(status_code=404, detail="Cloud identity not found")

    activity = (
        scoped_cloud_events(db, current_user.organization_id)
        .filter(
            CloudEvent.account_id == identity.account_id,
            CloudEvent.actor_identity == identity.identity_name,
        )
        .order_by(CloudEvent.event_timestamp.desc())
        .limit(activity_limit)
        .all()
    )
    roles_assumed = sorted(
        {e.assumed_role_arn for e in activity if e.assumed_role_arn}
    )

    out = CloudIdentityDetailOut.model_validate(identity)
    out.recent_activity = [CloudEventOut.model_validate(e) for e in activity]
    out.roles_assumed = roles_assumed
    return out


@router.get("/events", response_model=list[CloudEventOut])
def list_cloud_events(
    account_id: str | None = None,
    actor: str | None = None,
    event_name: str | None = None,
    errors_only: bool = False,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("cloud.read")),
):
    q = scoped_cloud_events(db, current_user.organization_id)
    if account_id:
        q = q.filter(CloudEvent.account_id == account_id)
    if actor:
        q = q.filter(CloudEvent.actor_identity == actor)
    if event_name:
        q = q.filter(CloudEvent.event_name == event_name)
    if errors_only:
        q = q.filter(CloudEvent.error_code.isnot(None))
    if start_time:
        q = q.filter(CloudEvent.event_timestamp >= start_time)
    if end_time:
        q = q.filter(CloudEvent.event_timestamp <= end_time)
    rows = q.order_by(CloudEvent.event_timestamp.desc()).offset(offset).limit(limit).all()
    return [CloudEventOut.model_validate(r) for r in rows]


@router.get("/attack-paths", response_model=list[AttackPathOut])
def list_attack_paths(
    incident_id: uuid.UUID | None = None,
    alert_id: uuid.UUID | None = None,
    privilege_escalation_only: bool = False,
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("iam.read")),
):
    q = scoped_query(db, IAMAttackPath, current_user)
    if incident_id:
        q = q.filter(IAMAttackPath.incident_id == incident_id)
    if alert_id:
        q = q.filter(IAMAttackPath.alert_id == alert_id)
    if privilege_escalation_only:
        q = q.filter(IAMAttackPath.privilege_escalation_detected.is_(True))
    rows = q.order_by(IAMAttackPath.created_at.desc()).limit(limit).all()
    return [AttackPathOut.model_validate(r) for r in rows]


@router.get("/attack-paths/{path_id}", response_model=AttackPathOut)
def get_attack_path(
    path_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("iam.read")),
):
    path = scoped_query(db, IAMAttackPath, current_user).filter(IAMAttackPath.id == path_id).one_or_none()
    if path is None:
        raise HTTPException(status_code=404, detail="Attack path not found")
    return AttackPathOut.model_validate(path)


@router.post("/attack-paths", response_model=AttackPathOut, status_code=201)
def build_attack_path(
    payload: AttackPathBuildRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("iam.read")),
):
    start = payload.start_time or (datetime.now(timezone.utc) - timedelta(hours=payload.window_hours))
    path = reconstruct_attack_path(
        db,
        organization_id=current_user.organization_id,
        account_id=payload.account_id,
        seed_identity=payload.seed_identity,
        start_time=start,
        window_hours=payload.window_hours,
        alert_id=payload.alert_id,
        incident_id=payload.incident_id,
    )
    if path is None:
        raise HTTPException(
            status_code=404,
            detail=(
                f"No cloud activity found for identity '{payload.seed_identity}' in account "
                f"'{payload.account_id}' within the requested window."
            ),
        )

    log_audit_event(
        db,
        action="iam_attack_path_built",
        actor_id=current_user.id,
        actor_label=current_user.email,
        resource_type="iam_attack_path",
        resource_id=str(path.id),
        outcome="success",
        source_ip=get_client_ip(request),
        details={
            "seed_identity": payload.seed_identity,
            "account_id": payload.account_id,
            "nodes": len(path.path_nodes),
            "edges": len(path.path_edges),
            "privilege_escalation": path.privilege_escalation_detected,
        },
    )
    return AttackPathOut.model_validate(path)
