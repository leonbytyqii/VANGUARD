import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.deps import get_client_ip, require_permission
from app.core.security import hash_password
from app.db.session import get_db
from app.models.audit import AuditLog
from app.models.user import Role, User
from app.schemas.audit import AuditLogOut
from app.schemas.user import RoleOut, UserCreateRequest, UserOut, UserUpdateRequest
from app.services.audit import log_audit_event

router = APIRouter(tags=["admin"])


@router.get("/admin/users", response_model=list[UserOut])
def list_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("admin.users")),
):
    users = db.query(User).filter(User.organization_id == current_user.organization_id).all()
    return [UserOut(**_user_out_kwargs(u)) for u in users]


@router.post("/admin/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("admin.users")),
):
    if db.query(User).filter(User.email == payload.email.lower()).one_or_none():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="A user with this email already exists")

    role = db.query(Role).filter(Role.name == payload.role).one_or_none()
    if role is None:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"Unknown role '{payload.role}'")

    user = User(
        email=payload.email.lower().strip(),
        full_name=payload.full_name,
        hashed_password=hash_password(payload.password),
        role_id=role.id,
        organization_id=current_user.organization_id,
        must_change_password=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    log_audit_event(
        db, action="user_created", actor_id=current_user.id, actor_label=current_user.email,
        resource_type="user", resource_id=str(user.id), outcome="success",
        source_ip=get_client_ip(request), details={"email": user.email, "role": role.name},
    )
    return UserOut(**_user_out_kwargs(user))


@router.patch("/admin/users/{user_id}", response_model=UserOut)
def update_user(
    user_id: uuid.UUID,
    payload: UserUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("admin.users")),
):
    target = (
        db.query(User)
        .filter(User.id == user_id, User.organization_id == current_user.organization_id)
        .one_or_none()
    )
    if target is None:
        # Same response whether the id doesn't exist or belongs to another
        # tenant — existence of another org's user is not disclosed.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    changes: dict[str, object] = {}
    if payload.full_name is not None:
        target.full_name = payload.full_name
        changes["full_name"] = payload.full_name
    if payload.is_active is not None:
        target.is_active = payload.is_active
        changes["is_active"] = payload.is_active
    if payload.role is not None:
        role = db.query(Role).filter(Role.name == payload.role).one_or_none()
        if role is None:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"Unknown role '{payload.role}'")
        changes["role"] = {"from": target.role.name, "to": role.name}
        target.role_id = role.id

    db.add(target)
    db.commit()
    db.refresh(target)

    log_audit_event(
        db, action="user_changed", actor_id=current_user.id, actor_label=current_user.email,
        resource_type="user", resource_id=str(target.id), outcome="success",
        source_ip=get_client_ip(request), details=changes,
    )
    if "role" in changes:
        log_audit_event(
            db, action="role_changed", actor_id=current_user.id, actor_label=current_user.email,
            resource_type="user", resource_id=str(target.id), outcome="success",
            source_ip=get_client_ip(request), details=changes["role"],
        )
    return UserOut(**_user_out_kwargs(target))


@router.get("/admin/roles", response_model=list[RoleOut])
def list_roles(
    db: Session = Depends(get_db),
    _: User = Depends(require_permission("admin.roles")),
):
    roles = db.query(Role).all()
    return [RoleOut(id=r.id, name=r.name, description=r.description, permissions=[p.code for p in r.permissions]) for r in roles]


@router.get("/audit", response_model=list[AuditLogOut])
def list_audit_log(
    limit: int = 100,
    db: Session = Depends(get_db),
    _: User = Depends(require_permission("audit.read")),
):
    limit = min(max(limit, 1), 500)
    entries = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit).all()
    return [AuditLogOut.model_validate(e) for e in entries]


def _user_out_kwargs(user: User) -> dict:
    return {
        "id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role.name,
        "is_active": user.is_active,
        "organization_id": user.organization_id,
        "last_login_at": user.last_login_at,
        "created_at": user.created_at,
    }
