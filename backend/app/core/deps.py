"""
FastAPI dependencies for authentication and authorization.

`get_current_user` is the only place a request's JWT is trusted; every
permission check downstream reads from the *database* role/permission
state via `user.has_permission()`, not from the token's cached `perms`
claim — so a permission revoked mid-session takes effect on the very next
request rather than only after the access token expires. The `perms` claim
on the token still exists (issued in app/services/auth_service.py) purely
so the frontend can render/hide UI without an extra round trip; it is never
used server-side as the source of truth.
"""
from __future__ import annotations

import uuid

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy.orm import Session

from app.core.security import TokenType, decode_token
from app.db.session import get_db
from app.models.user import User
from app.services.audit import log_audit_event
from app.services.api_key_service import authenticate_by_api_key

bearer_scheme = HTTPBearer(auto_error=False)


def get_client_ip(request: Request) -> str | None:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    token = credentials.credentials

    # API key path: "vanguard_<hex>" format, never a JWT
    if token.startswith("vanguard_"):
        api_key = authenticate_by_api_key(db, token)
        if api_key is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or revoked API key")
        user = db.query(User).filter(User.id == api_key.user_id).one_or_none()
        if user is None or not user.is_active:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")
        request.state.current_user = user
        return user

    try:
        payload = decode_token(token)
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

    if payload.get("type") != TokenType.ACCESS.value:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Wrong token type")

    try:
        user_id = uuid.UUID(payload["sub"])
    except (KeyError, ValueError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token subject")

    user = db.query(User).filter(User.id == user_id).one_or_none()
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")

    request.state.current_user = user
    return user


def require_permission(permission_code: str):
    """
    Dependency factory: `Depends(require_permission("response.approve"))`.
    Denials are audited with the resolved resource path so
    docs/SECURITY.md's audit-architecture guarantee ("every permission
    denial is auditable") holds for every protected route without each
    route handler having to remember to log it.
    """

    def _checker(
        request: Request,
        db: Session = Depends(get_db),
        user: User = Depends(get_current_user),
    ) -> User:
        if not user.has_permission(permission_code):
            log_audit_event(
                db,
                action="permission_denied",
                actor_id=user.id,
                actor_label=user.email,
                resource_type="endpoint",
                resource_id=request.url.path,
                outcome="denied",
                source_ip=get_client_ip(request),
                details={"required_permission": permission_code, "role": user.role.name},
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required permission: {permission_code}",
            )
        return user

    return _checker


def require_any_permission(*permission_codes: str):
    def _checker(
        request: Request,
        db: Session = Depends(get_db),
        user: User = Depends(get_current_user),
    ) -> User:
        if not any(user.has_permission(code) for code in permission_codes):
            log_audit_event(
                db,
                action="permission_denied",
                actor_id=user.id,
                actor_label=user.email,
                resource_type="endpoint",
                resource_id=request.url.path,
                outcome="denied",
                source_ip=get_client_ip(request),
                details={"required_any_of": list(permission_codes), "role": user.role.name},
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing one of required permissions: {', '.join(permission_codes)}",
            )
        return user

    return _checker
