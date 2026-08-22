from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.deps import get_client_ip, get_current_user
from app.core.rate_limit import limiter
from app.core.security import hash_password, verify_password
from app.db.session import get_db
from app.models.user import User
from app.schemas.auth import (
    AccessTokenResponse,
    ChangePasswordRequest,
    CurrentUserResponse,
    LoginRequest,
)
from app.services.audit import log_audit_event
from app.services.auth_service import (
    AuthError,
    authenticate_user,
    issue_access_token,
    issue_refresh_token,
    revoke_refresh_token,
    rotate_refresh_token,
)

router = APIRouter(prefix="/auth", tags=["auth"])


def _set_refresh_cookie(response: Response, raw_refresh_token: str) -> None:
    response.set_cookie(
        key=settings.REFRESH_COOKIE_NAME,
        value=raw_refresh_token,
        httponly=True,
        secure=settings.is_production,
        samesite="lax",
        max_age=settings.REFRESH_TOKEN_EXPIRE_MINUTES * 60,
        path="/api/v1/auth",
    )


@router.post("/login", response_model=AccessTokenResponse)
@limiter.limit(settings.RATE_LIMIT_AUTH)
def login(payload: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    # Per-IP rate limiting (RATE_LIMIT_AUTH, stricter than the app-wide
    # default) is enforced by the decorator above; account-level lockout
    # below is a second, independent control that survives an attacker
    # rotating source IPs or operating from many of them at once.
    source_ip = get_client_ip(request)
    try:
        user = authenticate_user(db, email=payload.email, password=payload.password, source_ip=source_ip)
    except AuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message)

    access_token = issue_access_token(user)
    raw_refresh, _ = issue_refresh_token(
        db, user, user_agent=request.headers.get("user-agent"), source_ip=source_ip
    )
    _set_refresh_cookie(response, raw_refresh)

    return AccessTokenResponse(access_token=access_token, expires_in_minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)


@router.post("/refresh", response_model=AccessTokenResponse)
@limiter.limit(settings.RATE_LIMIT_AUTH)
def refresh(request: Request, response: Response, db: Session = Depends(get_db)):
    raw_refresh = request.cookies.get(settings.REFRESH_COOKIE_NAME)
    if not raw_refresh:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="No refresh token presented")

    source_ip = get_client_ip(request)
    try:
        new_raw, _, user = rotate_refresh_token(
            db, raw_refresh, user_agent=request.headers.get("user-agent"), source_ip=source_ip
        )
    except AuthError as exc:
        response.delete_cookie(settings.REFRESH_COOKIE_NAME, path="/api/v1/auth")
        raise HTTPException(status_code=exc.status_code, detail=exc.message)

    _set_refresh_cookie(response, new_raw)
    access_token = issue_access_token(user)
    return AccessTokenResponse(access_token=access_token, expires_in_minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    raw_refresh = request.cookies.get(settings.REFRESH_COOKIE_NAME)
    if raw_refresh:
        revoke_refresh_token(db, raw_refresh, source_ip=get_client_ip(request))
    response.delete_cookie(settings.REFRESH_COOKIE_NAME, path="/api/v1/auth")
    return None


@router.get("/me", response_model=CurrentUserResponse)
def me(user: User = Depends(get_current_user)):
    permissions = ["*"] if user.is_superuser else [p.code for p in user.role.permissions]
    return CurrentUserResponse(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=user.role.name,
        organization_id=user.organization_id,
        permissions=permissions,
        must_change_password=user.must_change_password,
    )


@router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT)
def change_password(
    payload: ChangePasswordRequest,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not verify_password(payload.current_password, user.hashed_password):
        log_audit_event(
            db, action="password_change_failed", actor_id=user.id, actor_label=user.email,
            resource_type="user", resource_id=str(user.id), outcome="denied",
            source_ip=get_client_ip(request), details={"reason": "wrong_current_password"},
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect")

    user.hashed_password = hash_password(payload.new_password)
    user.must_change_password = False
    db.add(user)
    db.commit()

    log_audit_event(
        db, action="password_changed", actor_id=user.id, actor_label=user.email,
        resource_type="user", resource_id=str(user.id), outcome="success", source_ip=get_client_ip(request),
    )
    return None
