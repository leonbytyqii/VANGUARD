from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.deps import get_client_ip, get_current_user
from app.core.rate_limit import limiter
from app.core.security import create_mfa_challenge_token, decode_mfa_challenge_token, hash_password, verify_password
from app.db.session import get_db
from app.models.user import User
from app.schemas.auth import (
    AccessTokenResponse,
    APIKeyCreateRequest,
    APIKeyResponse,
    ChangePasswordRequest,
    CurrentUserResponse,
    LoginRequest,
    LoginResponse,
    MFAChallengeRequest,
    MFADisableRequest,
    MFARecoveryCodesResponse,
    MFASetupConfirmRequest,
    MFASetupResponse,
    MFAStatusResponse,
)
from app.services.api_key_service import APIKeyError, create_api_key, list_api_keys, revoke_api_key, rotate_api_key
from app.services.audit import log_audit_event
from app.services.auth_service import (
    AuthError,
    authenticate_user,
    issue_access_token,
    issue_refresh_token,
    revoke_refresh_token,
    rotate_refresh_token,
)
from app.services.mfa_service import (
    MFAAlreadyEnabledError,
    MFAError,
    begin_totp_setup,
    confirm_totp_setup,
    disable_totp,
    recovery_codes_remaining,
    regenerate_recovery_codes,
    verify_totp_or_recovery,
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
        path=settings.REFRESH_COOKIE_PATH,
    )


def _mfa_error_to_http(exc: MFAError) -> HTTPException:
    return HTTPException(status_code=exc.status_code, detail=exc.message)


@router.post("/login", response_model=LoginResponse)
@limiter.limit(settings.RATE_LIMIT_AUTH)
def login(payload: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    source_ip = get_client_ip(request)
    try:
        user = authenticate_user(db, email=payload.email, password=payload.password, source_ip=source_ip)
    except AuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message)

    if user.totp_enabled:
        # Return a short-lived challenge token; the client must POST /auth/mfa/complete
        # with this token + the TOTP code to receive actual credentials.
        challenge_token = create_mfa_challenge_token(user_id=str(user.id))
        return LoginResponse(mfa_required=True, mfa_challenge_token=challenge_token)

    access_token = issue_access_token(user)
    raw_refresh, _ = issue_refresh_token(
        db, user, user_agent=request.headers.get("user-agent"), source_ip=source_ip
    )
    _set_refresh_cookie(response, raw_refresh)
    return LoginResponse(
        mfa_required=False,
        access_token=access_token,
        token_type="bearer",
        expires_in_minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES,
    )


@router.post("/mfa/complete", response_model=AccessTokenResponse)
@limiter.limit(settings.RATE_LIMIT_AUTH)
def mfa_complete(payload: MFAChallengeRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    """
    Second factor of the MFA login flow. Accepts the challenge token from
    /auth/login and a TOTP code (or recovery code). Issues full credentials
    on success.
    """
    source_ip = get_client_ip(request)
    user_id = decode_mfa_challenge_token(payload.mfa_challenge_token)
    if user_id is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="MFA challenge token is invalid or expired.")

    user = db.query(User).filter(User.id == user_id).one_or_none()
    if user is None or not user.is_active or not user.totp_enabled:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="MFA challenge token is invalid or expired.")

    try:
        verify_totp_or_recovery(db, user, payload.code)
    except MFAError as exc:
        log_audit_event(
            db, action="mfa_verify_failed", actor_id=user.id, actor_label=user.email,
            resource_type="user", resource_id=str(user.id), outcome="denied", source_ip=source_ip,
        )
        raise HTTPException(status_code=exc.status_code, detail=exc.message)

    access_token = issue_access_token(user)
    raw_refresh, _ = issue_refresh_token(
        db, user, user_agent=request.headers.get("user-agent"), source_ip=source_ip
    )
    _set_refresh_cookie(response, raw_refresh)

    log_audit_event(
        db, action="login", actor_id=user.id, actor_label=user.email,
        resource_type="user", resource_id=str(user.id), outcome="success", source_ip=source_ip,
        details={"mfa": "totp"},
    )
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
        response.delete_cookie(settings.REFRESH_COOKIE_NAME, path=settings.REFRESH_COOKIE_PATH)
        raise HTTPException(status_code=exc.status_code, detail=exc.message)

    _set_refresh_cookie(response, new_raw)
    access_token = issue_access_token(user)
    return AccessTokenResponse(access_token=access_token, expires_in_minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    raw_refresh = request.cookies.get(settings.REFRESH_COOKIE_NAME)
    if raw_refresh:
        revoke_refresh_token(db, raw_refresh, source_ip=get_client_ip(request))
    response.delete_cookie(settings.REFRESH_COOKIE_NAME, path=settings.REFRESH_COOKIE_PATH)
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
        totp_enabled=user.totp_enabled,
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


# ---------------------------------------------------------------------------
# MFA endpoints (authenticated — user must already have an access token)
# ---------------------------------------------------------------------------


@router.get("/mfa/status", response_model=MFAStatusResponse)
def mfa_status(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return MFAStatusResponse(
        totp_enabled=user.totp_enabled,
        recovery_codes_remaining=recovery_codes_remaining(db, user) if user.totp_enabled else 0,
    )


@router.post("/mfa/setup", response_model=MFASetupResponse)
def mfa_setup(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Initiate TOTP enrolment. Returns a provisioning URI for QR-code display."""
    try:
        result = begin_totp_setup(db, user)
    except MFAAlreadyEnabledError as exc:
        raise _mfa_error_to_http(exc)
    return MFASetupResponse(**result)


@router.post("/mfa/setup/confirm", response_model=MFARecoveryCodesResponse)
def mfa_setup_confirm(
    payload: MFASetupConfirmRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Confirm TOTP setup with the first valid code. Returns recovery codes (shown once)."""
    try:
        codes = confirm_totp_setup(db, user, payload.code)
    except MFAError as exc:
        raise _mfa_error_to_http(exc)
    return MFARecoveryCodesResponse(recovery_codes=codes)


@router.post("/mfa/disable", status_code=status.HTTP_204_NO_CONTENT)
def mfa_disable(
    payload: MFADisableRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Disable TOTP. Requires a valid TOTP or recovery code to prevent silent downgrade."""
    try:
        disable_totp(db, user, payload.code)
    except MFAError as exc:
        raise _mfa_error_to_http(exc)
    return None


@router.post("/mfa/recovery-codes/regenerate", response_model=MFARecoveryCodesResponse)
def mfa_regenerate_recovery_codes(
    payload: MFASetupConfirmRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Regenerate recovery codes. Requires a valid TOTP code. Old codes are immediately invalidated."""
    try:
        codes = regenerate_recovery_codes(db, user, payload.code)
    except MFAError as exc:
        raise _mfa_error_to_http(exc)
    return MFARecoveryCodesResponse(recovery_codes=codes)


# ---------------------------------------------------------------------------
# API key endpoints
# ---------------------------------------------------------------------------


api_key_router = APIRouter(prefix="/api-keys", tags=["api-keys"])


@api_key_router.get("", response_model=list[APIKeyResponse])
def list_keys(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return [APIKeyResponse.model_validate(k) for k in list_api_keys(db, user)]


@api_key_router.post("", response_model=APIKeyResponse, status_code=status.HTTP_201_CREATED)
def create_key(
    payload: APIKeyCreateRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    record, raw_key = create_api_key(db, user, name=payload.name, expires_at=payload.expires_at)
    resp = APIKeyResponse.model_validate(record)
    resp.raw_key = raw_key
    return resp


@api_key_router.delete("/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_key(
    key_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    try:
        revoke_api_key(db, user, key_id)
    except APIKeyError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message)
    return None


@api_key_router.post("/{key_id}/rotate", response_model=APIKeyResponse)
def rotate_key(
    key_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    try:
        record, raw_key = rotate_api_key(db, user, key_id)
    except APIKeyError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message)
    resp = APIKeyResponse.model_validate(record)
    resp.raw_key = raw_key
    return resp
