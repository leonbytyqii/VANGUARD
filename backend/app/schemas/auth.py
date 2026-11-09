import uuid
from datetime import datetime

from pydantic import BaseModel, field_validator

from app.core.security import validate_password_policy
from app.core.validation import validate_email_syntax


class LoginRequest(BaseModel):
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def _validate_email(cls, v: str) -> str:
        return validate_email_syntax(v)


class LoginResponse(BaseModel):
    """
    Returned by POST /auth/login.

    If mfa_required=True the client must POST to /auth/mfa/complete with
    mfa_challenge_token + code to receive actual credentials. The access_token
    and other fields are absent in that case.

    If mfa_required=False the response includes a full access token (the
    refresh token is set as an HttpOnly cookie, not in this body).
    """
    mfa_required: bool
    mfa_challenge_token: str | None = None

    access_token: str | None = None
    token_type: str = "bearer"
    expires_in_minutes: int | None = None


class AccessTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in_minutes: int


class CurrentUserResponse(BaseModel):
    id: uuid.UUID
    email: str
    full_name: str
    role: str
    organization_id: uuid.UUID
    permissions: list[str]
    must_change_password: bool
    totp_enabled: bool = False

    model_config = {"from_attributes": True}


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def _validate_policy(cls, v: str) -> str:
        validate_password_policy(v)
        return v


# ---------------------------------------------------------------------------
# MFA schemas
# ---------------------------------------------------------------------------


class MFAChallengeRequest(BaseModel):
    mfa_challenge_token: str
    code: str


class MFAStatusResponse(BaseModel):
    totp_enabled: bool
    recovery_codes_remaining: int


class MFASetupResponse(BaseModel):
    provisioning_uri: str
    secret: str


class MFASetupConfirmRequest(BaseModel):
    code: str


class MFADisableRequest(BaseModel):
    code: str


class MFARecoveryCodesResponse(BaseModel):
    recovery_codes: list[str]


# ---------------------------------------------------------------------------
# API key schemas
# ---------------------------------------------------------------------------


class APIKeyCreateRequest(BaseModel):
    name: str
    expires_at: datetime | None = None


class APIKeyResponse(BaseModel):
    id: uuid.UUID
    name: str
    key_prefix: str
    created_at: datetime
    expires_at: datetime | None
    last_used_at: datetime | None
    raw_key: str | None = None

    model_config = {"from_attributes": True}
