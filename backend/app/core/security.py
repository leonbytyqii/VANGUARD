"""
Password hashing, password policy, and JWT issuance/verification.

Hashing: Argon2id via passlib — OWASP's current recommendation for new
applications (memory-hard, GPU/ASIC-resistant, tunable). We do not use
bcrypt as the primary scheme even though it's still supported for verifying
any legacy hash (CryptContext with deprecated="auto" means passlib
re-hashes to argon2 on next successful login automatically).

Tokens: short-lived stateless JWT access tokens (never stored server-side —
revocation is by short TTL) plus stateful, hashed, rotating refresh tokens
(see app/models/auth.py::RefreshToken and app/services/auth_service.py for
why refresh tokens need server-side state and access tokens don't).
"""
import hashlib
import re
import secrets
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings

pwd_context = CryptContext(schemes=["argon2", "bcrypt"], deprecated="auto")

# A small, deliberately embedded blocklist of catastrophically common
# passwords. Not a substitute for a full breach-corpus check (e.g.
# Have I Been Pwned's k-anonymity API) but blocks the obvious cases offline.
_COMMON_PASSWORD_BLOCKLIST = {
    "password", "password1", "password123", "123456", "12345678",
    "qwerty123", "letmein123", "welcome123", "admin1234", "changeme123",
    "soc-ai123", "socanalyst", "iloveyou123",
}


class TokenType(str, Enum):
    ACCESS = "access"
    REFRESH = "refresh"
    MFA_CHALLENGE = "mfa_challenge"


def hash_password(plain_password: str) -> str:
    return pwd_context.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception:
        return False


def needs_rehash(hashed_password: str) -> bool:
    return pwd_context.needs_update(hashed_password)


class PasswordPolicyError(ValueError):
    def __init__(self, reasons: list[str]):
        self.reasons = reasons
        super().__init__("; ".join(reasons))


def validate_password_policy(password: str) -> None:
    """
    Raises PasswordPolicyError with every violated rule (not just the
    first) so a caller/UI can show the full list at once.
    """
    reasons = []
    if len(password) < settings.PASSWORD_MIN_LENGTH:
        reasons.append(f"must be at least {settings.PASSWORD_MIN_LENGTH} characters")
    if not re.search(r"[a-z]", password):
        reasons.append("must include a lowercase letter")
    if not re.search(r"[A-Z]", password):
        reasons.append("must include an uppercase letter")
    if not re.search(r"\d", password):
        reasons.append("must include a digit")
    if not re.search(r"[^\w\s]", password):
        reasons.append("must include a special character")
    if password.lower() in _COMMON_PASSWORD_BLOCKLIST:
        reasons.append("is too common — choose a less predictable password")
    if reasons:
        raise PasswordPolicyError(reasons)


def _create_jwt(subject: str, token_type: TokenType, expires_delta: timedelta, extra_claims: dict[str, Any] | None = None) -> str:
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": subject,
        "type": token_type.value,
        "iat": now,
        "exp": now + expires_delta,
        "jti": secrets.token_hex(16),
    }
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def create_access_token(user_id: str, *, organization_id: str, role: str, permissions: list[str]) -> str:
    return _create_jwt(
        subject=user_id,
        token_type=TokenType.ACCESS,
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        extra_claims={"org": organization_id, "role": role, "perms": permissions},
    )


def create_refresh_token_raw() -> str:
    """
    Refresh tokens are opaque random strings, not JWTs — the server is the
    only party that ever needs to interpret them (it looks the hash up in
    the refresh_tokens table), so there's no benefit to making them
    self-describing, and an opaque token can't be replayed against the
    wrong verification path.
    """
    return secrets.token_urlsafe(48)


def hash_refresh_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def decode_token(token: str) -> dict[str, Any]:
    """Raises jose.JWTError (including ExpiredSignatureError) on any invalid/expired/tampered token."""
    return jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])


# MFA challenge token: short-lived (5 min), single-use signal that the
# first factor (password) has passed and only the second factor (TOTP)
# remains. It binds to a specific user_id and is verified in /auth/mfa/complete.
_MFA_CHALLENGE_TTL_MINUTES = 5


def create_mfa_challenge_token(user_id: str) -> str:
    return _create_jwt(
        subject=user_id,
        token_type=TokenType.MFA_CHALLENGE,
        expires_delta=timedelta(minutes=_MFA_CHALLENGE_TTL_MINUTES),
    )


def decode_mfa_challenge_token(token: str) -> str | None:
    """
    Validate a MFA challenge token. Returns the user_id (sub claim) on
    success; returns None on any failure (expired, wrong type, bad sig).
    """
    import uuid as _uuid
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        if payload.get("type") != TokenType.MFA_CHALLENGE.value:
            return None
        user_id = payload.get("sub")
        # Validate it's a valid UUID before returning
        _uuid.UUID(user_id)
        return user_id
    except (JWTError, ValueError, TypeError):
        return None


__all__ = [
    "JWTError",
    "TokenType",
    "PasswordPolicyError",
    "hash_password",
    "verify_password",
    "needs_rehash",
    "validate_password_policy",
    "create_access_token",
    "create_refresh_token_raw",
    "hash_refresh_token",
    "decode_token",
    "create_mfa_challenge_token",
    "decode_mfa_challenge_token",
]
