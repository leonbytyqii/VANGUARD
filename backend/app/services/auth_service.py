"""
Login, token issuance, refresh-token rotation, and account lockout.

Design notes (see docs/SECURITY.md for the full writeup):
- Access tokens are stateless JWTs, short-lived (default 30 min), never
  persisted server-side. Revoking a compromised access token isn't
  possible before it expires — that's the accepted tradeoff for statelessness,
  which is why the TTL is short and why anything sensitive re-checks
  permissions server-side on every request rather than trusting the token
  contents indefinitely.
- Refresh tokens are opaque, long-lived (default 7 days), and *are*
  persisted (hashed) so they can be revoked and rotation-reuse can be
  detected. Every refresh call issues a brand new refresh token and
  revokes the old one (rotation). If a refresh token that's already been
  rotated away is presented again, that's a strong signal of theft (an
  attacker replaying a stolen token after the legitimate client already
  moved on) — we respond by revoking *every* active refresh token for that
  user, forcing re-authentication everywhere.
- Account lockout: after MAX_FAILED_LOGIN_ATTEMPTS consecutive failures the
  account is locked for ACCOUNT_LOCKOUT_MINUTES. A successful login resets
  the counter. This is layered on top of (not instead of) the per-IP rate
  limit on the /auth/login route itself.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import (
    create_access_token,
    create_refresh_token_raw,
    hash_refresh_token,
    verify_password,
)
from app.models.auth import RefreshToken
from app.models.user import User
from app.services.audit import log_audit_event


class AuthError(Exception):
    """Base class for authentication failures with a caller-safe message."""

    def __init__(self, message: str, *, audit_action: str, status_code: int = 401):
        self.message = message
        self.audit_action = audit_action
        self.status_code = status_code
        super().__init__(message)


class InvalidCredentialsError(AuthError):
    def __init__(self):
        super().__init__("Incorrect email or password.", audit_action="login_failed", status_code=401)


class AccountLockedError(AuthError):
    def __init__(self, locked_until: datetime):
        self.locked_until = locked_until
        super().__init__(
            f"Account is locked until {locked_until.isoformat()} due to repeated failed logins.",
            audit_action="login_blocked_lockout",
            status_code=423,
        )


class AccountInactiveError(AuthError):
    def __init__(self):
        super().__init__("Account is disabled.", audit_action="login_blocked_inactive", status_code=403)


class RefreshTokenInvalidError(AuthError):
    def __init__(self, audit_action: str = "token_refresh_failed"):
        super().__init__("Refresh token is invalid or expired.", audit_action=audit_action, status_code=401)


def authenticate_user(db: Session, *, email: str, password: str, source_ip: str | None) -> User:
    user = db.query(User).filter(User.email == email.lower().strip()).one_or_none()

    if user is None:
        # Deliberately identical error/timing-shape to "wrong password" so the
        # endpoint doesn't let an attacker enumerate valid usernames.
        log_audit_event(
            db, action="login_failed", actor_label=email, resource_type="user", resource_id=None,
            outcome="denied", source_ip=source_ip, details={"reason": "no_such_user"},
        )
        raise InvalidCredentialsError()

    if user.is_locked:
        log_audit_event(
            db, action="login_blocked_lockout", actor_id=user.id, actor_label=user.email,
            resource_type="user", resource_id=str(user.id), outcome="denied", source_ip=source_ip,
            details={"locked_until": user.locked_until.isoformat()},
        )
        raise AccountLockedError(user.locked_until)

    if not user.is_active:
        log_audit_event(
            db, action="login_blocked_inactive", actor_id=user.id, actor_label=user.email,
            resource_type="user", resource_id=str(user.id), outcome="denied", source_ip=source_ip,
        )
        raise AccountInactiveError()

    if not verify_password(password, user.hashed_password):
        user.failed_login_attempts += 1
        locked_now = False
        if user.failed_login_attempts >= settings.MAX_FAILED_LOGIN_ATTEMPTS:
            user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCOUNT_LOCKOUT_MINUTES)
            locked_now = True
        db.add(user)
        db.commit()
        log_audit_event(
            db, action="login_failed", actor_id=user.id, actor_label=user.email,
            resource_type="user", resource_id=str(user.id), outcome="denied", source_ip=source_ip,
            details={
                "failed_attempts": user.failed_login_attempts,
                "account_locked": locked_now,
            },
        )
        if locked_now:
            raise AccountLockedError(user.locked_until)
        raise InvalidCredentialsError()

    # Success: reset lockout counters, stamp last login.
    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login_at = datetime.now(timezone.utc)
    db.add(user)
    db.commit()
    db.refresh(user)

    log_audit_event(
        db, action="login", actor_id=user.id, actor_label=user.email,
        resource_type="user", resource_id=str(user.id), outcome="success", source_ip=source_ip,
    )
    return user


def issue_access_token(user: User) -> str:
    permissions = [p.code for p in user.role.permissions] if not user.is_superuser else ["*"]
    return create_access_token(
        user_id=str(user.id),
        organization_id=str(user.organization_id),
        role=user.role.name,
        permissions=permissions,
    )


def issue_refresh_token(
    db: Session, user: User, *, user_agent: str | None, source_ip: str | None
) -> tuple[str, RefreshToken]:
    raw_token = create_refresh_token_raw()
    record = RefreshToken(
        user_id=user.id,
        token_hash=hash_refresh_token(raw_token),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES),
        user_agent=user_agent,
        ip_address=source_ip,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return raw_token, record


def rotate_refresh_token(
    db: Session, raw_token: str, *, user_agent: str | None, source_ip: str | None
) -> tuple[str, RefreshToken, User]:
    """
    Validates the presented refresh token and, if valid, atomically revokes
    it and issues a replacement (rotation). If the token matches a record
    that was *already* revoked, this is treated as reuse of a stolen or
    replayed token: every *other currently active* refresh token for that
    user is revoked once, as a precaution, and the caller must
    re-authenticate.

    "Once" matters: `reuse_detected_at` marks that this specific token's
    theft/reuse has already triggered a session wipe. Without that guard,
    an attacker who simply keeps replaying the same stale, already-revoked
    token would re-trigger the cascade on every attempt — which would also
    revoke any *new, legitimate* session the real user created after the
    original incident was handled, indefinitely. One incident, one wipe.
    """
    token_hash = hash_refresh_token(raw_token)
    record = db.query(RefreshToken).filter(RefreshToken.token_hash == token_hash).one_or_none()

    if record is None:
        raise RefreshTokenInvalidError()

    user = db.query(User).filter(User.id == record.user_id).one_or_none()

    if record.revoked_at is not None:
        if record.reuse_detected_at is None:
            record.reuse_detected_at = datetime.now(timezone.utc)
            db.add(record)
            revoked_count = 0
            for other in db.query(RefreshToken).filter(
                RefreshToken.user_id == record.user_id, RefreshToken.revoked_at.is_(None)
            ):
                other.revoked_at = datetime.now(timezone.utc)
                db.add(other)
                revoked_count += 1
            db.commit()
            log_audit_event(
                db, action="refresh_token_reuse_detected", actor_id=record.user_id,
                actor_label=user.email if user else None, resource_type="refresh_token", resource_id=str(record.id),
                outcome="denied", source_ip=source_ip, details={"sessions_revoked": revoked_count},
            )
        else:
            log_audit_event(
                db, action="token_refresh_failed", actor_id=record.user_id,
                actor_label=user.email if user else None, resource_type="refresh_token", resource_id=str(record.id),
                outcome="denied", source_ip=source_ip, details={"reason": "replay_of_known_stolen_token"},
            )
        raise RefreshTokenInvalidError(audit_action="refresh_token_reuse_detected")

    if not record.is_active or user is None or not user.is_active:
        log_audit_event(
            db, action="token_refresh_failed", actor_id=record.user_id,
            actor_label=user.email if user else None, resource_type="refresh_token", resource_id=str(record.id),
            outcome="denied", source_ip=source_ip, details={"reason": "expired_or_inactive"},
        )
        raise RefreshTokenInvalidError()

    new_raw, new_record = issue_refresh_token(db, user, user_agent=user_agent, source_ip=source_ip)
    record.revoked_at = datetime.now(timezone.utc)
    record.replaced_by_id = new_record.id
    db.add(record)
    db.commit()

    log_audit_event(
        db, action="token_refresh", actor_id=user.id, actor_label=user.email,
        resource_type="refresh_token", resource_id=str(new_record.id), outcome="success", source_ip=source_ip,
    )
    return new_raw, new_record, user


def revoke_refresh_token(db: Session, raw_token: str, *, source_ip: str | None) -> None:
    token_hash = hash_refresh_token(raw_token)
    record = db.query(RefreshToken).filter(RefreshToken.token_hash == token_hash).one_or_none()
    if record is None or record.revoked_at is not None:
        return
    record.revoked_at = datetime.now(timezone.utc)
    db.add(record)
    db.commit()

    log_audit_event(
        db, action="logout", actor_id=record.user_id, resource_type="refresh_token",
        resource_id=str(record.id), outcome="success", source_ip=source_ip,
    )
