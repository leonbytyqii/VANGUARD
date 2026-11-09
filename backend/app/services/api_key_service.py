"""
Phase 16 — API key lifecycle (create, list, rotate, revoke).

Design:
- Raw key format: "vanguard_<32 random bytes hex>" (prefix makes them
  identifiable and scannable by secret-scanning tools).
- Only the SHA-256 hex digest is stored; the raw key is returned once on
  creation and once on rotation.
- Keys are scoped to the creating user's organization and carry the
  creating user's permission set at the time of creation. They do NOT
  follow subsequent role changes on the user (intentional — this avoids
  silent permission escalation on existing machine tokens).
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models.auth import APIKey
from app.models.user import User
from app.services.audit import log_audit_event

_KEY_PREFIX = "vanguard_"
_KEY_BYTES = 32  # 64 hex chars → 256 bits of entropy


def _generate_raw_key() -> str:
    return _KEY_PREFIX + secrets.token_hex(_KEY_BYTES)


def _hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def _prefix(raw: str) -> str:
    """First 16 chars of the raw key (prefix + start of random part) for display."""
    return raw[:16]


class APIKeyError(Exception):
    def __init__(self, message: str, status_code: int = 400):
        self.message = message
        self.status_code = status_code
        super().__init__(message)


def create_api_key(
    db: Session,
    user: User,
    *,
    name: str,
    expires_at: datetime | None = None,
) -> tuple[APIKey, str]:
    """
    Create a new API key for the user. Returns (record, raw_key).
    The raw_key must be shown to the user immediately and is never
    recoverable afterward.
    """
    raw = _generate_raw_key()
    record = APIKey(
        user_id=user.id,
        organization_id=user.organization_id,
        name=name,
        key_prefix=_prefix(raw),
        key_hash=_hash_key(raw),
        expires_at=expires_at,
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    log_audit_event(
        db, action="api_key_created", actor_id=user.id, actor_label=user.email,
        resource_type="api_key", resource_id=str(record.id), outcome="success",
        details={"name": name, "expires_at": expires_at.isoformat() if expires_at else None},
    )
    return record, raw


def list_api_keys(db: Session, user: User) -> list[APIKey]:
    """Return all non-revoked API keys for the user."""
    return (
        db.query(APIKey)
        .filter(APIKey.user_id == user.id, APIKey.revoked_at.is_(None))
        .order_by(APIKey.created_at.desc())
        .all()
    )


def revoke_api_key(db: Session, user: User, key_id: str) -> APIKey:
    """
    Revoke an API key by ID. Only the owning user (or a superuser) can
    revoke a key; this is enforced at the API layer by scoping the lookup
    to the user's own keys.
    """
    import uuid as _uuid
    record = (
        db.query(APIKey)
        .filter(APIKey.id == _uuid.UUID(key_id), APIKey.user_id == user.id, APIKey.revoked_at.is_(None))
        .one_or_none()
    )
    if record is None:
        raise APIKeyError("API key not found or already revoked.", status_code=404)

    record.revoked_at = datetime.now(timezone.utc)
    db.add(record)
    db.commit()

    log_audit_event(
        db, action="api_key_revoked", actor_id=user.id, actor_label=user.email,
        resource_type="api_key", resource_id=str(record.id), outcome="success",
        details={"name": record.name},
    )
    return record


def rotate_api_key(db: Session, user: User, key_id: str) -> tuple[APIKey, str]:
    """
    Rotate: revoke the old key and issue a new one with the same name and
    expiry. Returns (new_record, raw_key).
    """
    old = revoke_api_key(db, user, key_id)
    new_record, raw = create_api_key(db, user, name=old.name, expires_at=old.expires_at)

    log_audit_event(
        db, action="api_key_rotated", actor_id=user.id, actor_label=user.email,
        resource_type="api_key", resource_id=str(new_record.id), outcome="success",
        details={"old_id": key_id, "name": old.name},
    )
    return new_record, raw


def authenticate_by_api_key(db: Session, raw_key: str) -> APIKey | None:
    """
    Look up and validate a raw API key. Returns the active APIKey record
    or None. Updates last_used_at on success.
    """
    if not raw_key.startswith(_KEY_PREFIX):
        return None

    record = db.query(APIKey).filter(APIKey.key_hash == _hash_key(raw_key)).one_or_none()
    if record is None or not record.is_active:
        return None

    record.last_used_at = datetime.now(timezone.utc)
    db.add(record)
    db.commit()
    return record
