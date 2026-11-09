import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base_class import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:  # pragma: no cover - resolves the string forward references SQLAlchemy uses below
    from app.models.user import User


class RefreshToken(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    Server-side record of an issued refresh token, so refresh tokens
    (unlike short-lived access JWTs) can be revoked and rotation-reuse can
    be detected. The raw token is never stored — only its SHA-256 hash —
    so a database leak doesn't hand out working credentials.
    """
    __tablename__ = "refresh_tokens"

    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    user: Mapped["User"] = relationship()

    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)  # sha256 hex
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    replaced_by_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("refresh_tokens.id"), nullable=True)

    # Set the first (and only the first) time this specific token is
    # replayed after already being revoked. Without this, an attacker who
    # merely holds on to one stale, already-rotated-away token could
    # replay it forever and force a full session wipe on *every* attempt —
    # including wiping out legitimate sessions the user created long after
    # the original incident was already handled. See
    # app/services/auth_service.py::rotate_refresh_token.
    reuse_detected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)

    @property
    def is_active(self) -> bool:
        from app.db.base_class import utcnow
        return self.revoked_at is None and self.expires_at > utcnow()


class TOTPDevice(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    One TOTP enrollment per user. The secret is stored encrypted at rest
    (see services/mfa_service.py — the application-layer encryption key
    comes from settings.MFA_ENCRYPTION_KEY). Storing an encrypted secret
    rather than a one-way hash allows recovery-flow regeneration without
    forcing the user to re-scan a QR code during a key rotation.

    Only one device per user is supported. Re-enrolling overwrites the
    existing row (old secret immediately invalidated).
    """
    __tablename__ = "totp_devices"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False, unique=True, index=True,
    )
    user: Mapped["User"] = relationship()

    encrypted_secret: Mapped[str] = mapped_column(Text, nullable=False)
    confirmed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    enrolled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class RecoveryCode(Base, UUIDPrimaryKeyMixin):
    """
    One-time backup codes issued when a user enables TOTP. Each code is
    stored as an Argon2id hash (never plaintext). Using a code marks it
    consumed; codes are never recycled. A regeneration call deletes all
    existing codes and issues a fresh batch.
    """
    __tablename__ = "recovery_codes"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    user: Mapped["User"] = relationship()

    code_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    @property
    def is_used(self) -> bool:
        return self.used_at is not None


class APIKey(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    Long-lived API key for machine-to-machine access. The raw key is
    returned ONCE on creation and never stored — only its SHA-256 hex
    digest is persisted. Keys are scoped to the issuing user's organization
    and carry an optional permission subset (empty list = inherit all
    permissions the user has).
    """
    __tablename__ = "api_keys"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    user: Mapped["User"] = relationship()

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    name: Mapped[str] = mapped_column(String(100), nullable=False)
    key_prefix: Mapped[str] = mapped_column(String(16), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)

    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    @property
    def is_active(self) -> bool:
        from app.db.base_class import utcnow
        now = utcnow()
        return self.revoked_at is None and (self.expires_at is None or self.expires_at > now)
