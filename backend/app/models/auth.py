import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, String
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
