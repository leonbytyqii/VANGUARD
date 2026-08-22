import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    """Shared declarative base for all ORM models."""
    pass


class UUIDPrimaryKeyMixin:
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


class TenantScopedMixin:
    """
    Applied to every resource table that a future multi-tenant deployment
    must isolate (hosts, events, alerts, incidents, IOCs, cloud identities,
    AI investigations, playbooks, blueprints, response actions).

    Nullable today because Phase 2 ships a single default Organization and
    later phases (3+) are the ones that actually populate these tables with
    data — but the column, the index, and the query-scoping helper
    (`app.core.scope.scoped_query`) all exist now so that turning on real
    multi-tenancy later is a matter of (a) making the column non-nullable
    and (b) confirming every query already goes through the scoping helper,
    rather than a schema rewrite touching every table.
    """
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=True, index=True
    )
