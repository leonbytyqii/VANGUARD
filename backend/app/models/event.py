import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import JSON, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base_class import Base, TenantScopedMixin, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:  # pragma: no cover - resolves the string forward references SQLAlchemy uses below
    from app.models.host import Host


class Event(Base, UUIDPrimaryKeyMixin, TimestampMixin, TenantScopedMixin):
    """
    Normalized security event. Every ingested log — regardless of source
    format — is mapped into this common schema by a source adapter.
    `raw_event` always preserves the untouched original payload; the
    normalized fields are a projection, never a replacement, of that
    evidence.
    """
    __tablename__ = "events"

    event_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False, index=True)  # EventSource
    category: Mapped[str] = mapped_column(String(64), nullable=False, index=True)  # EventCategory
    action: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    event_type: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)

    host_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("hosts.id"), nullable=True, index=True)
    host: Mapped["Host | None"] = relationship()
    host_name_raw: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)

    user: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)

    src_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    dst_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)

    process: Mapped[str | None] = mapped_column(String(512), nullable=True, index=True)
    parent_process: Mapped[str | None] = mapped_column(String(512), nullable=True, index=True)
    command_line: Mapped[str | None] = mapped_column(String, nullable=True)
    file_hash: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)

    domain: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    url: Mapped[str | None] = mapped_column(String, nullable=True)

    cloud_account: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    cloud_region: Mapped[str | None] = mapped_column(String(64), nullable=True)
    iam_role: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)

    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    raw_event: Mapped[dict] = mapped_column(JSON, nullable=False)

    __table_args__ = (
        Index("ix_events_source_category", "source", "category"),
        Index("ix_events_host_user", "host_name_raw", "user"),
    )


class Process(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    Reconstructed process-tree node, derived from process_creation events.
    Lets the frontend render parent/child relationships without
    re-scanning raw events on every click.
    """
    __tablename__ = "processes"

    event_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("events.id"), nullable=False, index=True)
    host_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("hosts.id"), nullable=True, index=True)

    process_name: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    process_guid: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    parent_process_name: Mapped[str | None] = mapped_column(String(512), nullable=True, index=True)
    parent_process_guid: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    command_line: Mapped[str | None] = mapped_column(String, nullable=True)
    user: Mapped[str | None] = mapped_column(String(255), nullable=True)
    file_hash: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    process_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class NetworkConnection(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "network_connections"

    event_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("events.id"), nullable=False, index=True)
    host_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("hosts.id"), nullable=True, index=True)

    src_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    dst_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(16), nullable=True)
    process_name: Mapped[str | None] = mapped_column(String(512), nullable=True)
    connection_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
