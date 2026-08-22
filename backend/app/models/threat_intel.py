import uuid
from datetime import datetime

from sqlalchemy import JSON, Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Table, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base_class import Base, TenantScopedMixin, TimestampMixin, UUIDPrimaryKeyMixin

incident_iocs = Table(
    "incident_iocs",
    Base.metadata,
    Column("incident_id", UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True),
    Column("ioc_id", UUID(as_uuid=True), ForeignKey("iocs.id", ondelete="CASCADE"), primary_key=True),
)


class IOC(Base, UUIDPrimaryKeyMixin, TimestampMixin, TenantScopedMixin):
    """A tracked indicator of compromise, independent of which provider(s) have scored it."""
    __tablename__ = "iocs"

    ioc_type: Mapped[str] = mapped_column(String(16), nullable=False, index=True)  # IOCType
    value: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    related_alert_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    related_incident_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    notes: Mapped[str] = mapped_column(String, default="", nullable=False)
    added_by_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)

    # --- Phase 10: aggregate verdict across providers -------------------
    # Derived, never set by a caller: app/services/threat_intel.py
    # recomputes both from the IOC's `enrichments` every time one is added.
    # Storing the aggregate rather than computing it per read is what makes
    # "show me every malicious indicator" a single indexed query instead of
    # a join-and-fold over every enrichment row.
    reputation: Mapped[str] = mapped_column(String(16), nullable=False, default="unknown", index=True)  # IOCReputation
    threat_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0, index=True)  # 0-100
    last_enriched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # False = kept for history but no longer treated as a live indicator.
    # Deleting an IOC would orphan the incidents that cite it, so
    # retirement is a flag, not a DELETE.
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)

    enrichments: Mapped[list["ThreatIntelligence"]] = relationship(
        back_populates="ioc", cascade="all, delete-orphan", order_by="ThreatIntelligence.queried_at"
    )

    __table_args__ = (
        # One row per indicator per tenant. Without this, repeated
        # extraction from overlapping events would create a new IOC every
        # time and the enrichment cache would never hit.
        UniqueConstraint("organization_id", "ioc_type", "value", name="uq_iocs_org_type_value"),
    )


class ThreatIntelligence(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """One enrichment result for an IOC from one provider (VirusTotal, AbuseIPDB, OTX, internal, mock, ...)."""
    __tablename__ = "threat_intelligence"

    ioc_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False, index=True)
    ioc: Mapped["IOC"] = relationship(back_populates="enrichments")

    provider: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    reputation: Mapped[str] = mapped_column(String(32), nullable=False)  # malicious/suspicious/clean/unknown
    confidence: Mapped[float] = mapped_column(Float, nullable=False)  # 0-1
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    raw_response: Mapped[dict] = mapped_column(JSON, default=dict)
    queried_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # --- Phase 10 ------------------------------------------------------
    # When this result stops being reused from cache. A verdict is a
    # point-in-time observation: an IP that was clean last month is not
    # evidence that it is clean now, so results expire rather than being
    # trusted indefinitely.
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    # True when the provider was unreachable / errored. The row is still
    # written — a failed lookup is information, and silently retrying
    # forever against a dead provider is worse than recording that it is
    # dead.
    lookup_failed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    error: Mapped[str | None] = mapped_column(String, nullable=True)
