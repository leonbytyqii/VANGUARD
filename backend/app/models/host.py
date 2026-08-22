from datetime import datetime

from sqlalchemy import JSON, DateTime, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base_class import Base, TenantScopedMixin, TimestampMixin, UUIDPrimaryKeyMixin


class Host(Base, UUIDPrimaryKeyMixin, TimestampMixin, TenantScopedMixin):
    """
    An asset (endpoint, server, cloud instance) observed in telemetry.

    `criticality` feeds Phase 5's risk-scoring formula
    (app/services/risk_scoring.py) — expected values are "low",
    "standard" (default), "important", "critical", documented there
    rather than as a DB enum so an admin can tune it without a migration.
    """
    __tablename__ = "hosts"

    # Phase 5 bug fix: hostname was globally unique across the whole
    # deployment (a single index, not scoped to organization_id), which
    # meant two different tenants could never both register a host named
    # e.g. "WIN-01" — a near-certain real-world collision once a second
    # tenant exists. Caught while wiring asset-criticality lookups into
    # risk scoring. Fixed by scoping uniqueness to (organization_id,
    # hostname) via the composite constraint below instead of a
    # column-level `unique=True`. See alembic migration
    # ac52294ad8d5_host_hostname_tenant_scoped_uniqueness.
    hostname: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    os_family: Mapped[str | None] = mapped_column(String(64), nullable=True)  # windows / linux / cloud
    criticality: Mapped[str] = mapped_column(String(32), default="standard", nullable=False)
    owner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tags: Mapped[dict] = mapped_column(JSON, default=dict)
    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (UniqueConstraint("organization_id", "hostname", name="uq_hosts_org_hostname"),)
