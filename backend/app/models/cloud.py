import uuid
from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base_class import Base, TenantScopedMixin, TimestampMixin, UUIDPrimaryKeyMixin


class CloudIdentity(Base, UUIDPrimaryKeyMixin, TimestampMixin, TenantScopedMixin):
    """An IAM identity (user, role, service account) observed in cloud telemetry."""
    __tablename__ = "cloud_identities"

    provider: Mapped[str] = mapped_column(String(32), nullable=False, default="aws")
    account_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    identity_type: Mapped[str] = mapped_column(String(32), nullable=False)  # user / role / service
    identity_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    arn: Mapped[str | None] = mapped_column(String(512), nullable=True, index=True)
    attached_policies: Mapped[list[str]] = mapped_column(JSON, default=list)
    effective_permissions: Mapped[list[str]] = mapped_column(JSON, default=list)
    is_privileged: Mapped[bool] = mapped_column(default=False, nullable=False)
    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class CloudEvent(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    A normalized CloudTrail-style event. Distinct from the generic `events`
    table because cloud/IAM events carry identity-chain fields (actor,
    assumed role, source identity) that drive attack-path reconstruction.
    """
    __tablename__ = "cloud_events"

    event_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("events.id"), nullable=True, index=True)

    event_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    provider: Mapped[str] = mapped_column(String(32), nullable=False, default="aws")
    account_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    region: Mapped[str | None] = mapped_column(String(64), nullable=True)
    event_name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)  # e.g. AssumeRole, PutUserPolicy
    event_source: Mapped[str] = mapped_column(String(128), nullable=False)  # e.g. iam.amazonaws.com

    actor_identity: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    actor_arn: Mapped[str | None] = mapped_column(String(512), nullable=True)
    assumed_role_arn: Mapped[str | None] = mapped_column(String(512), nullable=True, index=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)

    request_parameters: Mapped[dict] = mapped_column(JSON, default=dict)
    response_elements: Mapped[dict] = mapped_column(JSON, default=dict)
    error_code: Mapped[str | None] = mapped_column(String(128), nullable=True)

    raw_event: Mapped[dict] = mapped_column(JSON, nullable=False)


class IAMAttackPath(Base, UUIDPrimaryKeyMixin, TimestampMixin, TenantScopedMixin):
    """
    A reconstructed identity-based attack path, e.g.
    compromised_user -> AssumeRole -> DeveloperRole -> iam:PassRole ->
    Lambda -> PrivilegedRole -> sensitive S3 access.
    `path_nodes`/`path_edges` drive the IAM attack-path graph view.

    Tenant-scoped directly (Phase 11) rather than inferred from the
    alert/incident it hangs off: a path can legitimately have neither set
    (an analyst reconstructing an identity chain ad hoc), and deriving
    visibility from a nullable FK would have meant those paths were
    visible to everyone or to no one.
    """
    __tablename__ = "iam_attack_paths"

    alert_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("alerts.id"), nullable=True, index=True)
    incident_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("incidents.id"), nullable=True, index=True)
    investigation_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("ai_investigations.id"), nullable=True, index=True)

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    path_nodes: Mapped[list[dict]] = mapped_column(JSON, default=list)  # [{id, type, label, ...}]
    path_edges: Mapped[list[dict]] = mapped_column(JSON, default=list)  # [{from, to, action, event_id}]
    privilege_escalation_detected: Mapped[bool] = mapped_column(default=False, nullable=False)
    explanation: Mapped[str] = mapped_column(String, default="", nullable=False)
