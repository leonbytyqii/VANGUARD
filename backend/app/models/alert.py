import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import JSON, Column, DateTime, ForeignKey, Index, Integer, String, Table
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base_class import Base, TenantScopedMixin, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:  # pragma: no cover - resolves the string forward references SQLAlchemy uses below
    from app.models.mitre import MitreTechnique
    from app.models.user import User

alert_mitre_techniques = Table(
    "alert_mitre_techniques",
    Base.metadata,
    Column("alert_id", UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True),
    Column("technique_id", UUID(as_uuid=True), ForeignKey("mitre_techniques.id", ondelete="CASCADE"), primary_key=True),
)


class Alert(Base, UUIDPrimaryKeyMixin, TimestampMixin, TenantScopedMixin):
    """
    A generated alert. Risk scoring logic lives in
    app/services/risk_scoring.py and is fully documented in
    docs/DETECTION_ENGINE.md — this table stores the *result* plus enough
    structured evidence references that the score can always be explained.
    """
    __tablename__ = "alerts"

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(String, default="", nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)  # Severity
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, index=True)  # 0-100
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="new", index=True)  # AlertStatus

    source: Mapped[str] = mapped_column(String(64), nullable=False)
    detection_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("detections.id"), nullable=True, index=True)

    host_name: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    user: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)

    evidence: Mapped[dict] = mapped_column(JSON, default=dict)  # structured evidence snapshot
    related_event_ids: Mapped[list[str]] = mapped_column(JSON, default=list)

    assigned_to_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    assigned_to: Mapped["User | None"] = relationship()

    mitre_techniques: Mapped[list["MitreTechnique"]] = relationship(secondary=alert_mitre_techniques)

    alert_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)

    __table_args__ = (
        Index("ix_alerts_severity_status", "severity", "status"),
        Index("ix_alerts_host_user", "host_name", "user"),
    )
