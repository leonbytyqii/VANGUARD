import uuid
from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base_class import Base, TenantScopedMixin, TimestampMixin, UUIDPrimaryKeyMixin


class DetectionRule(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    A loaded detection rule — either parsed from a Sigma YAML file or a
    registered custom Python detection / behavioral correlation. Kept in the
    DB (not just on disk) so the UI can show rule provenance, enable/disable
    rules, and every fired Detection can reference exactly which rule
    version produced it.
    """
    __tablename__ = "detection_rules"

    rule_id: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(String, default="", nullable=False)
    engine: Mapped[str] = mapped_column(String(32), nullable=False, index=True)  # DetectionEngine
    level: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")  # sigma-style level
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="stable")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    mitre_technique_ids: Mapped[list[str]] = mapped_column(JSON, default=list)  # e.g. ["T1059.001"]
    logsource: Mapped[dict] = mapped_column(JSON, default=dict)
    detection_definition: Mapped[dict] = mapped_column(JSON, default=dict)  # parsed sigma / rule params
    source_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    base_risk_score: Mapped[int] = mapped_column(default=50, nullable=False)

    detections: Mapped[list["Detection"]] = relationship(back_populates="rule")
    # Relational counterpart to `mitre_technique_ids` above (Phase 6) —
    # kept in sync by app/mitre/seed.py::link_detection_rules_to_techniques.
    # See app/models/mitre.py::MitreTechnique's docstring for why both
    # representations exist side by side.
    mitre_techniques: Mapped[list["MitreTechnique"]] = relationship(  # noqa: F821
        secondary="detection_rule_mitre_techniques", back_populates="detection_rules"
    )


class Detection(Base, UUIDPrimaryKeyMixin, TimestampMixin, TenantScopedMixin):
    """
    A single firing of a DetectionRule against one or more events. Unlike
    DetectionRule (the shared, org-independent rule catalog), a Detection
    is tenant data — it's derived from one organization's events and must
    never be visible to another organization (see app.core.scope).
    """
    __tablename__ = "detections"

    rule_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("detection_rules.id"), nullable=False, index=True)
    rule: Mapped["DetectionRule"] = relationship(back_populates="detections")

    matched_event_ids: Mapped[list[str]] = mapped_column(JSON, default=list)  # event UUIDs as strings
    host_name: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    user: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    fired_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    evidence_summary: Mapped[dict] = mapped_column(JSON, default=dict)
    risk_score: Mapped[int] = mapped_column(nullable=False, default=0)
