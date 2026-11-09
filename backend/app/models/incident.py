import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import JSON, Boolean, Column, DateTime, ForeignKey, Integer, String, Table, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base_class import Base, TenantScopedMixin, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:  # pragma: no cover - resolves the string forward references SQLAlchemy uses below
    from app.models.alert import Alert
    from app.models.mitre import MitreTechnique
    from app.models.threat_intel import IOC
    from app.models.user import User

incident_alerts = Table(
    "incident_alerts",
    Base.metadata,
    Column("incident_id", UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True),
    Column("alert_id", UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True),
)

incident_mitre_techniques = Table(
    "incident_mitre_techniques",
    Base.metadata,
    Column("incident_id", UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True),
    Column("technique_id", UUID(as_uuid=True), ForeignKey("mitre_techniques.id", ondelete="CASCADE"), primary_key=True),
)


class Incident(Base, UUIDPrimaryKeyMixin, TimestampMixin, TenantScopedMixin):
    __tablename__ = "incidents"

    # Human-readable case reference, rendered "INC-000042" by the API
    # (app/schemas/incident.py::format_incident_reference). Sequential
    # *per organization*, not globally: two tenants both having an
    # INC-000001 is correct, and a tenant being able to infer another
    # tenant's case volume from a global counter is not. Allocation and
    # its unique-violation retry live in
    # app/services/incidents.py::_allocate_incident_number.
    incident_number: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    summary: Mapped[str] = mapped_column(String, default="", nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="new", index=True)  # IncidentStatus
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)

    assigned_to_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    assigned_to: Mapped["User | None"] = relationship(foreign_keys=[assigned_to_id])

    created_by_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    created_by: Mapped["User | None"] = relationship(foreign_keys=[created_by_id])

    # Phase 9 lifecycle milestones. These are *derived from real
    # transitions* (set by app/services/incidents.py the moment the
    # status actually changes), never supplied by the caller — an IR
    # metric an analyst can type in by hand is not a metric. Each is set
    # once, on first entry into that stage; re-entering `contained` after
    # a regression does not reset `contained_at`, because
    # time-to-first-containment is the number the SOC is measured on.
    detected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    triaged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    contained_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Mandatory when status == closed; see IncidentClosureClassification.
    closure_classification: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    closure_summary: Mapped[str | None] = mapped_column(String, nullable=True)

    alerts: Mapped[list["Alert"]] = relationship(secondary=incident_alerts)
    mitre_techniques: Mapped[list["MitreTechnique"]] = relationship(secondary=incident_mitre_techniques)
    iocs: Mapped[list["IOC"]] = relationship(secondary="incident_iocs")

    tasks: Mapped[list["IncidentTask"]] = relationship(back_populates="incident", cascade="all, delete-orphan")
    notes: Mapped[list["IncidentNote"]] = relationship(back_populates="incident", cascade="all, delete-orphan")
    timeline_events: Mapped[list["IncidentEvent"]] = relationship(back_populates="incident", cascade="all, delete-orphan")

    __table_args__ = (
        UniqueConstraint("organization_id", "incident_number", name="uq_incidents_org_number"),
    )


class IncidentTask(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    One item on an incident's response checklist. New incidents are seeded
    with the NIST SP 800-61r2-shaped default checklist in
    app/incidents/task_templates.py; analysts add case-specific tasks on
    top of it.
    """
    __tablename__ = "incident_tasks"

    incident_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    incident: Mapped["Incident"] = relationship(back_populates="tasks")

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    done: Mapped[bool] = mapped_column(default=False, nullable=False)
    assigned_to_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)

    description: Mapped[str] = mapped_column(String, default="", nullable=False)
    category: Mapped[str] = mapped_column(String(32), nullable=False, default="detection_analysis", index=True)  # IncidentTaskCategory
    # Presentation order within the checklist. Seeded tasks get 10, 20, 30…
    # so an analyst-added task can be slotted between two of them without
    # renumbering the rest.
    sort_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    is_from_template: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_by_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)


class IncidentNote(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    `is_ai_generated` is set to True *only* by the internal promotion path
    (app/services/incidents.py::promote_investigation_to_incident). The
    HTTP note endpoint hard-codes it to False and does not read it from
    the request body, so no caller can post text that renders in the case
    file with a provenance it didn't have — in either direction.
    """
    __tablename__ = "incident_notes"

    incident_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    incident: Mapped["Incident"] = relationship(back_populates="notes")

    author_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    body: Mapped[str] = mapped_column(String, nullable=False)
    is_ai_generated: Mapped[bool] = mapped_column(default=False, nullable=False)


class IncidentEvent(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A single timeline entry for an incident (status change, evidence added, action taken, ...)."""
    __tablename__ = "incident_events"

    incident_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    incident: Mapped["Incident"] = relationship(back_populates="timeline_events")

    event_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    kind: Mapped[str] = mapped_column(String(64), nullable=False)  # IncidentTimelineKind
    actor: Mapped[str | None] = mapped_column(String(255), nullable=True)  # user email or "ai_agent:<type>"
    details: Mapped[dict] = mapped_column(JSON, default=dict)
