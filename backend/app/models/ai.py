import uuid
from datetime import datetime

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base_class import Base, TenantScopedMixin, TimestampMixin, UUIDPrimaryKeyMixin


class AIInvestigation(Base, UUIDPrimaryKeyMixin, TimestampMixin, TenantScopedMixin):
    """
    Top-level record of one agentic investigation run against an alert.
    This is the object the UI's 'Investigate with AI' button creates and
    polls; `agent_steps` gives the full, replayable trace of how the
    conclusion was reached.
    """
    __tablename__ = "ai_investigations"

    alert_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("alerts.id"), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending", index=True)  # InvestigationStatus
    requested_by_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)

    blueprint_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("soc_blueprints.id"), nullable=True)

    ai_provider: Mapped[str] = mapped_column(String(64), nullable=False)
    ai_model: Mapped[str] = mapped_column(String(128), nullable=False)

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Final structured result (validated AIInvestigationResult schema), null until completed
    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    error: Mapped[str | None] = mapped_column(String, nullable=True)

    steps: Mapped[list["AgentStep"]] = relationship(back_populates="investigation", cascade="all, delete-orphan", order_by="AgentStep.step_number")


class AgentStep(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    One reasoning/tool-call step taken by one agent within an investigation.
    This is the audit trace: agent name, what it decided to do, the tool it
    called, the structured evidence it got back, and its intermediate
    reasoning note.
    """
    __tablename__ = "agent_steps"

    investigation_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("ai_investigations.id", ondelete="CASCADE"), nullable=False, index=True)
    investigation: Mapped["AIInvestigation"] = relationship(back_populates="steps")

    step_number: Mapped[int] = mapped_column(Integer, nullable=False)
    agent_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)  # AgentType
    action: Mapped[str] = mapped_column(String(128), nullable=False)  # tool name or "reasoning" / "handoff"
    tool_input: Mapped[dict] = mapped_column(JSON, default=dict)
    tool_output: Mapped[dict] = mapped_column(JSON, default=dict)
    reasoning_note: Mapped[str] = mapped_column(String, default="", nullable=False)
    step_started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    step_completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    evidence: Mapped[list["AgentEvidence"]] = relationship(back_populates="step", cascade="all, delete-orphan")


class AgentEvidence(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    A single atomic piece of evidence surfaced by a tool call. Every claim
    in the final AI report must trace back to one or more rows here, and
    each row must trace back to a real event/detection/IOC id — this is
    what the output validator checks before a report is allowed to render.
    """
    __tablename__ = "agent_evidence"

    step_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("agent_steps.id", ondelete="CASCADE"), nullable=False, index=True)
    step: Mapped["AgentStep"] = relationship(back_populates="evidence")

    claim: Mapped[str] = mapped_column(String, nullable=False)
    source_tool: Mapped[str] = mapped_column(String(128), nullable=False)
    source_event_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    source_table: Mapped[str | None] = mapped_column(String(64), nullable=True)  # events / detections / iocs / cloud_events
    confidence: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
