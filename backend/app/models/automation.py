import uuid
from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base_class import Base, TenantScopedMixin, TimestampMixin, UUIDPrimaryKeyMixin


class Playbook(Base, UUIDPrimaryKeyMixin, TimestampMixin, TenantScopedMixin):
    """
    A deterministic, fixed-order SOAR playbook (classic automation — the
    counterpoint to a SOC Blueprint). Used for predictable, low-risk
    enrichment work where adaptive reasoning isn't needed.
    """
    __tablename__ = "playbooks"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(String, default="", nullable=False)
    trigger: Mapped[str] = mapped_column(String(128), nullable=False)  # e.g. detection_rule:brute_force
    steps: Mapped[list[dict]] = mapped_column(JSON, default=list)  # ordered list of {action, params}
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    runs: Mapped[list["PlaybookRun"]] = relationship(back_populates="playbook", cascade="all, delete-orphan")


class PlaybookRun(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "playbook_runs"

    playbook_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("playbooks.id", ondelete="CASCADE"), nullable=False, index=True)
    playbook: Mapped["Playbook"] = relationship(back_populates="runs")

    alert_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("alerts.id"), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="running")
    step_log: Mapped[list[dict]] = mapped_column(JSON, default=list)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class SOCBlueprint(Base, UUIDPrimaryKeyMixin, TimestampMixin, TenantScopedMixin):
    """
    A *goal template* for the agentic Investigation Agent — a named,
    reusable checklist of suggested investigation steps for a class of
    alert (e.g. 'Suspicious PowerShell'). Unlike a Playbook, the agent
    treats this as a starting point, not a script: it can skip, reorder, or
    add steps based on the evidence it actually finds.
    """
    __tablename__ = "soc_blueprints"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(String, default="", nullable=False)
    applies_to: Mapped[dict] = mapped_column(JSON, default=dict)  # matcher, e.g. {"detection_rule": "suspicious_powershell"}
    suggested_steps: Mapped[list[dict]] = mapped_column(JSON, default=list)  # ordered checklist for the agent
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class ResponseAction(Base, UUIDPrimaryKeyMixin, TimestampMixin, TenantScopedMixin):
    """
    A proposed high-impact response action (isolate_host, disable_account,
    block_ip, revoke_cloud_credentials, ...).

    Origin is always one of: a human analyst (`requested_by_id` set) or an
    AI agent acting inside an investigation (`requested_by_agent_type`
    set). Either way this row starts life as `status=pending` and the
    *only* code path that can move it to `approved` is
    app.services.response_actions.approve_response_action, which requires
    an authenticated human User with the `response.approve` permission —
    there is no tool in the AI tool registry that calls it, so an agent
    cannot approve its own request no matter what it 'decides'. Execution
    additionally requires status == approved. See docs/SECURITY.md
    ("Human-in-the-loop approval model") for the full state machine.
    """
    __tablename__ = "response_actions"

    action_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    target: Mapped[str] = mapped_column(String(255), nullable=False)  # hostname / username / ip / role arn
    justification: Mapped[str] = mapped_column(String, nullable=False)
    investigation_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("ai_investigations.id"), nullable=True)
    incident_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("incidents.id"), nullable=True)

    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending", index=True)  # ApprovalStatus

    requested_by_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    requested_by_agent_type: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)  # AgentType, if AI-originated

    approved_by_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rejected_by_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    rejected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rejection_reason: Mapped[str | None] = mapped_column(String, nullable=True)

    executed_by_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    result: Mapped[dict] = mapped_column(JSON, default=dict)  # execution result / simulated effect
    verification: Mapped[dict] = mapped_column(JSON, default=dict)  # post-execution telemetry check
