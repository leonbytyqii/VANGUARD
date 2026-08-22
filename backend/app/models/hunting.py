"""
Threat-hunting data model (Phase 7): saved, reusable hunt query
definitions and a full audit trail of every time one was actually run.

A `HuntQuery.query_definition` is a Sigma-shaped selection/condition dict
— identical in shape to a Sigma detection's `detection:` block (named
selections plus a `condition` string) — evaluated on demand against a
bounded historical time range, rather than registered as a persistent
auto-firing `DetectionRule` (Phase 4). This is the deliberate distinction
between detection engineering and threat hunting: a `DetectionRule` fires
automatically on every future matching event; a `HuntQuery` is a
hypothesis a human (or, later, the Phase 8 `threat_hunt` agent type —
see app/models/enums.py::AgentType) tests against history on demand, and
can be promoted into a real `DetectionRule` once proven precise enough to
run unattended. `app/hunting/engine.py` evaluates both through the exact
same safe, no-`eval()` matcher (`app/detections/sigma_engine/matcher.py`)
so there is one tested boolean-matching implementation, not two.

Two-tier ownership, mirroring `DetectionRule`'s global-catalog design:
`HuntQuery` rows with `organization_id IS NULL` are built-in library
queries shipped with the platform (seeded by
app/hunting/builtin_queries.py + app/hunting/seed.py, read-only, listable
and runnable by every organization); non-null rows are an org's own
analyst-authored custom queries, visible and editable only within that
org (enforced in app/api/v1/hunting.py, not by the schema — the FK itself
is deliberately nullable, same as every other TenantScopedMixin table).

`HuntExecution` is always tenant-scoped — one run, by one analyst,
against one organization's `Event` rows — and freezes the exact
`query_definition` it ran as `query_definition_snapshot`, so editing or
deleting the saved `HuntQuery` later never changes the historical record
of what a past run actually searched for. This is the same
evidence-integrity reasoning that governs `Detection.matched_event_ids`
(Phase 4) and every AI agent's evidence citations (docs/ARCHITECTURE.md
§6): a record of "what was searched for and what it found" must remain
independently re-checkable even if the definition that produced it
changes underneath it.
"""
import uuid
from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base_class import Base, TenantScopedMixin, TimestampMixin, UUIDPrimaryKeyMixin


class HuntQuery(Base, UUIDPrimaryKeyMixin, TimestampMixin, TenantScopedMixin):
    __tablename__ = "hunt_queries"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(String, nullable=False, default="")

    # True for the seeded library queries (app/hunting/builtin_queries.py)
    # — always paired with organization_id IS NULL, but stored explicitly
    # rather than inferred from nullability so a future "org forks a
    # builtin into its own editable copy" feature has somewhere to record
    # provenance without an ambiguous null-check.
    is_builtin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)

    # Sigma-shaped {"<selection_name>": {"<Field>|<modifier>": value}, "condition": "..."}
    # — see this module's docstring and app/hunting/engine.py.
    query_definition: Mapped[dict] = mapped_column(JSON, nullable=False)

    # Default scan window when a run request doesn't specify one explicitly.
    default_lookback_hours: Mapped[int] = mapped_column(Integer, nullable=False, default=24)

    # JSON-only, not a relational M2M like DetectionRule.mitre_techniques
    # (Phase 6) — deliberately smaller scope: nothing yet needs to query
    # "every hunt query covering technique X" via a join the way the
    # coverage-matrix API needs it for detections. Documented as the
    # natural next step (docs/THREAT_HUNTING.md §5) if that need appears.
    mitre_technique_ids: Mapped[list[str]] = mapped_column(JSON, default=list)

    created_by_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)

    executions: Mapped[list["HuntExecution"]] = relationship(back_populates="hunt_query")


class HuntExecution(Base, UUIDPrimaryKeyMixin, TimestampMixin, TenantScopedMixin):
    __tablename__ = "hunt_executions"

    # ondelete="SET NULL": deleting a custom HuntQuery (app/api/v1/hunting.py's
    # DELETE endpoint) must never be blocked by, or cascade-destroy, its
    # past run history — query_definition_snapshot below already preserves
    # exactly what that run searched for independent of this FK.
    hunt_query_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("hunt_queries.id", ondelete="SET NULL"), nullable=True, index=True
    )
    hunt_query: Mapped["HuntQuery | None"] = relationship(back_populates="executions")

    # See class docstring: frozen at run time, independent of later edits
    # to the HuntQuery this pointed at (or independent of any saved query
    # at all, for an ad hoc/unsaved run — hunt_query_id is nullable).
    query_definition_snapshot: Mapped[dict] = mapped_column(JSON, nullable=False)

    executed_by_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    category_filter: Mapped[str | None] = mapped_column(String(64), nullable=True)  # EventCategory, optional narrowing

    time_range_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    time_range_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    status: Mapped[str] = mapped_column(String(16), nullable=False, default="completed", index=True)  # completed | failed

    scanned_event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    matched_event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Capped at app.hunting.engine.MAX_MATCHES_RETURNED — matched_event_count
    # above always reflects the true total, even when this list was
    # truncated (truncated_results=True), so the count is never quietly wrong.
    matched_event_ids: Mapped[list[str]] = mapped_column(JSON, default=list)

    truncated_scan: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    truncated_results: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    error: Mapped[str | None] = mapped_column(String, nullable=True)

    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
