"""
Threat-hunting execution engine (Phase 7).

Reuses the exact same safe, no-`eval()` Sigma selection/condition matcher
that powers the auto-firing detection engine (Phase 4,
app/detections/sigma_engine/matcher.py::evaluate_detection_dict) — a
hunt query is literally a Sigma-shaped selection+condition dict evaluated
against `Event` rows in a bounded time range, on demand, rather than
registered as a persistent auto-firing `DetectionRule`. This lets an
analyst test a hunting hypothesis against history before deciding whether
it's precise enough to promote to a permanent detection (a real, common
SOC workflow), without duplicating the boolean-matching logic or its
safety guarantees — there is exactly one tested implementation of "does
this event match this selection/condition", used by both Phase 4 and
Phase 7.

Deliberately synchronous and explicitly bounded — same "simple now,
documented seam to a queue/streaming engine later" posture as detection
execution (app/detections/engine.py) and alert generation
(app/services/alerting.py):

- `MAX_HUNT_RANGE_DAYS` caps the queryable time window so a hunt can't
  request an unbounded full-table scan.
- `MAX_EVENTS_SCANNED` caps how many `Event` rows are pulled into Python
  for matching; if the window contains more than this, the scan stops
  and `truncated_scan=True` is recorded on the `HuntExecution` — a
  partial scan is never silently presented as a complete one.
- `MAX_MATCHES_RETURNED` caps how many matched event IDs are persisted
  per run (the same idea, applied to the *output* instead of the input)
  — `matched_event_count` on the execution always reflects the true
  total number of matches found, even when the stored/returned
  `matched_event_ids` list was truncated.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.detections.sigma_engine.matcher import SigmaConditionError, evaluate_condition, evaluate_detection_dict
from app.detections.sigma_engine.models import SigmaRuleError
from app.models.event import Event
from app.models.hunting import HuntExecution

MAX_HUNT_RANGE_DAYS = 30
MAX_EVENTS_SCANNED = 20_000
MAX_MATCHES_RETURNED = 500


class HuntQueryError(ValueError):
    """
    A structurally invalid `query_definition` or an out-of-bounds time
    range — surfaced by the API layer as a 422, distinct from an
    unexpected runtime failure (which is recorded on the HuntExecution
    row as status="failed" rather than raised, so a bad ad hoc query
    still leaves an auditable record of the attempt).
    """


def validate_query_definition(query_definition: dict) -> None:
    """
    Fails fast, before touching the DB, on a malformed selection/
    condition dict — the same structural checks the Sigma loader
    performs on YAML rules at load time
    (app/detections/sigma_engine/loader.py), applied here to ad hoc,
    request-supplied dicts instead of trusted on-disk files. Also
    dry-runs the condition string's safe-AST parse (with every selection
    forced to `False`) so a request supplying a disallowed condition
    (anything beyond selection names combined with `and`/`or`/`not`/`()`)
    is rejected here rather than surfacing mid-scan.
    """
    if not isinstance(query_definition, dict):
        raise HuntQueryError("query_definition must be a JSON object")
    if "condition" not in query_definition or not isinstance(query_definition["condition"], str):
        raise HuntQueryError("query_definition must include a string 'condition'")

    selection_names = [k for k in query_definition if k != "condition"]
    if not selection_names:
        raise HuntQueryError("query_definition must declare at least one selection")
    for name in selection_names:
        selection = query_definition[name]
        if not isinstance(selection, dict):
            raise HuntQueryError(f"selection '{name}' must be a mapping of field -> value")

    try:
        evaluate_condition(query_definition["condition"], dict.fromkeys(selection_names, False))
    except (SigmaRuleError, SigmaConditionError) as exc:
        raise HuntQueryError(str(exc)) from exc


def run_hunt(
    db: Session,
    *,
    organization_id: uuid.UUID,
    query_definition: dict,
    time_range_start: datetime,
    time_range_end: datetime,
    category_filter: str | None = None,
    executed_by_id: uuid.UUID | None = None,
    hunt_query_id: uuid.UUID | None = None,
) -> HuntExecution:
    """
    Validate, scan, match, and persist one hunt run. Always returns a
    persisted `HuntExecution` — a run that fails mid-scan is recorded
    with status="failed" and an error message rather than raised, so
    every attempt (successful or not) leaves an audit trail; only
    request-level problems (bad query shape, bad time range) raise
    `HuntQueryError` before any DB row is created, since those represent
    a request that was never actually run.
    """
    if time_range_end <= time_range_start:
        raise HuntQueryError("time_range_end must be after time_range_start")
    if (time_range_end - time_range_start).days > MAX_HUNT_RANGE_DAYS:
        raise HuntQueryError(f"Hunt time range cannot exceed {MAX_HUNT_RANGE_DAYS} days")

    validate_query_definition(query_definition)

    started_at = datetime.now(timezone.utc)

    q = (
        db.query(Event)
        .filter(Event.organization_id == organization_id)
        .filter(Event.event_timestamp >= time_range_start)
        .filter(Event.event_timestamp <= time_range_end)
    )
    if category_filter:
        q = q.filter(Event.category == category_filter)

    events = q.order_by(Event.event_timestamp.asc()).limit(MAX_EVENTS_SCANNED + 1).all()
    truncated_scan = len(events) > MAX_EVENTS_SCANNED
    if truncated_scan:
        events = events[:MAX_EVENTS_SCANNED]

    try:
        matched_ids = [e.id for e in events if evaluate_detection_dict(e, query_definition, source_label="hunt query")]
    except Exception as exc:  # noqa: BLE001 — a failing hunt is recorded, not allowed to 500 past an audit trail
        execution = HuntExecution(
            organization_id=organization_id,
            hunt_query_id=hunt_query_id,
            query_definition_snapshot=query_definition,
            executed_by_id=executed_by_id,
            category_filter=category_filter,
            time_range_start=time_range_start,
            time_range_end=time_range_end,
            status="failed",
            scanned_event_count=len(events),
            matched_event_count=0,
            matched_event_ids=[],
            truncated_scan=truncated_scan,
            truncated_results=False,
            error=str(exc),
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
        )
        db.add(execution)
        db.commit()
        db.refresh(execution)
        return execution

    truncated_results = len(matched_ids) > MAX_MATCHES_RETURNED
    returned_ids = matched_ids[:MAX_MATCHES_RETURNED]

    execution = HuntExecution(
        organization_id=organization_id,
        hunt_query_id=hunt_query_id,
        query_definition_snapshot=query_definition,
        executed_by_id=executed_by_id,
        category_filter=category_filter,
        time_range_start=time_range_start,
        time_range_end=time_range_end,
        status="completed",
        scanned_event_count=len(events),
        matched_event_count=len(matched_ids),
        matched_event_ids=[str(i) for i in returned_ids],
        truncated_scan=truncated_scan,
        truncated_results=truncated_results,
        started_at=started_at,
        completed_at=datetime.now(timezone.utc),
    )
    db.add(execution)
    db.commit()
    db.refresh(execution)
    return execution
