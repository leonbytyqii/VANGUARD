"""
The incident-response case engine (docs/INCIDENT_RESPONSE.md).

Three things in here are load-bearing and worth reading before the code:

1. **The lifecycle is a state machine, not a free-text field.**
   `INCIDENT_TRANSITIONS` is the whole graph, and
   `transition_incident_status` is the only function that writes
   `Incident.status`. This is the same shape as Phase 2's response-action
   approval machine, for the same reason: a status column any handler can
   assign to is a status column that eventually holds a value no
   downstream consumer expected.

2. **Lifecycle timestamps are derived, never supplied.** `triaged_at`,
   `contained_at` and `closed_at` are stamped by this module at the
   moment the transition actually happens. Nothing in the API accepts
   them from a caller, because an IR metric an analyst can type in by
   hand is not a metric. `detected_at` is the one exception to "now" —
   it is taken from the *evidence's* own timestamp (the earliest linked
   alert), not from when somebody got round to opening the case, so
   time-to-triage measures the SOC rather than the paperwork.

3. **Nothing here executes anything.** An incident reaching `contained`
   is a human recording that containment happened; it does not isolate a
   host, and there is no code path from a status transition to
   `app.services.response_actions.execute_response_action`. Containment
   actions keep going through the Phase 2 `pending → approved →
   executed` machine with a human holding `response.approve`, exactly as
   before — Phase 9 only makes those actions *visible* on the case file.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Iterable

from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.incidents.task_templates import default_checklist
from app.models.alert import Alert
from app.models.ai import AIInvestigation
from app.models.automation import ResponseAction
from app.models.enums import (
    IncidentClosureClassification,
    IncidentStatus,
    IncidentTaskCategory,
    IncidentTimelineKind,
    InvestigationStatus,
    Severity,
)
from app.models.event import Event
from app.models.incident import Incident, IncidentNote, IncidentTask
from app.models.user import User
from app.services.audit import log_audit_event
from app.services.incident_timeline import record_timeline_event


class IncidentError(Exception):
    def __init__(self, message: str, *, status_code: int = 400):
        self.status_code = status_code
        super().__init__(message)


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

# NIST SP 800-61r2's handling phases, as an explicit transition graph.
#
# Two shapes here are deliberate rather than accidental:
#   * `closed` is reachable from *every* state. Deciding at any point that
#     a case is a false positive and closing it is normal SOC work, not an
#     anomaly, and forcing it to walk the full chain first would mean
#     recording containment that never happened.
#   * Backward edges exist where reality has them — `contained ->
#     investigating` (new scope surfaced) and `eradicated -> contained`
#     (the eradication regressed). What does *not* exist is a jump that
#     would skip evidence: `new -> contained` is refused, because you
#     cannot have contained something you have not yet scoped.
INCIDENT_TRANSITIONS: dict[str, frozenset[str]] = {
    IncidentStatus.NEW.value: frozenset({"triaged", "investigating", "closed"}),
    IncidentStatus.TRIAGED.value: frozenset({"investigating", "contained", "closed"}),
    IncidentStatus.INVESTIGATING.value: frozenset({"contained", "closed"}),
    IncidentStatus.CONTAINED.value: frozenset({"eradicated", "investigating", "closed"}),
    IncidentStatus.ERADICATED.value: frozenset({"recovered", "contained", "closed"}),
    IncidentStatus.RECOVERED.value: frozenset({"closed", "investigating"}),
    # Reopening is the single edge out of `closed`, and the route layer
    # additionally requires `incidents.assign` for it — see
    # app/api/v1/incidents.py. Reopening lands in `investigating` rather
    # than restoring the previous status: a case being looked at again is
    # by definition under investigation.
    IncidentStatus.CLOSED.value: frozenset({"investigating"}),
}

_VALID_STATUSES = {s.value for s in IncidentStatus}
_VALID_CLOSURE_CLASSIFICATIONS = {c.value for c in IncidentClosureClassification}
_VALID_TASK_CATEGORIES = {c.value for c in IncidentTaskCategory}

_SEVERITY_ORDER: dict[str, int] = {
    Severity.INFO.value: 0,
    Severity.LOW.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.HIGH.value: 3,
    Severity.CRITICAL.value: 4,
}

_MAX_NUMBER_ALLOCATION_ATTEMPTS = 5


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _actor_label(user: User | None) -> str | None:
    return user.email if user is not None else None


def max_severity(severities: Iterable[str], *, default: str = Severity.MEDIUM.value) -> str:
    ranked = [s for s in severities if s in _SEVERITY_ORDER]
    if not ranked:
        return default
    return max(ranked, key=lambda s: _SEVERITY_ORDER[s])


def _allocate_incident_number(db: Session, organization_id: uuid.UUID | None) -> int:
    current = (
        db.query(func.max(Incident.incident_number))
        .filter(Incident.organization_id == organization_id)
        .scalar()
    )
    return (current or 0) + 1


# ---------------------------------------------------------------------------
# Alert linking
# ---------------------------------------------------------------------------


def _fetch_scoped_alerts(db: Session, organization_id: uuid.UUID | None, alert_ids: list[uuid.UUID]) -> list[Alert]:
    """
    Resolve alert ids *within the incident's own organization*.

    An id that exists but belongs to another tenant is reported the same
    way as an id that does not exist at all — confirming that some other
    org has an alert with that id is exactly the cross-tenant information
    leak `app/core/scope.py` exists to prevent. Callers surface this as a
    422 naming only the ids the caller could legitimately have known
    about (their own), never a 403.
    """
    if not alert_ids:
        return []
    unique_ids = list(dict.fromkeys(alert_ids))
    alerts = (
        db.query(Alert)
        .filter(Alert.id.in_(unique_ids), Alert.organization_id == organization_id)
        .all()
    )
    found = {a.id for a in alerts}
    missing = [str(i) for i in unique_ids if i not in found]
    if missing:
        raise IncidentError(f"Unknown alert id(s): {', '.join(missing)}", status_code=422)
    return alerts


def _sync_mitre_from_alerts(incident: Incident) -> list[str]:
    """
    Recompute the incident's ATT&CK tags as the union over its currently
    linked alerts, and return the resulting technique ids.

    Recomputed wholesale rather than incrementally added, so unlinking an
    alert also removes the techniques only that alert contributed. There
    is no way to tag an incident with a technique by hand, which is what
    makes "recompute from scratch" safe — the linked alerts are the sole
    source of truth for this field.
    """
    by_id = {}
    for alert in incident.alerts:
        for technique in alert.mitre_techniques:
            by_id[technique.id] = technique
    incident.mitre_techniques = list(by_id.values())
    return sorted(t.technique_id for t in by_id.values())


def _refresh_detected_at(incident: Incident) -> None:
    """
    `detected_at` is the earliest evidence timestamp across the linked
    alerts — the moment the platform first had a signal — falling back to
    case creation time when no alert is linked. Linking an older alert
    later moves it *earlier*; it never moves later, because evidence does
    not become newer.
    """
    timestamps = [a.alert_timestamp for a in incident.alerts if a.alert_timestamp is not None]
    if timestamps:
        earliest = min(timestamps)
        if incident.detected_at is None or earliest < incident.detected_at:
            incident.detected_at = earliest
    elif incident.detected_at is None:
        incident.detected_at = incident.created_at or _now()


def link_alerts(
    db: Session,
    incident: Incident,
    *,
    alert_ids: list[uuid.UUID],
    actor: User | None,
    source_ip: str | None = None,
    commit: bool = True,
) -> list[Alert]:
    """
    Attach alerts to an incident. Returns the alerts newly linked by this
    call (already-linked ids are a no-op, not an error — re-posting the
    same promotion request should be idempotent).

    Note what this deliberately does *not* do: it does not raise the
    incident's severity to match a newly linked alert. An analyst who set
    a case to MEDIUM after looking at it has made a judgement, and
    silently overriding it because a noisy HIGH alert got attached would
    destroy that judgement invisibly. Instead the timeline entry records
    the linked alert's severity, so an escalation is *visible* and the
    analyst can act on it.
    """
    alerts = _fetch_scoped_alerts(db, incident.organization_id, alert_ids)
    already = {a.id for a in incident.alerts}
    newly = [a for a in alerts if a.id not in already]

    for alert in newly:
        incident.alerts.append(alert)

    if newly:
        _refresh_detected_at(incident)
        technique_ids = _sync_mitre_from_alerts(incident)
        db.add(incident)
        db.flush()
        for alert in newly:
            record_timeline_event(
                db,
                incident_id=incident.id,
                kind=IncidentTimelineKind.ALERT_LINKED,
                actor=_actor_label(actor),
                details={
                    "alert_id": str(alert.id),
                    "title": alert.title,
                    "severity": alert.severity,
                    "risk_score": alert.risk_score,
                    "host_name": alert.host_name,
                    "user": alert.user,
                    # Surfaced rather than auto-applied — see the docstring above.
                    "exceeds_incident_severity": (
                        _SEVERITY_ORDER.get(alert.severity, -1) > _SEVERITY_ORDER.get(incident.severity, -1)
                    ),
                },
                commit=False,
            )
        log_audit_event(
            db,
            action="incident_alerts_linked",
            actor_id=actor.id if actor else None,
            actor_label=_actor_label(actor),
            resource_type="incident",
            resource_id=str(incident.id),
            outcome="success",
            source_ip=source_ip,
            details={"alert_ids": [str(a.id) for a in newly], "mitre_technique_ids": technique_ids},
            commit=False,
        )

    if commit:
        db.commit()
        db.refresh(incident)
    return newly


def unlink_alert(
    db: Session,
    incident: Incident,
    *,
    alert_id: uuid.UUID,
    actor: User | None,
    source_ip: str | None = None,
) -> None:
    alert = next((a for a in incident.alerts if a.id == alert_id), None)
    if alert is None:
        raise IncidentError("Alert is not linked to this incident.", status_code=404)

    incident.alerts.remove(alert)
    technique_ids = _sync_mitre_from_alerts(incident)
    db.add(incident)
    db.flush()
    record_timeline_event(
        db,
        incident_id=incident.id,
        kind=IncidentTimelineKind.ALERT_UNLINKED,
        actor=_actor_label(actor),
        details={"alert_id": str(alert.id), "title": alert.title},
        commit=False,
    )
    log_audit_event(
        db,
        action="incident_alert_unlinked",
        actor_id=actor.id if actor else None,
        actor_label=_actor_label(actor),
        resource_type="incident",
        resource_id=str(incident.id),
        outcome="success",
        source_ip=source_ip,
        details={"alert_id": str(alert.id), "mitre_technique_ids": technique_ids},
        commit=False,
    )
    db.commit()
    db.refresh(incident)


# ---------------------------------------------------------------------------
# Creation
# ---------------------------------------------------------------------------


def seed_default_checklist(db: Session, incident: Incident) -> list[IncidentTask]:
    tasks: list[IncidentTask] = []
    for index, template in enumerate(default_checklist(), start=1):
        task = IncidentTask(
            incident_id=incident.id,
            title=template.title,
            description=template.description,
            category=template.category.value,
            sort_order=index * 10,
            is_from_template=True,
        )
        db.add(task)
        tasks.append(task)
    return tasks


def create_incident(
    db: Session,
    *,
    organization_id: uuid.UUID | None,
    title: str,
    summary: str = "",
    severity: str | None = None,
    created_by: User | None,
    alert_ids: list[uuid.UUID] | None = None,
    seed_checklist: bool = True,
    source_ip: str | None = None,
) -> Incident:
    """
    Open a case.

    `severity` may be omitted when `alert_ids` are supplied, in which case
    it is derived as the highest severity among the linked alerts — the
    "promote these alerts into an incident" path, where making the analyst
    restate a severity the alerts already carry is just an opportunity to
    get it wrong.
    """
    alert_ids = alert_ids or []
    alerts = _fetch_scoped_alerts(db, organization_id, alert_ids)

    if severity is None:
        if not alerts:
            raise IncidentError(
                "severity is required when the incident is not created from alerts.", status_code=422
            )
        severity = max_severity(a.severity for a in alerts)
    elif severity not in _SEVERITY_ORDER:
        raise IncidentError(f"Unknown severity '{severity}'.", status_code=422)

    incident = _insert_incident_with_number(
        db,
        organization_id=organization_id,
        title=title,
        summary=summary,
        severity=severity,
        created_by=created_by,
    )

    record_timeline_event(
        db,
        incident_id=incident.id,
        kind=IncidentTimelineKind.CREATED,
        actor=_actor_label(created_by),
        details={"title": title, "severity": severity, "from_alerts": len(alerts)},
        commit=False,
    )

    if seed_checklist:
        seeded = seed_default_checklist(db, incident)
        db.flush()
        record_timeline_event(
            db,
            incident_id=incident.id,
            kind=IncidentTimelineKind.TASK,
            actor=None,  # platform-generated, not somebody's action
            details={"action": "checklist_seeded", "task_count": len(seeded), "template": "nist_sp_800_61r2"},
            commit=False,
        )

    if alerts:
        link_alerts(
            db, incident, alert_ids=[a.id for a in alerts], actor=created_by, source_ip=source_ip, commit=False
        )

    _refresh_detected_at(incident)
    db.add(incident)

    log_audit_event(
        db,
        action="incident_created",
        actor_id=created_by.id if created_by else None,
        actor_label=_actor_label(created_by),
        resource_type="incident",
        resource_id=str(incident.id),
        outcome="success",
        source_ip=source_ip,
        details={
            "title": incident.title,
            "severity": incident.severity,
            "incident_number": incident.incident_number,
            "alert_count": len(alerts),
        },
        commit=False,
    )

    db.commit()
    db.refresh(incident)
    return incident


def _insert_incident_with_number(
    db: Session,
    *,
    organization_id: uuid.UUID | None,
    title: str,
    summary: str,
    severity: str,
    created_by: User | None,
) -> Incident:
    """
    Insert the incident row, allocating its per-tenant case number.

    `max(incident_number) + 1` read-then-write is racy by construction, so
    the correctness here comes from the database, not from the read: a
    unique constraint on `(organization_id, incident_number)` turns a lost
    race into an `IntegrityError` rather than two cases sharing a
    reference, and we retry against the now-higher maximum. Under
    contention this converges in one or two attempts; a Postgres sequence
    would not work here because the numbering has to restart per tenant.
    """
    last_error: IntegrityError | None = None
    for _ in range(_MAX_NUMBER_ALLOCATION_ATTEMPTS):
        savepoint = db.begin_nested()
        incident = Incident(
            organization_id=organization_id,
            incident_number=_allocate_incident_number(db, organization_id),
            title=title,
            summary=summary,
            severity=severity,
            status=IncidentStatus.NEW.value,
            created_by_id=created_by.id if created_by else None,
            detected_at=None,
        )
        db.add(incident)
        try:
            savepoint.commit()
            db.flush()
            return incident
        except IntegrityError as exc:
            last_error = exc
            savepoint.rollback()
            db.expunge(incident)
    raise IncidentError(
        "Could not allocate an incident number after repeated contention; retry the request.",
        status_code=503,
    ) from last_error


# ---------------------------------------------------------------------------
# Mutation
# ---------------------------------------------------------------------------


def transition_incident_status(
    db: Session,
    incident: Incident,
    *,
    new_status: str,
    actor: User | None,
    closure_classification: str | None = None,
    closure_summary: str | None = None,
    reopen_authorized: bool = False,
    source_ip: str | None = None,
) -> Incident:
    if new_status not in _VALID_STATUSES:
        raise IncidentError(f"Unknown incident status '{new_status}'.", status_code=422)

    previous = incident.status
    if new_status == previous:
        raise IncidentError(f"Incident is already in status '{previous}'.", status_code=409)

    allowed = INCIDENT_TRANSITIONS.get(previous, frozenset())
    if new_status not in allowed:
        raise IncidentError(
            f"Illegal transition '{previous}' -> '{new_status}'. "
            f"Allowed from '{previous}': {', '.join(sorted(allowed)) or 'none'}.",
            status_code=409,
        )

    is_reopen = previous == IncidentStatus.CLOSED.value
    if is_reopen and not reopen_authorized:
        # Belt and braces: the route already gates this on
        # `incidents.assign`. Repeating the check here means a future
        # internal caller cannot reopen a case just by not being an HTTP
        # request.
        raise IncidentError("Reopening a closed incident requires the 'incidents.assign' permission.", status_code=403)

    details: dict[str, Any] = {"from": previous, "to": new_status}

    if new_status == IncidentStatus.CLOSED.value:
        if not closure_classification:
            raise IncidentError(
                "closure_classification is required when closing an incident "
                f"(one of: {', '.join(sorted(_VALID_CLOSURE_CLASSIFICATIONS))}).",
                status_code=422,
            )
        if closure_classification not in _VALID_CLOSURE_CLASSIFICATIONS:
            raise IncidentError(
                f"Unknown closure_classification '{closure_classification}'.", status_code=422
            )
        incident.closure_classification = closure_classification
        incident.closure_summary = closure_summary
        incident.closed_at = _now()
        details["closure_classification"] = closure_classification

    if is_reopen:
        # The prior verdict is carried into the timeline before it is
        # cleared, so "this was closed as a false positive and then
        # reopened" stays answerable from the case file.
        details["reopened_from_classification"] = incident.closure_classification
        details["previously_closed_at"] = incident.closed_at.isoformat() if incident.closed_at else None
        incident.closure_classification = None
        incident.closure_summary = None
        incident.closed_at = None

    # First-entry stamping only: a case that re-enters containment after a
    # regression keeps its original time-to-contain.
    if new_status == IncidentStatus.TRIAGED.value and incident.triaged_at is None:
        incident.triaged_at = _now()
    if new_status == IncidentStatus.CONTAINED.value and incident.contained_at is None:
        incident.contained_at = _now()
    # Skipping straight from `new` to `investigating` still counts as
    # having been triaged — the analyst has looked at it, they just did
    # not stop at the intermediate state.
    if new_status == IncidentStatus.INVESTIGATING.value and incident.triaged_at is None and not is_reopen:
        incident.triaged_at = _now()

    incident.status = new_status
    db.add(incident)
    db.flush()

    record_timeline_event(
        db,
        incident_id=incident.id,
        kind=IncidentTimelineKind.STATUS_CHANGE,
        actor=_actor_label(actor),
        details=details,
        commit=False,
    )
    log_audit_event(
        db,
        action="incident_reopened" if is_reopen else "incident_status_changed",
        actor_id=actor.id if actor else None,
        actor_label=_actor_label(actor),
        resource_type="incident",
        resource_id=str(incident.id),
        outcome="success",
        source_ip=source_ip,
        details=details,
        commit=False,
    )
    db.commit()
    db.refresh(incident)
    return incident


def update_incident_fields(
    db: Session,
    incident: Incident,
    *,
    actor: User | None,
    title: str | None = None,
    summary: str | None = None,
    severity: str | None = None,
    source_ip: str | None = None,
) -> Incident:
    changed: dict[str, Any] = {}
    if title is not None and title != incident.title:
        changed["title"] = {"from": incident.title, "to": title}
        incident.title = title
    if summary is not None and summary != incident.summary:
        changed["summary"] = {"changed": True}
        incident.summary = summary
    if severity is not None and severity != incident.severity:
        if severity not in _SEVERITY_ORDER:
            raise IncidentError(f"Unknown severity '{severity}'.", status_code=422)
        changed["severity"] = {"from": incident.severity, "to": severity}
        incident.severity = severity

    if not changed:
        return incident

    db.add(incident)
    db.flush()
    record_timeline_event(
        db,
        incident_id=incident.id,
        kind=IncidentTimelineKind.STATUS_CHANGE if "severity" in changed else IncidentTimelineKind.NOTE,
        actor=_actor_label(actor),
        details={"action": "fields_updated", **changed},
        commit=False,
    )
    log_audit_event(
        db,
        action="incident_updated",
        actor_id=actor.id if actor else None,
        actor_label=_actor_label(actor),
        resource_type="incident",
        resource_id=str(incident.id),
        outcome="success",
        source_ip=source_ip,
        details=changed,
        commit=False,
    )
    db.commit()
    db.refresh(incident)
    return incident


def assign_incident(
    db: Session,
    incident: Incident,
    *,
    assignee: User,
    actor: User | None,
    source_ip: str | None = None,
) -> Incident:
    previous = incident.assigned_to_id
    incident.assigned_to_id = assignee.id
    # Assigning an untouched case is itself the triage act.
    if incident.status == IncidentStatus.NEW.value:
        incident.status = IncidentStatus.TRIAGED.value
        if incident.triaged_at is None:
            incident.triaged_at = _now()

    db.add(incident)
    db.flush()
    record_timeline_event(
        db,
        incident_id=incident.id,
        kind=IncidentTimelineKind.ASSIGNMENT,
        actor=_actor_label(actor),
        details={
            "assigned_to": assignee.email,
            "previous_assignee_id": str(previous) if previous else None,
            "status": incident.status,
        },
        commit=False,
    )
    log_audit_event(
        db,
        action="incident_assigned",
        actor_id=actor.id if actor else None,
        actor_label=_actor_label(actor),
        resource_type="incident",
        resource_id=str(incident.id),
        outcome="success",
        source_ip=source_ip,
        details={"assigned_to": assignee.email},
        commit=False,
    )
    db.commit()
    db.refresh(incident)
    return incident


def add_note(
    db: Session,
    incident: Incident,
    *,
    body: str,
    author: User | None,
    is_ai_generated: bool = False,
    source_ip: str | None = None,
    commit: bool = True,
) -> IncidentNote:
    """
    `is_ai_generated` is a *keyword-only internal* argument. The HTTP
    route never forwards a caller-supplied value into it — see
    app/api/v1/incidents.py::add_incident_note. The only caller that
    passes True is `promote_investigation_to_incident`.
    """
    note = IncidentNote(
        incident_id=incident.id,
        author_id=author.id if author else None,
        body=body,
        is_ai_generated=is_ai_generated,
    )
    db.add(note)
    db.flush()
    record_timeline_event(
        db,
        incident_id=incident.id,
        kind=IncidentTimelineKind.NOTE,
        actor="ai_agent:investigation" if is_ai_generated else _actor_label(author),
        details={"note_id": str(note.id), "is_ai_generated": is_ai_generated, "preview": body[:200]},
        commit=False,
    )
    log_audit_event(
        db,
        action="incident_note_added",
        actor_id=author.id if author else None,
        actor_label=_actor_label(author),
        resource_type="incident",
        resource_id=str(incident.id),
        outcome="success",
        source_ip=source_ip,
        details={"note_id": str(note.id), "is_ai_generated": is_ai_generated},
        commit=False,
    )
    if commit:
        db.commit()
        db.refresh(note)
    return note


# ---------------------------------------------------------------------------
# Tasks
# ---------------------------------------------------------------------------


def create_task(
    db: Session,
    incident: Incident,
    *,
    title: str,
    description: str = "",
    category: str = IncidentTaskCategory.DETECTION_ANALYSIS.value,
    assignee: User | None = None,
    sort_order: int | None = None,
    actor: User | None,
    source_ip: str | None = None,
) -> IncidentTask:
    if category not in _VALID_TASK_CATEGORIES:
        raise IncidentError(f"Unknown task category '{category}'.", status_code=422)

    if sort_order is None:
        current_max = (
            db.query(func.max(IncidentTask.sort_order))
            .filter(IncidentTask.incident_id == incident.id)
            .scalar()
        )
        sort_order = (current_max or 0) + 10

    task = IncidentTask(
        incident_id=incident.id,
        title=title,
        description=description,
        category=category,
        sort_order=sort_order,
        assigned_to_id=assignee.id if assignee else None,
        is_from_template=False,
    )
    db.add(task)
    db.flush()
    record_timeline_event(
        db,
        incident_id=incident.id,
        kind=IncidentTimelineKind.TASK,
        actor=_actor_label(actor),
        details={"action": "task_created", "task_id": str(task.id), "title": title, "category": category},
        commit=False,
    )
    db.commit()
    db.refresh(task)
    return task


def update_task(
    db: Session,
    incident: Incident,
    task: IncidentTask,
    *,
    actor: User | None,
    title: str | None = None,
    description: str | None = None,
    category: str | None = None,
    done: bool | None = None,
    assignee: User | None = None,
    clear_assignee: bool = False,
    source_ip: str | None = None,
) -> IncidentTask:
    changed: dict[str, Any] = {}
    if title is not None and title != task.title:
        changed["title"] = title
        task.title = title
    if description is not None and description != task.description:
        changed["description"] = True
        task.description = description
    if category is not None and category != task.category:
        if category not in _VALID_TASK_CATEGORIES:
            raise IncidentError(f"Unknown task category '{category}'.", status_code=422)
        changed["category"] = category
        task.category = category
    if clear_assignee:
        changed["assigned_to"] = None
        task.assigned_to_id = None
    elif assignee is not None and assignee.id != task.assigned_to_id:
        changed["assigned_to"] = assignee.email
        task.assigned_to_id = assignee.id
    if done is not None and done != task.done:
        changed["done"] = done
        task.done = done
        # Un-ticking clears the completion attribution rather than
        # leaving a stale "completed by" on an open task.
        task.completed_at = _now() if done else None
        task.completed_by_id = (actor.id if actor else None) if done else None

    if not changed:
        return task

    db.add(task)
    db.flush()
    record_timeline_event(
        db,
        incident_id=incident.id,
        kind=IncidentTimelineKind.TASK,
        actor=_actor_label(actor),
        details={"action": "task_updated", "task_id": str(task.id), "title": task.title, **changed},
        commit=False,
    )
    db.commit()
    db.refresh(task)
    return task


def delete_task(
    db: Session,
    incident: Incident,
    task: IncidentTask,
    *,
    actor: User | None,
    source_ip: str | None = None,
) -> None:
    task_id = str(task.id)
    title = task.title
    db.delete(task)
    db.flush()
    record_timeline_event(
        db,
        incident_id=incident.id,
        kind=IncidentTimelineKind.TASK,
        actor=_actor_label(actor),
        details={"action": "task_deleted", "task_id": task_id, "title": title},
        commit=False,
    )
    db.commit()


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


def _elapsed_seconds(start: datetime | None, end: datetime | None) -> int | None:
    if start is None or end is None:
        return None
    # Clamped at zero rather than reported negative. A negative value is
    # reachable honestly — linking an alert whose evidence timestamp
    # predates an already-recorded triage moves `detected_at` backwards
    # after the fact — but "this incident was contained -3 minutes after
    # detection" is not a number any dashboard should render. The
    # timeline still shows the real ordering.
    return max(0, int((end - start).total_seconds()))


def compute_incident_metrics(db: Session, incident: Incident) -> dict[str, Any]:
    """
    The IR numbers a SOC is actually measured on, derived entirely from
    timestamps this module stamped at transition time.

    All three durations are measured from `detected_at` (first evidence),
    not from `created_at` (when a human opened the case) — measuring from
    case creation would flatter the SOC by excluding exactly the delay
    that matters most.
    """
    now = _now()
    total_tasks = db.query(func.count(IncidentTask.id)).filter(IncidentTask.incident_id == incident.id).scalar() or 0
    done_tasks = (
        db.query(func.count(IncidentTask.id))
        .filter(IncidentTask.incident_id == incident.id, IncidentTask.done.is_(True))
        .scalar()
        or 0
    )
    is_open = incident.status != IncidentStatus.CLOSED.value
    return {
        "detected_at": incident.detected_at,
        "triaged_at": incident.triaged_at,
        "contained_at": incident.contained_at,
        "closed_at": incident.closed_at,
        "time_to_triage_seconds": _elapsed_seconds(incident.detected_at, incident.triaged_at),
        "time_to_contain_seconds": _elapsed_seconds(incident.detected_at, incident.contained_at),
        "time_to_close_seconds": _elapsed_seconds(incident.detected_at, incident.closed_at),
        "open_duration_seconds": _elapsed_seconds(incident.detected_at, now if is_open else incident.closed_at),
        "is_open": is_open,
        "tasks_total": int(total_tasks),
        "tasks_completed": int(done_tasks),
        "alert_count": len(incident.alerts),
    }


# ---------------------------------------------------------------------------
# AI investigation -> incident
# ---------------------------------------------------------------------------


def promote_investigation_to_incident(
    db: Session,
    investigation: AIInvestigation,
    *,
    actor: User | None,
    title: str | None = None,
    source_ip: str | None = None,
) -> tuple[Incident, dict[str, Any]]:
    """
    Turn a completed AI investigation into a real case file.

    **The Phase 8 "never fabricate evidence" rule applies again here, at a
    second boundary.** The orchestrator already validated every citation
    when it accepted the result; this re-validates them against the
    database at promotion time rather than trusting the stored JSON,
    because the two happen at different moments and a stored result is
    just data by the time it gets here. An evidence item naming a
    `source_event_id` is written to the case timeline only if that id
    still resolves to a real `Event` row *in this organization*. Items
    that do not resolve are counted and reported back to the caller —
    never silently dropped, and never written as though they were
    corroborated.

    Returns `(incident, promotion_report)`.
    """
    from app.schemas.ai_investigation import AIInvestigationResult  # local: avoids a schema<->service import cycle

    if investigation.status != InvestigationStatus.COMPLETED.value:
        raise IncidentError(
            f"Investigation is in status '{investigation.status}'; only a completed investigation can be promoted.",
            status_code=409,
        )
    if not investigation.result:
        raise IncidentError("Investigation has no stored result to promote.", status_code=409)

    try:
        result = AIInvestigationResult.model_validate(investigation.result)
    except Exception as exc:  # noqa: BLE001 - surfaced to the caller as a 422, not swallowed
        raise IncidentError(f"Stored investigation result is not a valid AIInvestigationResult: {exc}", status_code=422)

    alert = (
        db.query(Alert)
        .filter(Alert.id == investigation.alert_id, Alert.organization_id == investigation.organization_id)
        .one_or_none()
    )
    if alert is None:
        raise IncidentError("The investigation's alert is not available in this organization.", status_code=404)

    incident = create_incident(
        db,
        organization_id=investigation.organization_id,
        title=title or f"AI-investigated: {alert.title}",
        summary=result.summary,
        severity=result.severity,
        created_by=actor,
        alert_ids=[alert.id],
        seed_checklist=True,
        source_ip=source_ip,
    )

    # The AI's own narrative, stored with honest provenance. It renders as
    # AI-authored in the case file; no HTTP caller can produce a note with
    # this flag set.
    add_note(
        db,
        incident,
        body=result.summary,
        author=actor,
        is_ai_generated=True,
        source_ip=source_ip,
        commit=False,
    )

    recorded = 0
    rejected: list[dict[str, Any]] = []
    for item in result.observed_evidence:
        if item.source_event_id:
            try:
                event_uuid = uuid.UUID(item.source_event_id)
            except (TypeError, ValueError):
                rejected.append({"claim": item.claim, "reason": "source_event_id is not a valid uuid"})
                continue
            exists = (
                db.query(Event.id)
                .filter(Event.id == event_uuid, Event.organization_id == investigation.organization_id)
                .first()
            )
            if exists is None:
                rejected.append({"claim": item.claim, "reason": "source_event_id does not resolve to a real event"})
                continue
            event_backed = True
        else:
            # Grounded in a non-Event source (the alert, a host lookup, an
            # IOC enrichment). Recorded, but explicitly flagged as not
            # event-backed rather than implied to be.
            event_backed = False

        record_timeline_event(
            db,
            incident_id=incident.id,
            kind=IncidentTimelineKind.EVIDENCE,
            actor="ai_agent:investigation",
            details={
                "claim": item.claim,
                "source_tool": item.source_tool,
                "source_table": item.source_table,
                "source_event_id": item.source_event_id,
                "confidence": item.confidence,
                "event_backed": event_backed,
            },
            commit=False,
        )
        recorded += 1

    # Response actions this investigation already filed belong on the case
    # file. Their approval status is untouched — a pending action stays
    # pending; being attached to an incident approves nothing.
    linked_actions = (
        db.query(ResponseAction)
        .filter(
            ResponseAction.investigation_id == investigation.id,
            ResponseAction.organization_id == investigation.organization_id,
            ResponseAction.incident_id.is_(None),
        )
        .all()
    )
    for action in linked_actions:
        action.incident_id = incident.id
        db.add(action)
        record_timeline_event(
            db,
            incident_id=incident.id,
            kind=IncidentTimelineKind.RESPONSE_ACTION,
            actor=f"ai_agent:{action.requested_by_agent_type}" if action.requested_by_agent_type else None,
            details={
                "action": "attached_to_incident",
                "response_action_id": str(action.id),
                "action_type": action.action_type,
                "target": action.target,
                "status": action.status,
                "requires_human_approval": True,
            },
            commit=False,
        )

    report = {
        "investigation_id": str(investigation.id),
        "evidence_recorded": recorded,
        "evidence_rejected": len(rejected),
        "rejected_details": rejected,
        "response_actions_attached": len(linked_actions),
        "hypotheses": len(result.hypotheses),
    }

    record_timeline_event(
        db,
        incident_id=incident.id,
        kind=IncidentTimelineKind.AI_INVESTIGATION,
        actor="ai_agent:investigation",
        details={
            "action": "promoted_to_incident",
            "investigation_id": str(investigation.id),
            "ai_provider": investigation.ai_provider,
            "ai_model": investigation.ai_model,
            "confidence": result.confidence,
            "evidence_recorded": recorded,
            "evidence_rejected": len(rejected),
        },
        commit=False,
    )
    log_audit_event(
        db,
        action="incident_promoted_from_investigation",
        actor_id=actor.id if actor else None,
        actor_label=_actor_label(actor),
        resource_type="incident",
        resource_id=str(incident.id),
        outcome="success",
        source_ip=source_ip,
        details=report,
        commit=False,
    )

    db.commit()
    db.refresh(incident)
    return incident, report
