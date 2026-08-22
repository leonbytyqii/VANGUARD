"""
Dashboard aggregation API (Phase 12).

One endpoint, one round trip. The alternative — having the SOC overview
page fire eight parallel list requests and count the rows client-side —
would be wrong twice over: it would paginate-truncate the counts (a page
showing "50 alerts" because that is the page size is worse than showing
nothing), and it would compute security metrics in a place a user can
tamper with.

Everything here is a `COUNT`/`GROUP BY` executed inside the caller's
tenant scope. Nothing is cached: a SOC overview that is quietly ninety
seconds stale is a SOC overview that gets acted on ninety seconds late,
and at this data volume the aggregate queries are cheap.
"""
from collections import Counter
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.deps import require_permission
from app.core.scope import scoped_query
from app.db.session import get_db
from app.models.ai import AIInvestigation
from app.models.alert import Alert
from app.models.automation import ResponseAction
from app.models.cloud import IAMAttackPath
from app.models.detection import Detection, DetectionRule
from app.models.enums import IncidentStatus, Severity
from app.models.event import Event
from app.models.incident import Incident
from app.models.threat_intel import IOC
from app.models.user import User
from app.schemas.dashboard import (
    DashboardOverview,
    SeverityBreakdown,
    TimeseriesPoint,
    TopEntity,
)

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

_SEVERITIES = [s.value for s in Severity]


@router.get("/overview", response_model=DashboardOverview)
def dashboard_overview(
    window_hours: int = Query(24, ge=1, le=720),
    db: Session = Depends(get_db),
    # `alerts.read` is the narrowest permission every role that should see
    # a SOC overview already holds. The payload itself contains only
    # counts, never row contents, so it cannot leak anything a caller
    # could not already list.
    current_user: User = Depends(require_permission("alerts.read")),
):
    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=window_hours)

    alerts = scoped_query(db, Alert, current_user)
    incidents = scoped_query(db, Incident, current_user)

    open_alerts = alerts.filter(Alert.status.notin_(["closed", "false_positive"]))
    alert_severity = Counter(
        {row[0]: row[1] for row in alerts.with_entities(Alert.severity, func.count(Alert.id)).group_by(Alert.severity)}
    )
    open_incidents_q = incidents.filter(Incident.status != IncidentStatus.CLOSED.value)

    # --- MTTx over cases closed in the window -------------------------
    closed_recent = incidents.filter(
        Incident.status == IncidentStatus.CLOSED.value, Incident.closed_at.isnot(None), Incident.closed_at >= since
    ).all()
    triage_times = [
        (i.triaged_at - i.detected_at).total_seconds()
        for i in closed_recent
        if i.triaged_at and i.detected_at and i.triaged_at >= i.detected_at
    ]
    contain_times = [
        (i.contained_at - i.detected_at).total_seconds()
        for i in closed_recent
        if i.contained_at and i.detected_at and i.contained_at >= i.detected_at
    ]
    close_times = [
        (i.closed_at - i.detected_at).total_seconds()
        for i in closed_recent
        if i.closed_at and i.detected_at and i.closed_at >= i.detected_at
    ]

    # --- Alert volume per hour ----------------------------------------
    recent_alerts = alerts.filter(Alert.alert_timestamp >= since).all()
    buckets: Counter[str] = Counter()
    for alert in recent_alerts:
        bucket = alert.alert_timestamp.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)
        buckets[bucket.isoformat()] += 1
    timeseries = [TimeseriesPoint(bucket=k, count=v) for k, v in sorted(buckets.items())]

    top_hosts = Counter(a.host_name for a in recent_alerts if a.host_name)
    top_users = Counter(a.user for a in recent_alerts if a.user)

    # --- Detection-rule firing counts ---------------------------------
    # Grouped on `DetectionRule.rule_id` (the human-readable identifier),
    # not `Detection.rule_id` — which is a UUID foreign key with the same
    # attribute name on the related table. Reading the latter yields UUIDs
    # where a rule name belongs; see docs/LAB.md §8 for the same trap
    # caught in the scenario runner.
    rule_counts = (
        db.query(DetectionRule.rule_id, func.count(Detection.id))
        .join(Detection, Detection.rule_id == DetectionRule.id)
        .filter(Detection.organization_id == current_user.organization_id, Detection.fired_at >= since)
        .group_by(DetectionRule.rule_id)
        .order_by(func.count(Detection.id).desc())
        .limit(5)
        .all()
    )

    pending_approvals = (
        scoped_query(db, ResponseAction, current_user).filter(ResponseAction.status == "pending").count()
    )

    return DashboardOverview(
        generated_at=now,
        window_hours=window_hours,
        events_total=scoped_query(db, Event, current_user).count(),
        events_in_window=scoped_query(db, Event, current_user).filter(Event.event_timestamp >= since).count(),
        alerts_total=alerts.count(),
        alerts_open=open_alerts.count(),
        alerts_in_window=len(recent_alerts),
        alerts_by_severity=SeverityBreakdown(**{s.lower(): alert_severity.get(s, 0) for s in _SEVERITIES}),
        incidents_total=incidents.count(),
        incidents_open=open_incidents_q.count(),
        incidents_by_status={
            row[0]: row[1]
            for row in incidents.with_entities(Incident.status, func.count(Incident.id)).group_by(Incident.status)
        },
        # Null rather than 0 when nothing closed in the window — "no data"
        # and "instantaneous response" must not render identically.
        mean_time_to_triage_seconds=int(sum(triage_times) / len(triage_times)) if triage_times else None,
        mean_time_to_contain_seconds=int(sum(contain_times) / len(contain_times)) if contain_times else None,
        mean_time_to_close_seconds=int(sum(close_times) / len(close_times)) if close_times else None,
        incidents_closed_in_window=len(closed_recent),
        pending_approvals=pending_approvals,
        ai_investigations_total=scoped_query(db, AIInvestigation, current_user).count(),
        ai_investigations_in_window=scoped_query(db, AIInvestigation, current_user)
        .filter(AIInvestigation.created_at >= since)
        .count(),
        iocs_total=scoped_query(db, IOC, current_user).filter(IOC.is_active.is_(True)).count(),
        iocs_malicious=scoped_query(db, IOC, current_user)
        .filter(IOC.is_active.is_(True), IOC.reputation == "malicious")
        .count(),
        attack_paths_total=scoped_query(db, IAMAttackPath, current_user).count(),
        attack_paths_with_escalation=scoped_query(db, IAMAttackPath, current_user)
        .filter(IAMAttackPath.privilege_escalation_detected.is_(True))
        .count(),
        alert_timeseries=timeseries,
        top_hosts=[TopEntity(name=n, count=c) for n, c in top_hosts.most_common(5)],
        top_users=[TopEntity(name=n, count=c) for n, c in top_users.most_common(5)],
        top_rules=[TopEntity(name=r, count=c) for r, c in rule_counts],
    )
