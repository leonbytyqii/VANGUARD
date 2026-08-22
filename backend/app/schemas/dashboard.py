"""SOC overview aggregation contract (Phase 12)."""
from datetime import datetime

from pydantic import BaseModel, Field


class SeverityBreakdown(BaseModel):
    info: int = 0
    low: int = 0
    medium: int = 0
    high: int = 0
    critical: int = 0


class TimeseriesPoint(BaseModel):
    bucket: str  # ISO-8601 hour
    count: int


class TopEntity(BaseModel):
    name: str
    count: int


class DashboardOverview(BaseModel):
    """
    Every mean-time metric is `None`, never `0`, when no incident closed
    in the window. A dashboard that renders "0s mean time to contain"
    because nothing happened is actively misleading — it reads as
    perfect performance.
    """

    generated_at: datetime
    window_hours: int

    events_total: int
    events_in_window: int

    alerts_total: int
    alerts_open: int
    alerts_in_window: int
    alerts_by_severity: SeverityBreakdown

    incidents_total: int
    incidents_open: int
    incidents_by_status: dict[str, int] = Field(default_factory=dict)
    incidents_closed_in_window: int

    mean_time_to_triage_seconds: int | None
    mean_time_to_contain_seconds: int | None
    mean_time_to_close_seconds: int | None

    pending_approvals: int

    ai_investigations_total: int
    ai_investigations_in_window: int

    iocs_total: int
    iocs_malicious: int

    attack_paths_total: int
    attack_paths_with_escalation: int

    alert_timeseries: list[TimeseriesPoint] = Field(default_factory=list)
    top_hosts: list[TopEntity] = Field(default_factory=list)
    top_users: list[TopEntity] = Field(default_factory=list)
    top_rules: list[TopEntity] = Field(default_factory=list)
