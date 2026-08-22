"""
SOC dashboard aggregation (Phase 12).

This file exists because the aggregation endpoint shipped without one and
immediately broke in the live smoke test: `top_rules` grouped on
`Detection.rule_id`, which is a **UUID foreign key**, not the
human-readable identifier of the same name on `DetectionRule`. The
response model rejected the UUID and the whole overview 500'd.

`test_top_rules_returns_rule_names_not_uuids` is the regression guard,
and it is deliberately the first behavioural test in the file.
"""
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.db.session import SessionLocal
from app.lab.scenarios import SCENARIOS_BY_ID
from app.models.incident import Incident
from app.services.lab import run_scenario
from tests.factories import auth_headers, create_organization, create_user


@pytest.fixture()
def populated(client):
    """An organization with real telemetry, detections and alerts behind it."""
    org = create_organization()
    admin, pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, pw)

    db = SessionLocal()
    try:
        run_scenario(db, SCENARIOS_BY_ID["encoded_powershell_c2"], organization_id=org.id)
        run_scenario(db, SCENARIOS_BY_ID["ssh_brute_force"], organization_id=org.id)
    finally:
        db.close()
    return org, admin, headers


def _overview(client, headers, **params):
    resp = client.get("/api/v1/dashboard/overview", headers=headers, params=params)
    assert resp.status_code == 200, resp.text
    return resp.json()


# --------------------------------------------------------------------------
# The regression that motivated this file
# --------------------------------------------------------------------------


def test_top_rules_returns_rule_names_not_uuids(client, populated):
    _, _, headers = populated
    body = _overview(client, headers)

    assert body["top_rules"], "scenarios fired detections, so this must not be empty"
    for entry in body["top_rules"]:
        assert not _looks_like_uuid(entry["name"]), f"{entry['name']} is a UUID, not a rule id"
        assert entry["name"].startswith(("sigma_", "custom_")), entry["name"]
        assert entry["count"] >= 1


def _looks_like_uuid(value: str) -> bool:
    try:
        uuid.UUID(value)
        return True
    except (ValueError, AttributeError, TypeError):
        return False


# --------------------------------------------------------------------------
# Counts
# --------------------------------------------------------------------------


def test_overview_counts_reflect_real_rows(client, populated):
    _, _, headers = populated
    body = _overview(client, headers)

    assert body["events_total"] > 0
    assert body["alerts_total"] > 0
    assert body["alerts_open"] <= body["alerts_total"]
    assert sum(body["alerts_by_severity"].values()) == body["alerts_total"]

    listed = client.get("/api/v1/alerts", headers=headers, params={"limit": 500}).json()
    assert body["alerts_total"] == len(listed), "the aggregate must match a full listing"


def test_counts_are_not_capped_by_a_page_size(client):
    """
    The reason this endpoint exists: counting client-side over a paginated
    list would silently report the page size as the total.
    """
    org = create_organization()
    admin, pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, pw)

    db = SessionLocal()
    try:
        # Two scenarios produce well over 50 events between them.
        run_scenario(db, SCENARIOS_BY_ID["ssh_brute_force"], organization_id=org.id)
        run_scenario(db, SCENARIOS_BY_ID["lateral_movement"], organization_id=org.id)
    finally:
        db.close()

    body = _overview(client, headers)
    assert body["events_total"] > 20
    assert body["events_total"] % 50 != 0 or body["events_total"] > 50


def test_window_narrows_the_in_window_counts(client, populated):
    _, _, headers = populated
    wide = _overview(client, headers, window_hours=720)
    assert wide["events_in_window"] <= wide["events_total"]
    assert wide["alerts_in_window"] <= wide["alerts_total"]


def test_window_bounds_are_enforced(client, populated):
    _, _, headers = populated
    assert client.get("/api/v1/dashboard/overview", headers=headers, params={"window_hours": 0}).status_code == 422
    assert client.get("/api/v1/dashboard/overview", headers=headers, params={"window_hours": 99999}).status_code == 422


# --------------------------------------------------------------------------
# The null-is-not-zero rule
# --------------------------------------------------------------------------


def test_mean_times_are_null_not_zero_when_nothing_closed(client, populated):
    """
    The single most important rendering property of this endpoint. A
    dashboard showing "0s mean time to contain" because nothing was
    contained reads as flawless performance.
    """
    _, _, headers = populated
    body = _overview(client, headers)

    assert body["incidents_closed_in_window"] == 0
    assert body["mean_time_to_triage_seconds"] is None
    assert body["mean_time_to_contain_seconds"] is None
    assert body["mean_time_to_close_seconds"] is None


def test_mean_times_are_computed_once_a_case_closes(client, populated):
    org, _, headers = populated

    incident = client.post(
        "/api/v1/incidents", headers=headers, json={"title": "Metrics case", "severity": "HIGH"}
    ).json()
    iid = incident["id"]

    # Backdate detection so the durations are measurable rather than 0.
    db = SessionLocal()
    try:
        row = db.query(Incident).filter(Incident.id == uuid.UUID(iid)).one()
        row.detected_at = datetime.now(timezone.utc) - timedelta(minutes=30)
        db.add(row)
        db.commit()
    finally:
        db.close()

    client.patch(f"/api/v1/incidents/{iid}/status", headers=headers, json={"status": "triaged"})
    client.patch(f"/api/v1/incidents/{iid}/status", headers=headers, json={"status": "contained"})
    client.patch(
        f"/api/v1/incidents/{iid}/status",
        headers=headers,
        json={"status": "closed", "closure_classification": "true_positive"},
    )

    body = _overview(client, headers)
    assert body["incidents_closed_in_window"] == 1
    assert body["mean_time_to_triage_seconds"] >= 30 * 60
    assert body["mean_time_to_contain_seconds"] >= 30 * 60
    assert body["mean_time_to_close_seconds"] >= 30 * 60


def test_negative_durations_are_never_reported(client, populated):
    """
    Detection can move backwards when older evidence is linked later; the
    aggregate must not surface a negative mean.
    """
    org, _, headers = populated
    incident = client.post(
        "/api/v1/incidents", headers=headers, json={"title": "Backwards", "severity": "LOW"}
    ).json()
    iid = incident["id"]
    client.patch(f"/api/v1/incidents/{iid}/status", headers=headers, json={"status": "triaged"})

    db = SessionLocal()
    try:
        row = db.query(Incident).filter(Incident.id == uuid.UUID(iid)).one()
        row.detected_at = datetime.now(timezone.utc) + timedelta(hours=2)  # in the future
        db.add(row)
        db.commit()
    finally:
        db.close()

    client.patch(
        f"/api/v1/incidents/{iid}/status",
        headers=headers,
        json={"status": "closed", "closure_classification": "duplicate"},
    )
    body = _overview(client, headers)
    for key in ("mean_time_to_triage_seconds", "mean_time_to_contain_seconds", "mean_time_to_close_seconds"):
        assert body[key] is None or body[key] >= 0, key


# --------------------------------------------------------------------------
# Cross-phase panels
# --------------------------------------------------------------------------


def test_cloud_and_threat_intel_panels_populate(client):
    org = create_organization()
    admin, pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, pw)

    db = SessionLocal()
    try:
        run_scenario(db, SCENARIOS_BY_ID["cloud_privilege_escalation"], organization_id=org.id)
    finally:
        db.close()

    client.post("/api/v1/threat-intel/lookup", headers=headers, json={"ioc_type": "ip", "value": "203.0.113.7"})
    client.post(
        "/api/v1/cloud/attack-paths",
        headers=headers,
        json={"account_id": "999988887777", "seed_identity": "sim-dev-alice", "window_hours": 24},
    )

    body = _overview(client, headers)
    assert body["iocs_total"] >= 1
    assert body["iocs_malicious"] >= 1
    assert body["attack_paths_total"] >= 1
    assert body["attack_paths_with_escalation"] >= 1


def test_pending_approvals_are_surfaced(client, populated):
    _, _, headers = populated
    client.post(
        "/api/v1/response/actions",
        headers=headers,
        json={"action_type": "isolate_host", "target": "SIM-WKS-01", "justification": "test"},
    )
    assert _overview(client, headers)["pending_approvals"] == 1


def test_timeseries_buckets_are_hourly_and_ordered(client, populated):
    _, _, headers = populated
    body = _overview(client, headers, window_hours=720)
    buckets = [p["bucket"] for p in body["alert_timeseries"]]
    assert buckets == sorted(buckets)
    for bucket in buckets:
        parsed = datetime.fromisoformat(bucket)
        assert parsed.minute == 0 and parsed.second == 0


def test_top_hosts_and_users_are_populated(client, populated):
    _, _, headers = populated
    body = _overview(client, headers)
    assert body["top_hosts"], "the scenarios name hosts"
    assert all(isinstance(h["name"], str) and h["count"] >= 1 for h in body["top_hosts"])


# --------------------------------------------------------------------------
# Tenancy + RBAC
# --------------------------------------------------------------------------


def test_the_overview_is_tenant_scoped(client, populated):
    """A second organization must see zeroes, not the first one's totals."""
    _, _, _ = populated
    other_org = create_organization()
    other_user, pw = create_user(other_org, role_name="admin", is_superuser=True)
    other_headers = auth_headers(client, other_user.email, pw)

    body = _overview(client, other_headers)
    assert body["events_total"] == 0
    assert body["alerts_total"] == 0
    assert body["incidents_total"] == 0
    assert body["top_rules"] == []
    assert body["top_hosts"] == []


@pytest.mark.parametrize("role", ["viewer", "threat_hunter", "soc_analyst", "soc_manager", "admin"])
def test_every_role_that_can_read_alerts_can_read_the_overview(client, role):
    org = create_organization()
    user, pw = create_user(org, role_name=role)
    headers = auth_headers(client, user.email, pw)
    assert client.get("/api/v1/dashboard/overview", headers=headers).status_code == 200


def test_unauthenticated_access_is_rejected(client):
    assert client.get("/api/v1/dashboard/overview").status_code == 401


def test_the_payload_contains_only_counts_never_row_contents(client, populated):
    """
    The endpoint is gated on the narrowest permission, which is only safe
    because it cannot leak anything the caller could not already list.
    """
    _, _, headers = populated
    body = _overview(client, headers)

    scalar_or_shallow = {
        "generated_at", "window_hours", "events_total", "events_in_window", "alerts_total", "alerts_open",
        "alerts_in_window", "alerts_by_severity", "incidents_total", "incidents_open", "incidents_by_status",
        "incidents_closed_in_window", "mean_time_to_triage_seconds", "mean_time_to_contain_seconds",
        "mean_time_to_close_seconds", "pending_approvals", "ai_investigations_total",
        "ai_investigations_in_window", "iocs_total", "iocs_malicious", "attack_paths_total",
        "attack_paths_with_escalation", "alert_timeseries", "top_hosts", "top_users", "top_rules",
    }
    assert set(body) == scalar_or_shallow, set(body) ^ scalar_or_shallow

    # No alert titles, no event payloads, no user emails.
    serialized = str(body)
    assert "raw_event" not in serialized
    assert "@example.com" not in serialized
