"""
Incident response (Phase 9): the lifecycle state machine, alert->incident
promotion and ATT&CK derivation, the seeded NIST SP 800-61r2 checklist,
notes with honest AI provenance, the forge-proof timeline, IR metrics,
response-action mirroring, the `check_related_incidents` agent tool, and
RBAC / tenant-isolation coverage on every new route.
"""
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.ai.agents.permissions import ToolPermissionError, invoke_agent_tool
from app.ai.tools.registry import TOOL_REGISTRY
from app.db.session import SessionLocal
from app.incidents.task_templates import DEFAULT_IR_CHECKLIST
from app.models.alert import Alert
from app.models.automation import ResponseAction
from app.models.enums import ActionEffect, AgentType, IncidentTaskCategory
from app.models.incident import Incident, IncidentEvent
from app.services.incidents import INCIDENT_TRANSITIONS, max_severity
from tests.factories import auth_headers, create_organization, create_user

_BASE_TIME = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _make_alert(
    org_id,
    *,
    title="Suspicious activity",
    severity="HIGH",
    risk_score=80,
    host_name="IR-HOST-01",
    user="alice",
    minutes_ago=60,
) -> Alert:
    db = SessionLocal()
    try:
        alert = Alert(
            organization_id=org_id,
            title=title,
            description="Created directly for incident-response tests.",
            severity=severity,
            risk_score=risk_score,
            status="new",
            source="manual_test",
            host_name=host_name,
            user=user,
            alert_timestamp=datetime.now(timezone.utc) - timedelta(minutes=minutes_ago),
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        return alert
    finally:
        db.close()


def _tag_alert_with_technique(alert_id, technique_id: str) -> None:
    from app.models.mitre import MitreTechnique

    db = SessionLocal()
    try:
        alert = db.query(Alert).filter(Alert.id == alert_id).one()
        technique = db.query(MitreTechnique).filter(MitreTechnique.technique_id == technique_id).one()
        alert.mitre_techniques.append(technique)
        db.add(alert)
        db.commit()
    finally:
        db.close()


def _create_incident(client, headers, **body):
    payload = {"title": "Test incident", "severity": "MEDIUM"}
    payload.update(body)
    resp = client.post("/api/v1/incidents", headers=headers, json=payload)
    assert resp.status_code == 201, resp.text
    return resp.json()


def _set_status(client, headers, incident_id, status, **extra):
    return client.patch(
        f"/api/v1/incidents/{incident_id}/status", headers=headers, json={"status": status, **extra}
    )


def _timeline(client, headers, incident_id, **params):
    resp = client.get(f"/api/v1/incidents/{incident_id}/timeline", headers=headers, params=params)
    assert resp.status_code == 200, resp.text
    return resp.json()


@pytest.fixture()
def manager_ctx(client):
    """A SOC-manager session: holds incidents.* including assign, plus response.approve."""
    org = create_organization()
    user, pw = create_user(org, role_name="soc_manager")
    return org, user, auth_headers(client, user.email, pw)


# --------------------------------------------------------------------------
# Pure / data-integrity invariants
# --------------------------------------------------------------------------


def test_transition_graph_only_references_real_statuses():
    from app.models.enums import IncidentStatus

    valid = {s.value for s in IncidentStatus}
    assert set(INCIDENT_TRANSITIONS) == valid, "every status must have an explicit outgoing edge set"
    for source, targets in INCIDENT_TRANSITIONS.items():
        assert targets <= valid, f"{source} has an edge to an unknown status"
        assert source not in targets, f"{source} should not list itself as a transition"


def test_closed_is_reachable_from_every_non_closed_status():
    for source, targets in INCIDENT_TRANSITIONS.items():
        if source == "closed":
            continue
        assert "closed" in targets, f"a case in '{source}' must always be closable"


def test_reopen_is_the_only_edge_out_of_closed():
    assert INCIDENT_TRANSITIONS["closed"] == frozenset({"investigating"})


def test_default_checklist_covers_every_task_category_except_preparation():
    categories = {t.category for t in DEFAULT_IR_CHECKLIST}
    assert categories == set(IncidentTaskCategory)


def test_default_checklist_titles_are_unique():
    titles = [t.title for t in DEFAULT_IR_CHECKLIST]
    assert len(titles) == len(set(titles))


def test_max_severity_picks_the_highest_not_the_last():
    assert max_severity(["LOW", "CRITICAL", "MEDIUM"]) == "CRITICAL"
    assert max_severity(["INFO", "LOW"]) == "LOW"
    assert max_severity([]) == "MEDIUM"
    assert max_severity(["not-a-severity"]) == "MEDIUM"


# --------------------------------------------------------------------------
# Creation, case numbering, checklist seeding
# --------------------------------------------------------------------------


def test_create_incident_seeds_checklist_and_allocates_a_case_number(client, manager_ctx):
    _, _, headers = manager_ctx
    incident = _create_incident(client, headers, title="Ransomware on finance share")

    assert incident["incident_number"] == 1, "first case in a fresh organization"
    assert incident["reference"] == "INC-000001"
    assert incident["status"] == "new"
    assert incident["detected_at"] is not None

    tasks = client.get(f"/api/v1/incidents/{incident['id']}/tasks", headers=headers).json()
    assert len(tasks) == len(DEFAULT_IR_CHECKLIST)
    assert all(t["is_from_template"] for t in tasks)
    assert [t["sort_order"] for t in tasks] == sorted(t["sort_order"] for t in tasks)
    assert not any(t["done"] for t in tasks)


def test_case_numbers_are_sequential_within_and_independent_across_tenants(client):
    org_a = create_organization()
    user_a, pw_a = create_user(org_a, role_name="soc_manager")
    headers_a = auth_headers(client, user_a.email, pw_a)

    org_b = create_organization()
    user_b, pw_b = create_user(org_b, role_name="soc_manager")
    headers_b = auth_headers(client, user_b.email, pw_b)

    first_a = _create_incident(client, headers_a, title="A1")
    second_a = _create_incident(client, headers_a, title="A2")
    first_b = _create_incident(client, headers_b, title="B1")

    assert [first_a["incident_number"], second_a["incident_number"]] == [1, 2]
    # Tenant B starts at 1 too — a global counter would leak A's case volume.
    assert first_b["incident_number"] == 1


def test_create_without_severity_or_alerts_is_rejected(client, manager_ctx):
    _, _, headers = manager_ctx
    resp = client.post("/api/v1/incidents", headers=headers, json={"title": "No severity"})
    assert resp.status_code == 422
    assert "severity is required" in resp.json()["detail"]


def test_seed_checklist_can_be_opted_out(client, manager_ctx):
    _, _, headers = manager_ctx
    incident = _create_incident(client, headers, seed_checklist=False)
    tasks = client.get(f"/api/v1/incidents/{incident['id']}/tasks", headers=headers).json()
    assert tasks == []


# --------------------------------------------------------------------------
# Alert promotion
# --------------------------------------------------------------------------


def test_creating_from_alerts_derives_severity_mitre_tags_and_detected_at(client, manager_ctx):
    org, _, headers = manager_ctx
    low = _make_alert(org.id, title="Low signal", severity="LOW", risk_score=20, minutes_ago=30)
    high = _make_alert(org.id, title="High signal", severity="CRITICAL", risk_score=95, minutes_ago=120)
    _tag_alert_with_technique(high.id, "T1059.001")

    incident = _create_incident(
        client, headers, title="Correlated intrusion", severity=None, alert_ids=[str(low.id), str(high.id)]
    )

    assert incident["severity"] == "CRITICAL", "derived from the highest linked alert"
    assert set(incident["alert_ids"]) == {str(low.id), str(high.id)}
    assert "T1059.001" in incident["mitre_technique_ids"]
    # detected_at comes from the *earliest evidence*, not from case creation.
    detected = datetime.fromisoformat(incident["detected_at"])
    assert detected < datetime.now(timezone.utc) - timedelta(minutes=90)


def test_linking_an_alert_does_not_silently_override_analyst_severity(client, manager_ctx):
    org, _, headers = manager_ctx
    incident = _create_incident(client, headers, severity="LOW")
    critical = _make_alert(org.id, severity="CRITICAL", risk_score=99)

    resp = client.post(
        f"/api/v1/incidents/{incident['id']}/alerts", headers=headers, json={"alert_ids": [str(critical.id)]}
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["severity"] == "LOW", "an analyst's deliberate severity is not overwritten"

    # ...but the escalation is made visible on the timeline instead of being lost.
    entries = _timeline(client, headers, incident["id"], kind="alert_linked")
    assert entries[-1]["details"]["exceeds_incident_severity"] is True


def test_unlinking_an_alert_recomputes_mitre_tags(client, manager_ctx):
    org, _, headers = manager_ctx
    alert = _make_alert(org.id)
    _tag_alert_with_technique(alert.id, "T1059.001")
    incident = _create_incident(client, headers, severity=None, alert_ids=[str(alert.id)])
    assert incident["mitre_technique_ids"] == ["T1059.001"]

    resp = client.delete(f"/api/v1/incidents/{incident['id']}/alerts/{alert.id}", headers=headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["mitre_technique_ids"] == [], "a technique only that alert contributed is removed"
    assert resp.json()["alert_ids"] == []


def test_linking_the_same_alert_twice_is_idempotent(client, manager_ctx):
    org, _, headers = manager_ctx
    alert = _make_alert(org.id)
    incident = _create_incident(client, headers, severity=None, alert_ids=[str(alert.id)])

    resp = client.post(
        f"/api/v1/incidents/{incident['id']}/alerts", headers=headers, json={"alert_ids": [str(alert.id)]}
    )
    assert resp.status_code == 200
    assert resp.json()["alert_ids"] == [str(alert.id)]
    assert len(_timeline(client, headers, incident["id"], kind="alert_linked")) == 1


def test_cannot_link_an_alert_belonging_to_another_tenant(client, manager_ctx):
    _, _, headers = manager_ctx
    other_org = create_organization()
    foreign_alert = _make_alert(other_org.id, title="Someone else's alert")

    incident = _create_incident(client, headers)
    resp = client.post(
        f"/api/v1/incidents/{incident['id']}/alerts",
        headers=headers,
        json={"alert_ids": [str(foreign_alert.id)]},
    )
    assert resp.status_code == 422
    # Reported as unknown, not forbidden — confirming it exists elsewhere
    # would itself be the cross-tenant leak.
    assert "Unknown alert id" in resp.json()["detail"]

    assert client.get(f"/api/v1/incidents/{incident['id']}", headers=headers).json()["alert_ids"] == []


def test_cannot_create_an_incident_from_another_tenants_alert(client, manager_ctx):
    _, _, headers = manager_ctx
    other_org = create_organization()
    foreign_alert = _make_alert(other_org.id)

    resp = client.post(
        "/api/v1/incidents",
        headers=headers,
        json={"title": "IDOR attempt", "alert_ids": [str(foreign_alert.id)]},
    )
    assert resp.status_code == 422


# --------------------------------------------------------------------------
# Lifecycle state machine
# --------------------------------------------------------------------------


def test_full_lifecycle_walk_stamps_each_milestone_once(client, manager_ctx):
    _, _, headers = manager_ctx
    incident = _create_incident(client, headers)
    iid = incident["id"]

    assert _set_status(client, headers, iid, "triaged").status_code == 200
    assert _set_status(client, headers, iid, "investigating").status_code == 200
    contained = _set_status(client, headers, iid, "contained")
    assert contained.status_code == 200
    first_contained_at = contained.json()["contained_at"]
    assert first_contained_at is not None

    # A regression back to investigating and forward again must NOT reset
    # time-to-first-containment.
    assert _set_status(client, headers, iid, "investigating").status_code == 200
    again = _set_status(client, headers, iid, "contained")
    assert again.status_code == 200
    assert again.json()["contained_at"] == first_contained_at

    assert _set_status(client, headers, iid, "eradicated").status_code == 200
    assert _set_status(client, headers, iid, "recovered").status_code == 200
    closed = _set_status(client, headers, iid, "closed", closure_classification="true_positive")
    assert closed.status_code == 200
    body = closed.json()
    assert body["status"] == "closed"
    assert body["closure_classification"] == "true_positive"
    assert body["closed_at"] is not None


def test_illegal_transition_is_rejected_with_409(client, manager_ctx):
    _, _, headers = manager_ctx
    incident = _create_incident(client, headers)
    resp = _set_status(client, headers, incident["id"], "contained")
    assert resp.status_code == 409
    detail = resp.json()["detail"]
    assert "Illegal transition 'new' -> 'contained'" in detail
    assert "triaged" in detail, "the error should name what IS allowed"


def test_transition_to_the_same_status_is_rejected(client, manager_ctx):
    _, _, headers = manager_ctx
    incident = _create_incident(client, headers)
    resp = _set_status(client, headers, incident["id"], "new")
    assert resp.status_code == 409


def test_closing_requires_a_classification(client, manager_ctx):
    _, _, headers = manager_ctx
    incident = _create_incident(client, headers)
    resp = _set_status(client, headers, incident["id"], "closed")
    assert resp.status_code == 422
    assert "closure_classification is required" in resp.json()["detail"]
    assert client.get(f"/api/v1/incidents/{incident['id']}", headers=headers).json()["status"] == "new"


def test_unknown_closure_classification_is_rejected_by_the_schema(client, manager_ctx):
    _, _, headers = manager_ctx
    incident = _create_incident(client, headers)
    resp = _set_status(client, headers, incident["id"], "closed", closure_classification="probably_fine")
    assert resp.status_code == 422


def test_skipping_straight_to_investigating_still_records_triage(client, manager_ctx):
    _, _, headers = manager_ctx
    incident = _create_incident(client, headers)
    resp = _set_status(client, headers, incident["id"], "investigating")
    assert resp.status_code == 200
    assert resp.json()["triaged_at"] is not None, "an analyst who went straight in has still triaged it"


def test_assigning_a_new_incident_triages_it(client, manager_ctx):
    org, user, headers = manager_ctx
    incident = _create_incident(client, headers)
    resp = client.patch(
        f"/api/v1/incidents/{incident['id']}/assign", headers=headers, json={"assigned_to_id": str(user.id)}
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "triaged"
    assert body["assigned_to_id"] == str(user.id)
    assert body["triaged_at"] is not None


def test_cannot_assign_to_a_user_from_another_organization(client, manager_ctx):
    _, _, headers = manager_ctx
    other_org = create_organization()
    outsider, _ = create_user(other_org, role_name="soc_analyst")

    incident = _create_incident(client, headers)
    resp = client.patch(
        f"/api/v1/incidents/{incident['id']}/assign",
        headers=headers,
        json={"assigned_to_id": str(outsider.id)},
    )
    assert resp.status_code == 422


# --------------------------------------------------------------------------
# Reopen authorization
# --------------------------------------------------------------------------


def test_analyst_can_close_but_cannot_reopen(client):
    org = create_organization()
    analyst, analyst_pw = create_user(org, role_name="soc_analyst")
    analyst_headers = auth_headers(client, analyst.email, analyst_pw)
    manager, manager_pw = create_user(org, role_name="soc_manager")
    manager_headers = auth_headers(client, manager.email, manager_pw)

    incident = _create_incident(client, analyst_headers)
    iid = incident["id"]

    closed = _set_status(client, analyst_headers, iid, "closed", closure_classification="false_positive")
    assert closed.status_code == 200, "closing a case is line-analyst work"

    denied = _set_status(client, analyst_headers, iid, "investigating")
    assert denied.status_code == 403
    assert "incidents.assign" in denied.json()["detail"]

    # The manager can, and reopening clears the verdict while preserving
    # it on the timeline.
    reopened = _set_status(client, manager_headers, iid, "investigating")
    assert reopened.status_code == 200, reopened.text
    assert reopened.json()["status"] == "investigating"
    assert reopened.json()["closure_classification"] is None
    assert reopened.json()["closed_at"] is None

    entries = _timeline(client, manager_headers, iid, kind="status_change")
    reopen_entry = entries[-1]
    assert reopen_entry["details"]["reopened_from_classification"] == "false_positive"


# --------------------------------------------------------------------------
# Notes
# --------------------------------------------------------------------------


def test_notes_round_trip_and_are_never_flagged_ai_generated_via_the_api(client, manager_ctx):
    _, user, headers = manager_ctx
    incident = _create_incident(client, headers)

    resp = client.post(
        f"/api/v1/incidents/{incident['id']}/notes",
        headers=headers,
        # A caller attempting to forge AI provenance: the field is not on
        # the request schema, so it is ignored rather than honoured.
        json={"body": "Confirmed beaconing to 203.0.113.7.", "is_ai_generated": True},
    )
    assert resp.status_code == 201, resp.text
    note = resp.json()
    assert note["is_ai_generated"] is False, "no HTTP caller can author an AI-attributed note"
    assert note["author_id"] == str(user.id)

    notes = client.get(f"/api/v1/incidents/{incident['id']}/notes", headers=headers).json()
    assert len(notes) == 1
    assert notes[0]["body"] == "Confirmed beaconing to 203.0.113.7."


def test_empty_note_is_rejected(client, manager_ctx):
    _, _, headers = manager_ctx
    incident = _create_incident(client, headers)
    resp = client.post(f"/api/v1/incidents/{incident['id']}/notes", headers=headers, json={"body": ""})
    assert resp.status_code == 422


# --------------------------------------------------------------------------
# Tasks
# --------------------------------------------------------------------------


def test_task_create_complete_and_reopen_tracks_attribution(client, manager_ctx):
    _, user, headers = manager_ctx
    incident = _create_incident(client, headers)
    iid = incident["id"]

    created = client.post(
        f"/api/v1/incidents/{iid}/tasks",
        headers=headers,
        json={"title": "Pull EDR triage package", "category": "containment"},
    )
    assert created.status_code == 201, created.text
    task = created.json()
    assert task["is_from_template"] is False
    # Slotted after the seeded checklist rather than colliding with it.
    assert task["sort_order"] > len(DEFAULT_IR_CHECKLIST) * 10
    assert task["completed_at"] is None

    done = client.patch(
        f"/api/v1/incidents/{iid}/tasks/{task['id']}", headers=headers, json={"done": True}
    )
    assert done.status_code == 200, done.text
    assert done.json()["done"] is True
    assert done.json()["completed_at"] is not None
    assert done.json()["completed_by_id"] == str(user.id)

    undone = client.patch(
        f"/api/v1/incidents/{iid}/tasks/{task['id']}", headers=headers, json={"done": False}
    )
    assert undone.status_code == 200
    assert undone.json()["completed_at"] is None, "un-ticking must not leave a stale completion record"
    assert undone.json()["completed_by_id"] is None


def test_task_delete_removes_it_and_records_the_removal(client, manager_ctx):
    _, _, headers = manager_ctx
    incident = _create_incident(client, headers)
    iid = incident["id"]
    task = client.post(
        f"/api/v1/incidents/{iid}/tasks", headers=headers, json={"title": "Temporary task"}
    ).json()

    resp = client.delete(f"/api/v1/incidents/{iid}/tasks/{task['id']}", headers=headers)
    assert resp.status_code == 204

    remaining = client.get(f"/api/v1/incidents/{iid}/tasks", headers=headers).json()
    assert task["id"] not in [t["id"] for t in remaining]

    deletions = [e for e in _timeline(client, headers, iid, kind="task") if e["details"].get("action") == "task_deleted"]
    assert len(deletions) == 1


def test_unknown_task_category_is_rejected(client, manager_ctx):
    _, _, headers = manager_ctx
    incident = _create_incident(client, headers)
    resp = client.post(
        f"/api/v1/incidents/{incident['id']}/tasks",
        headers=headers,
        json={"title": "Bad category", "category": "hand_wringing"},
    )
    assert resp.status_code == 422


def test_a_task_from_another_incident_cannot_be_reached_through_this_one(client, manager_ctx):
    _, _, headers = manager_ctx
    first = _create_incident(client, headers, title="First")
    second = _create_incident(client, headers, title="Second")

    other_task = client.get(f"/api/v1/incidents/{second['id']}/tasks", headers=headers).json()[0]
    resp = client.patch(
        f"/api/v1/incidents/{first['id']}/tasks/{other_task['id']}", headers=headers, json={"done": True}
    )
    assert resp.status_code == 404


# --------------------------------------------------------------------------
# Timeline
# --------------------------------------------------------------------------


def test_timeline_records_the_whole_case_history_in_order(client, manager_ctx):
    org, user, headers = manager_ctx
    alert = _make_alert(org.id)
    incident = _create_incident(client, headers, severity=None, alert_ids=[str(alert.id)])
    iid = incident["id"]

    client.patch(f"/api/v1/incidents/{iid}/assign", headers=headers, json={"assigned_to_id": str(user.id)})
    client.post(f"/api/v1/incidents/{iid}/notes", headers=headers, json={"body": "Scoping under way."})
    _set_status(client, headers, iid, "investigating")

    entries = _timeline(client, headers, iid)
    kinds = [e["kind"] for e in entries]
    assert kinds[0] == "created"
    for expected in ("task", "alert_linked", "assignment", "note", "status_change"):
        assert expected in kinds, f"missing {expected} entry"

    timestamps = [e["event_timestamp"] for e in entries]
    assert timestamps == sorted(timestamps)
    assert any(e["actor"] == user.email for e in entries)


def test_timeline_is_read_only_over_http(client, manager_ctx):
    """
    The case file's integrity rests on there being no write route at all —
    not on a permission check that a later refactor could relax.
    """
    _, _, headers = manager_ctx
    incident = _create_incident(client, headers)
    url = f"/api/v1/incidents/{incident['id']}/timeline"

    forged = {"kind": "status_change", "actor": "attacker@evil.test"}
    for method in ("POST", "PATCH", "PUT", "DELETE"):
        resp = client.request(method, url, headers=headers, json=forged)
        assert resp.status_code == 405, f"{method} {url} should not exist"

    # And the case file is unchanged by the attempt.
    assert all(e["actor"] != "attacker@evil.test" for e in _timeline(client, headers, incident["id"]))


def test_platform_generated_timeline_entries_have_no_actor(client, manager_ctx):
    _, _, headers = manager_ctx
    incident = _create_incident(client, headers)
    seeded = [
        e
        for e in _timeline(client, headers, incident["id"], kind="task")
        if e["details"].get("action") == "checklist_seeded"
    ]
    assert len(seeded) == 1
    assert seeded[0]["actor"] is None, "the checklist is not somebody's action"
    assert seeded[0]["details"]["template"] == "nist_sp_800_61r2"


# --------------------------------------------------------------------------
# Metrics
# --------------------------------------------------------------------------


def test_metrics_are_null_until_the_milestone_is_reached_then_measured_from_detection(client, manager_ctx):
    org, _, headers = manager_ctx
    alert = _make_alert(org.id, minutes_ago=45)
    incident = _create_incident(client, headers, severity=None, alert_ids=[str(alert.id)])
    iid = incident["id"]

    metrics = client.get(f"/api/v1/incidents/{iid}/metrics", headers=headers).json()
    assert metrics["time_to_triage_seconds"] is None, "not triaged yet — null, not zero"
    assert metrics["time_to_contain_seconds"] is None
    assert metrics["is_open"] is True
    assert metrics["tasks_total"] == len(DEFAULT_IR_CHECKLIST)
    assert metrics["tasks_completed"] == 0
    assert metrics["alert_count"] == 1
    # Measured from the alert's own timestamp (45 min ago), not case creation.
    assert metrics["open_duration_seconds"] >= 45 * 60

    _set_status(client, headers, iid, "triaged")
    metrics = client.get(f"/api/v1/incidents/{iid}/metrics", headers=headers).json()
    assert metrics["time_to_triage_seconds"] >= 45 * 60

    _set_status(client, headers, iid, "closed", closure_classification="true_positive")
    metrics = client.get(f"/api/v1/incidents/{iid}/metrics", headers=headers).json()
    assert metrics["is_open"] is False
    assert metrics["time_to_close_seconds"] >= 45 * 60


def test_metrics_never_report_a_negative_duration(client, manager_ctx):
    """
    Linking an alert whose evidence predates an already-recorded triage
    moves detected_at backwards after the fact. That is legitimate, but a
    negative time-to-triage is not a number any dashboard should render.
    """
    org, _, headers = manager_ctx
    incident = _create_incident(client, headers)
    iid = incident["id"]
    _set_status(client, headers, iid, "triaged")

    future_alert = _make_alert(org.id, minutes_ago=-120)  # timestamped in the future
    client.post(f"/api/v1/incidents/{iid}/alerts", headers=headers, json={"alert_ids": [str(future_alert.id)]})

    metrics = client.get(f"/api/v1/incidents/{iid}/metrics", headers=headers).json()
    assert metrics["time_to_triage_seconds"] >= 0


def test_completed_tasks_are_counted(client, manager_ctx):
    _, _, headers = manager_ctx
    incident = _create_incident(client, headers)
    iid = incident["id"]
    tasks = client.get(f"/api/v1/incidents/{iid}/tasks", headers=headers).json()
    client.patch(f"/api/v1/incidents/{iid}/tasks/{tasks[0]['id']}", headers=headers, json={"done": True})

    metrics = client.get(f"/api/v1/incidents/{iid}/metrics", headers=headers).json()
    assert metrics["tasks_completed"] == 1
    assert metrics["tasks_total"] == len(DEFAULT_IR_CHECKLIST)


# --------------------------------------------------------------------------
# Response actions on a case
# --------------------------------------------------------------------------


def test_response_action_lifecycle_is_mirrored_onto_the_incident_timeline(client, manager_ctx):
    _, _, headers = manager_ctx
    incident = _create_incident(client, headers, severity="CRITICAL")
    iid = incident["id"]

    created = client.post(
        "/api/v1/response/actions",
        headers=headers,
        json={
            "action_type": "isolate_host",
            "target": "IR-HOST-01",
            "justification": "Confirmed hands-on-keyboard activity.",
            "incident_id": iid,
        },
    )
    assert created.status_code == 201, created.text
    action = created.json()
    assert action["status"] == "pending"

    listed = client.get(f"/api/v1/incidents/{iid}/response-actions", headers=headers)
    assert listed.status_code == 200
    assert [a["id"] for a in listed.json()] == [action["id"]]

    client.patch(f"/api/v1/response/actions/{action['id']}/approve", headers=headers)
    client.post(f"/api/v1/response/actions/{action['id']}/execute", headers=headers)

    phases = [
        e["details"]["phase"] for e in _timeline(client, headers, iid, kind="response_action")
    ]
    assert phases == ["requested", "approved", "executed"]


def test_containing_an_incident_executes_nothing(client, manager_ctx):
    """
    The security-critical negative: moving a case to `contained` is a
    human recording that containment happened. It must not approve or
    execute any privileged action by itself.
    """
    _, _, headers = manager_ctx
    incident = _create_incident(client, headers)
    iid = incident["id"]

    created = client.post(
        "/api/v1/response/actions",
        headers=headers,
        json={
            "action_type": "isolate_host",
            "target": "IR-HOST-01",
            "justification": "Proposed containment.",
            "incident_id": iid,
        },
    )
    action_id = created.json()["id"]

    _set_status(client, headers, iid, "triaged")
    _set_status(client, headers, iid, "contained")

    still = client.get(f"/api/v1/incidents/{iid}/response-actions", headers=headers).json()
    assert len(still) == 1
    assert still[0]["status"] == "pending", "status transitions never approve anything"

    db = SessionLocal()
    try:
        row = db.query(ResponseAction).filter(ResponseAction.id == uuid.UUID(action_id)).one()
        assert row.approved_at is None
        assert row.executed_at is None
    finally:
        db.close()


def test_cannot_attach_a_response_action_to_another_tenants_incident(client, manager_ctx):
    """
    `incident_id` became a write target in Phase 9 (it is mirrored onto
    that incident's timeline), so an unvalidated id would be a
    cross-tenant write.
    """
    _, _, headers = manager_ctx
    other_org = create_organization()
    other_user, other_pw = create_user(other_org, role_name="soc_manager")
    other_headers = auth_headers(client, other_user.email, other_pw)
    foreign_incident = _create_incident(client, other_headers, title="Their case")

    resp = client.post(
        "/api/v1/response/actions",
        headers=headers,
        json={
            "action_type": "block_ip",
            "target": "203.0.113.9",
            "justification": "Cross-tenant attempt.",
            "incident_id": foreign_incident["id"],
        },
    )
    assert resp.status_code == 422
    assert "Unknown incident_id" in resp.json()["detail"]

    assert _timeline(client, other_headers, foreign_incident["id"], kind="response_action") == []


# --------------------------------------------------------------------------
# AI investigation -> incident promotion
# --------------------------------------------------------------------------


def _run_investigation(client, headers):
    """Ingest an event that fires a HIGH detection, then investigate the alert."""
    event = {
        "source": "windows_sysmon",
        "timestamp": _BASE_TIME.isoformat(),
        "host": "IR-PROMOTE-01",
        "user": "alice",
        "event_type": "process_creation",
        "process": "powershell.exe",
        "command_line": "powershell.exe -enc SQBFAFgA==",
    }
    assert client.post("/api/v1/events", headers=headers, json=event).status_code == 201
    alerts = client.get("/api/v1/alerts", headers=headers, params={"host": "IR-PROMOTE-01"}).json()
    assert len(alerts) == 1
    resp = client.post("/api/v1/ai/investigations", headers=headers, json={"alert_id": alerts[0]["id"]})
    assert resp.status_code == 201, resp.text
    return resp.json()


def test_promoting_an_investigation_builds_a_grounded_case_file(client):
    org = create_organization()
    admin, pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, pw)

    investigation = _run_investigation(client, headers)
    assert investigation["status"] == "completed"

    resp = client.post(
        "/api/v1/incidents/from-investigation",
        headers=headers,
        json={"investigation_id": investigation["id"]},
    )
    assert resp.status_code == 201, resp.text
    promotion = resp.json()
    incident = promotion["incident"]

    assert promotion["evidence_recorded"] > 0
    assert promotion["evidence_rejected"] == 0, "the orchestrator's own output must survive re-validation"
    assert incident["severity"] == investigation["result"]["severity"]
    assert incident["alert_ids"] == [investigation["alert_id"]]

    # The AI's narrative lands as a note that is honestly attributed.
    notes = client.get(f"/api/v1/incidents/{incident['id']}/notes", headers=headers).json()
    ai_notes = [n for n in notes if n["is_ai_generated"]]
    assert len(ai_notes) == 1
    assert ai_notes[0]["body"] == investigation["result"]["summary"]

    # Every recorded evidence entry names the tool it came from.
    evidence = _timeline(client, headers, incident["id"], kind="evidence")
    assert len(evidence) == promotion["evidence_recorded"]
    assert all(e["details"]["source_tool"] for e in evidence)
    assert all(e["actor"] == "ai_agent:investigation" for e in evidence)

    # The pending containment request the Response Agent filed is attached
    # to the case — still pending, still needing a human.
    assert promotion["response_actions_attached"] >= 1
    actions = client.get(f"/api/v1/incidents/{incident['id']}/response-actions", headers=headers).json()
    assert actions and all(a["status"] == "pending" for a in actions)


def test_promotion_rejects_evidence_whose_source_event_no_longer_resolves(client):
    """
    The Phase 8 "never fabricate" gate, re-applied at the incident
    boundary. A stored result is just data by the time it reaches
    promotion, so citations are re-checked against the database rather
    than trusted.
    """
    org = create_organization()
    admin, pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, pw)

    investigation = _run_investigation(client, headers)

    # Tamper with the stored result the way a corrupted or attacker-influenced
    # record would look: a citation pointing at an event that does not exist.
    db = SessionLocal()
    try:
        from app.models.ai import AIInvestigation

        row = db.query(AIInvestigation).filter(AIInvestigation.id == uuid.UUID(investigation["id"])).one()
        result = dict(row.result)
        evidence = list(result["observed_evidence"])
        evidence.append(
            {
                "claim": "A fabricated observation with no backing row.",
                "source_tool": "search_events",
                "source_event_id": str(uuid.uuid4()),
                "source_table": "events",
                "confidence": 0.99,
            }
        )
        result["observed_evidence"] = evidence
        row.result = result
        db.add(row)
        db.commit()
    finally:
        db.close()

    resp = client.post(
        "/api/v1/incidents/from-investigation",
        headers=headers,
        json={"investigation_id": investigation["id"]},
    )
    assert resp.status_code == 201, resp.text
    promotion = resp.json()

    assert promotion["evidence_rejected"] == 1
    assert "does not resolve to a real event" in promotion["rejected_details"][0]["reason"]

    claims = [
        e["details"]["claim"]
        for e in _timeline(client, headers, promotion["incident"]["id"], kind="evidence")
    ]
    assert "A fabricated observation with no backing row." not in claims


def test_promoting_an_incomplete_investigation_is_refused(client):
    org = create_organization()
    admin, pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, pw)

    alert = _make_alert(org.id)
    db = SessionLocal()
    try:
        from app.models.ai import AIInvestigation

        pending = AIInvestigation(
            organization_id=org.id,
            alert_id=alert.id,
            status="pending",
            ai_provider="mock",
            ai_model="mock-deterministic-analyst",
        )
        db.add(pending)
        db.commit()
        db.refresh(pending)
        pending_id = str(pending.id)
    finally:
        db.close()

    resp = client.post(
        "/api/v1/incidents/from-investigation", headers=headers, json={"investigation_id": pending_id}
    )
    assert resp.status_code == 409
    assert "only a completed investigation" in resp.json()["detail"]


def test_cannot_promote_another_tenants_investigation(client, manager_ctx):
    _, _, headers = manager_ctx
    other_org = create_organization()
    other_admin, other_pw = create_user(other_org, role_name="admin", is_superuser=True)
    other_headers = auth_headers(client, other_admin.email, other_pw)

    foreign_investigation = _run_investigation(client, other_headers)

    resp = client.post(
        "/api/v1/incidents/from-investigation",
        headers=headers,
        json={"investigation_id": foreign_investigation["id"]},
    )
    assert resp.status_code == 404


def test_promotion_requires_ai_read_as_well_as_incidents_create(client):
    """
    A role that cannot read AI investigation output must not be able to
    launder it into an incident it *is* allowed to read.
    """
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    admin_headers = auth_headers(client, admin.email, admin_pw)
    investigation = _run_investigation(client, admin_headers)

    # Strip ai.read from the analyst role for the duration of this test.
    from app.models.user import Role

    db = SessionLocal()
    try:
        role = db.query(Role).filter(Role.name == "soc_analyst").one()
        removed = [p for p in role.permissions if p.code == "ai.read"]
        for perm in removed:
            role.permissions.remove(perm)
        db.add(role)
        db.commit()
    finally:
        db.close()

    try:
        analyst, analyst_pw = create_user(org, role_name="soc_analyst")
        analyst_headers = auth_headers(client, analyst.email, analyst_pw)
        resp = client.post(
            "/api/v1/incidents/from-investigation",
            headers=analyst_headers,
            json={"investigation_id": investigation["id"]},
        )
        assert resp.status_code == 403
        assert "ai.read" in resp.json()["detail"]
    finally:
        db = SessionLocal()
        try:
            role = db.query(Role).filter(Role.name == "soc_analyst").one()
            for perm in removed:
                role.permissions.append(db.merge(perm))
            db.add(role)
            db.commit()
        finally:
            db.close()


# --------------------------------------------------------------------------
# check_related_incidents (the Phase 9 agent tool)
# --------------------------------------------------------------------------


def test_check_related_incidents_is_read_only_and_response_agent_only():
    tool = TOOL_REGISTRY["check_related_incidents"]
    assert tool.effect is ActionEffect.READ_ONLY

    from app.ai.agents.permissions import AGENT_TOOL_ALLOWLIST

    granted = {a for a, tools in AGENT_TOOL_ALLOWLIST.items() if "check_related_incidents" in tools}
    assert granted == {AgentType.RESPONSE}


def test_response_agent_sees_an_open_incident_for_the_host(client, manager_ctx):
    org, _, headers = manager_ctx
    alert = _make_alert(org.id, host_name="RELATED-01", user="bob")
    incident = _create_incident(client, headers, severity=None, alert_ids=[str(alert.id)])

    db = SessionLocal()
    try:
        result = invoke_agent_tool(
            db,
            agent_type=AgentType.RESPONSE,
            tool_name="check_related_incidents",
            organization_id=org.id,
            hostname="RELATED-01",
        )
    finally:
        db.close()

    assert result["count"] == 1
    assert result["incidents"][0]["incident_id"] == incident["id"]
    assert result["incidents"][0]["reference"] == "INC-000001"
    assert result["incidents"][0]["status"] == "new"


def test_check_related_incidents_excludes_closed_cases_by_default(client, manager_ctx):
    org, _, headers = manager_ctx
    alert = _make_alert(org.id, host_name="CLOSED-01")
    incident = _create_incident(client, headers, severity=None, alert_ids=[str(alert.id)])
    _set_status(client, headers, incident["id"], "closed", closure_classification="false_positive")

    db = SessionLocal()
    try:
        default = invoke_agent_tool(
            db, agent_type=AgentType.RESPONSE, tool_name="check_related_incidents",
            organization_id=org.id, hostname="CLOSED-01",
        )
        including = invoke_agent_tool(
            db, agent_type=AgentType.RESPONSE, tool_name="check_related_incidents",
            organization_id=org.id, hostname="CLOSED-01", include_closed=True,
        )
    finally:
        db.close()

    assert default["count"] == 0, "a closed case is not a reason to skip containment"
    assert including["count"] == 1


def test_check_related_incidents_never_crosses_a_tenant_boundary(client, manager_ctx):
    org, _, headers = manager_ctx
    other_org = create_organization()
    other_user, other_pw = create_user(other_org, role_name="soc_manager")
    other_headers = auth_headers(client, other_user.email, other_pw)

    foreign_alert = _make_alert(other_org.id, host_name="SHARED-HOSTNAME")
    _create_incident(client, other_headers, severity=None, alert_ids=[str(foreign_alert.id)])

    db = SessionLocal()
    try:
        result = invoke_agent_tool(
            db, agent_type=AgentType.RESPONSE, tool_name="check_related_incidents",
            organization_id=org.id, hostname="SHARED-HOSTNAME",
        )
    finally:
        db.close()

    assert result["count"] == 0


def test_check_related_incidents_with_no_criteria_returns_an_error_not_an_exception():
    """
    The agent loop only catches ToolPermissionError, so a TypeError from a
    missing keyword would abort the whole investigation instead of
    becoming a correctable tool result.
    """
    org = create_organization()
    db = SessionLocal()
    try:
        result = invoke_agent_tool(
            db, agent_type=AgentType.RESPONSE, tool_name="check_related_incidents", organization_id=org.id
        )
    finally:
        db.close()
    assert "error" in result


@pytest.mark.parametrize("agent_type", [AgentType.TRIAGE, AgentType.INVESTIGATION, AgentType.THREAT_HUNT, AgentType.CLOUD_IAM])
def test_other_agents_are_denied_check_related_incidents(agent_type):
    org = create_organization()
    db = SessionLocal()
    try:
        with pytest.raises(ToolPermissionError) as exc:
            invoke_agent_tool(
                db, agent_type=agent_type, tool_name="check_related_incidents",
                organization_id=org.id, hostname="ANY-HOST",
            )
        assert exc.value.reason == "tool_not_in_agent_allowlist"
    finally:
        db.close()


def test_no_incident_mutating_tool_exists_in_the_registry():
    """
    Phase 9 gives agents *visibility* of the case file, never authorship.
    Nothing an agent can dispatch may create, close, or edit an incident.
    """
    forbidden = {"create_incident", "close_incident", "update_incident", "add_incident_note", "assign_incident"}
    assert forbidden.isdisjoint(TOOL_REGISTRY)
    assert all(t.effect is not ActionEffect.PRIVILEGED_ACTION for t in TOOL_REGISTRY.values())


# --------------------------------------------------------------------------
# RBAC + tenant isolation on the new routes
# --------------------------------------------------------------------------


def test_viewer_can_read_but_cannot_create_or_mutate(client):
    org = create_organization()
    manager, manager_pw = create_user(org, role_name="soc_manager")
    manager_headers = auth_headers(client, manager.email, manager_pw)
    viewer, viewer_pw = create_user(org, role_name="viewer")
    viewer_headers = auth_headers(client, viewer.email, viewer_pw)

    incident = _create_incident(client, manager_headers)
    iid = incident["id"]

    assert client.get(f"/api/v1/incidents/{iid}", headers=viewer_headers).status_code == 200
    assert client.get(f"/api/v1/incidents/{iid}/timeline", headers=viewer_headers).status_code == 200
    assert client.get(f"/api/v1/incidents/{iid}/metrics", headers=viewer_headers).status_code == 200
    assert client.get(f"/api/v1/incidents/{iid}/tasks", headers=viewer_headers).status_code == 200

    assert client.post("/api/v1/incidents", headers=viewer_headers, json={"title": "x", "severity": "LOW"}).status_code == 403
    assert _set_status(client, viewer_headers, iid, "triaged").status_code == 403
    assert client.post(f"/api/v1/incidents/{iid}/notes", headers=viewer_headers, json={"body": "hi"}).status_code == 403
    assert client.post(f"/api/v1/incidents/{iid}/tasks", headers=viewer_headers, json={"title": "t"}).status_code == 403
    assert client.patch(f"/api/v1/incidents/{iid}/assign", headers=viewer_headers, json={"assigned_to_id": str(viewer.id)}).status_code == 403


def test_analyst_can_update_but_cannot_assign(client):
    org = create_organization()
    analyst, pw = create_user(org, role_name="soc_analyst")
    headers = auth_headers(client, analyst.email, pw)

    incident = _create_incident(client, headers)
    iid = incident["id"]

    assert client.patch(f"/api/v1/incidents/{iid}", headers=headers, json={"summary": "Updated."}).status_code == 200
    assert _set_status(client, headers, iid, "triaged").status_code == 200
    assert client.patch(
        f"/api/v1/incidents/{iid}/assign", headers=headers, json={"assigned_to_id": str(analyst.id)}
    ).status_code == 403


def test_unauthenticated_access_is_rejected(client, manager_ctx):
    _, _, headers = manager_ctx
    incident = _create_incident(client, headers)
    for path in ("", f"/{incident['id']}", f"/{incident['id']}/timeline", f"/{incident['id']}/tasks"):
        assert client.get(f"/api/v1/incidents{path}").status_code == 401


@pytest.mark.parametrize(
    "path_suffix",
    ["", "/metrics", "/timeline", "/notes", "/tasks", "/response-actions"],
)
def test_every_nested_route_is_tenant_isolated(client, manager_ctx, path_suffix):
    """
    IDOR sweep: a valid incident id from another organization must 404 on
    every nested route, not just on the detail endpoint.
    """
    _, _, headers = manager_ctx
    other_org = create_organization()
    other_user, other_pw = create_user(other_org, role_name="soc_manager")
    other_headers = auth_headers(client, other_user.email, other_pw)
    foreign = _create_incident(client, other_headers, title="Their case")

    resp = client.get(f"/api/v1/incidents/{foreign['id']}{path_suffix}", headers=headers)
    assert resp.status_code == 404, f"{path_suffix} leaked a cross-tenant incident"


def test_another_tenants_incident_cannot_be_mutated(client, manager_ctx):
    _, _, headers = manager_ctx
    other_org = create_organization()
    other_user, other_pw = create_user(other_org, role_name="soc_manager")
    other_headers = auth_headers(client, other_user.email, other_pw)
    foreign = _create_incident(client, other_headers, title="Their case")
    fid = foreign["id"]

    assert _set_status(client, headers, fid, "triaged").status_code == 404
    assert client.patch(f"/api/v1/incidents/{fid}", headers=headers, json={"summary": "hijacked"}).status_code == 404
    assert client.post(f"/api/v1/incidents/{fid}/notes", headers=headers, json={"body": "hijacked"}).status_code == 404
    assert client.post(f"/api/v1/incidents/{fid}/tasks", headers=headers, json={"title": "hijacked"}).status_code == 404

    # And nothing landed on their case file.
    assert client.get(f"/api/v1/incidents/{fid}", headers=other_headers).json()["status"] == "new"
    assert client.get(f"/api/v1/incidents/{fid}/notes", headers=other_headers).json() == []


def test_incident_list_only_shows_your_own_organization(client, manager_ctx):
    _, _, headers = manager_ctx
    _create_incident(client, headers, title="Mine")

    other_org = create_organization()
    other_user, other_pw = create_user(other_org, role_name="soc_manager")
    other_headers = auth_headers(client, other_user.email, other_pw)
    _create_incident(client, other_headers, title="Theirs")

    titles = [i["title"] for i in client.get("/api/v1/incidents", headers=headers).json()]
    assert "Mine" in titles
    assert "Theirs" not in titles


def test_list_filters_narrow_the_result_set(client, manager_ctx):
    _, _, headers = manager_ctx
    low = _create_incident(client, headers, title="Low case", severity="LOW")
    high = _create_incident(client, headers, title="High case", severity="HIGH")
    _set_status(client, headers, low["id"], "closed", closure_classification="false_positive")

    open_only = client.get("/api/v1/incidents", headers=headers, params={"open_only": True}).json()
    ids = [i["id"] for i in open_only]
    assert high["id"] in ids
    assert low["id"] not in ids

    by_severity = client.get("/api/v1/incidents", headers=headers, params={"severity": "HIGH"}).json()
    assert all(i["severity"] == "HIGH" for i in by_severity)


def test_unknown_incident_id_is_404_not_500(client, manager_ctx):
    _, _, headers = manager_ctx
    assert client.get(f"/api/v1/incidents/{uuid.uuid4()}", headers=headers).status_code == 404


# --------------------------------------------------------------------------
# Audit trail
# --------------------------------------------------------------------------


def test_lifecycle_actions_are_audited(client, manager_ctx):
    org, user, headers = manager_ctx
    incident = _create_incident(client, headers)
    iid = incident["id"]
    _set_status(client, headers, iid, "triaged")
    _set_status(client, headers, iid, "closed", closure_classification="duplicate")

    from app.models.audit import AuditLog

    db = SessionLocal()
    try:
        actions = {
            row.action
            for row in db.query(AuditLog).filter(AuditLog.resource_id == iid).all()
        }
    finally:
        db.close()

    assert {"incident_created", "incident_status_changed"} <= actions


def test_timeline_entry_count_matches_a_real_db_read(client, manager_ctx):
    """Guards against the API silently paginating away part of the case file."""
    _, _, headers = manager_ctx
    incident = _create_incident(client, headers)
    api_entries = _timeline(client, headers, incident["id"])

    db = SessionLocal()
    try:
        db_count = (
            db.query(IncidentEvent)
            .filter(IncidentEvent.incident_id == uuid.UUID(incident["id"]))
            .count()
        )
        stored = db.query(Incident).filter(Incident.id == uuid.UUID(incident["id"])).one()
        assert stored.incident_number is not None
    finally:
        db.close()

    assert len(api_entries) == db_count
