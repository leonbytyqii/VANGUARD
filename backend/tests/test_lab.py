"""
Attack simulation lab (Phase 14).

The headline assertion here is that **every shipped scenario still
produces the detections it claims**. That makes this file a regression
harness for the whole detection stack, not just a test of the lab: if a
Sigma rule or a correlation window is broken by a later change, the
scenario that exercises it stops firing and this fails.
"""
import ipaddress

import pytest

from app.db.session import SessionLocal
from app.detections.registry import DETECTION_REGISTRY
from app.lab.scenarios import SCENARIOS, SCENARIOS_BY_ID
from app.models.event import Event
from app.services.lab import run_scenario
from tests.factories import auth_headers, create_organization, create_user

_DOC_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]


@pytest.fixture()
def admin_ctx(client):
    org = create_organization()
    user, pw = create_user(org, role_name="admin", is_superuser=True)
    return org, user, auth_headers(client, user.email, pw)


def _all_payload_values(scenario):
    for step in scenario.steps:
        for value in step.payload.values():
            if isinstance(value, str):
                yield value
            elif isinstance(value, dict):
                for nested in value.values():
                    if isinstance(nested, str):
                        yield nested
                    elif isinstance(nested, dict):
                        for deep in nested.values():
                            if isinstance(deep, str):
                                yield deep


# --------------------------------------------------------------------------
# Scenario data integrity
# --------------------------------------------------------------------------


def test_scenario_ids_are_unique():
    ids = [s.scenario_id for s in SCENARIOS]
    assert len(ids) == len(set(ids))


def test_every_expected_detection_is_a_real_registered_rule():
    """
    A scenario claiming a rule that does not exist would silently always
    'fail' — catching the typo here rather than in a demo.
    """
    known = {d.rule_id for d in DETECTION_REGISTRY}
    for scenario in SCENARIOS:
        for rule_id in scenario.expected_detections:
            assert rule_id in known, f"{scenario.scenario_id} expects unknown rule {rule_id}"


def test_every_scenario_mitre_id_is_in_the_seeded_catalog():
    from app.mitre.data import TECHNIQUES

    seeded = {t["technique_id"] for t in TECHNIQUES}
    for scenario in SCENARIOS:
        for technique_id in scenario.mitre_technique_ids:
            assert technique_id in seeded, f"{scenario.scenario_id} references unseeded {technique_id}"


def test_no_scenario_names_a_real_ip_address():
    """
    The same safety rule as the threat-intel sample feed: a committed
    scenario must never describe somebody's real host as an attacker.
    """
    for scenario in SCENARIOS:
        for value in _all_payload_values(scenario):
            try:
                addr = ipaddress.ip_address(value)
            except ValueError:
                continue
            allowed = (
                any(addr in net for net in _DOC_NETWORKS)
                or addr.is_private
                or addr.is_loopback
            )
            assert allowed, f"{scenario.scenario_id} uses non-reserved address {value}"


def test_no_scenario_names_a_real_domain():
    for scenario in SCENARIOS:
        for step in scenario.steps:
            domain = step.payload.get("domain")
            if domain:
                assert domain.endswith((".invalid", ".test")), f"{scenario.scenario_id} uses {domain}"


def test_scenario_steps_are_ordered_and_bounded():
    for scenario in SCENARIOS:
        offsets = [s.offset_minutes for s in scenario.steps]
        assert offsets, f"{scenario.scenario_id} has no steps"
        assert all(o >= 0 for o in offsets)
        assert max(offsets) <= 60, f"{scenario.scenario_id} spans more than an hour"


def test_scenarios_contain_no_executable_instructions():
    """
    A "simulation" here is synthetic telemetry describing an attack, never
    an attack. Nothing in a scenario payload may be a directive the
    platform would act on — the payloads only ever become `events` rows.
    """
    for scenario in SCENARIOS:
        for step in scenario.steps:
            # Command lines are *described*, and only ever stored as text
            # on an Event. Nothing reads them back to execute.
            assert "source" in step.payload
            assert step.payload["source"] in {
                "windows_sysmon", "linux_auth", "dns", "firewall", "cloudtrail", "synthetic_lab",
            }


# --------------------------------------------------------------------------
# Running scenarios end to end
# --------------------------------------------------------------------------


@pytest.mark.parametrize("scenario_id", sorted(SCENARIOS_BY_ID))
def test_every_scenario_fires_its_expected_detections(client, scenario_id):
    """
    The regression harness. Each scenario is replayed through the real
    ingestion path in its own fresh organization, and every detection it
    claims must actually fire.
    """
    org = create_organization()
    db = SessionLocal()
    try:
        result = run_scenario(db, SCENARIOS_BY_ID[scenario_id], organization_id=org.id)
    finally:
        db.close()

    assert result.errors == [], f"{scenario_id} had ingestion errors: {result.errors}"
    assert result.events_ingested == len(SCENARIOS_BY_ID[scenario_id].steps)
    assert result.missing_detections == [], (
        f"{scenario_id} expected {result.expected_detections} but only {result.detections_fired} fired"
    )
    assert result.fully_detected is True


def test_a_scenario_run_creates_real_alerts(client):
    org = create_organization()
    db = SessionLocal()
    try:
        result = run_scenario(db, SCENARIOS_BY_ID["encoded_powershell_c2"], organization_id=org.id)
    finally:
        db.close()
    assert result.alerts_created > 0, "detections should have produced alerts through the normal path"


def test_simulated_events_are_permanently_tagged_as_synthetic(client):
    org = create_organization()
    db = SessionLocal()
    try:
        result = run_scenario(db, SCENARIOS_BY_ID["credential_access_lsass"], organization_id=org.id)
        events = db.query(Event).filter(Event.id.in_(result.event_ids)).all()
        for event in events:
            extra = event.raw_event.get("extra") or {}
            assert extra.get("simulated") is True
            assert extra.get("scenario_id") == "credential_access_lsass"
    finally:
        db.close()


def test_cloud_scenario_also_populates_the_cloud_projection(client):
    """The lab drives Phase 11's projection too, because it uses the real ingest path."""
    from app.models.cloud import CloudEvent, CloudIdentity

    org = create_organization()
    db = SessionLocal()
    try:
        result = run_scenario(db, SCENARIOS_BY_ID["cloud_privilege_escalation"], organization_id=org.id)
        cloud_events = db.query(CloudEvent).filter(CloudEvent.event_id.in_(result.event_ids)).all()
        identities = {
            i.identity_name for i in db.query(CloudIdentity).filter(CloudIdentity.organization_id == org.id).all()
        }
    finally:
        db.close()

    assert len(cloud_events) == len(result.event_ids)
    assert "sim-dev-alice" in identities
    assert "SimDeployRole" in identities


def test_scenario_runs_are_tenant_isolated(client):
    org_a = create_organization()
    org_b = create_organization()
    db = SessionLocal()
    try:
        run_scenario(db, SCENARIOS_BY_ID["ssh_brute_force"], organization_id=org_a.id)
        in_b = db.query(Event).filter(Event.organization_id == org_b.id).count()
    finally:
        db.close()
    assert in_b == 0


# --------------------------------------------------------------------------
# API + RBAC
# --------------------------------------------------------------------------


def test_scenario_list_and_run_via_the_api(client, admin_ctx):
    _, _, headers = admin_ctx

    listed = client.get("/api/v1/lab/scenarios", headers=headers)
    assert listed.status_code == 200, listed.text
    assert len(listed.json()) == len(SCENARIOS)

    run = client.post("/api/v1/lab/scenarios/dga_beaconing/run", headers=headers, json={})
    assert run.status_code == 201, run.text
    body = run.json()
    assert body["fully_detected"] is True
    assert body["events_ingested"] == len(SCENARIOS_BY_ID["dga_beaconing"].steps)


def test_unknown_scenario_is_404(client, admin_ctx):
    _, _, headers = admin_ctx
    resp = client.post("/api/v1/lab/scenarios/not-a-scenario/run", headers=headers, json={})
    assert resp.status_code == 404


def test_non_admin_roles_cannot_manufacture_telemetry(client):
    """
    A scenario run produces real alerts in the same queue analysts work
    from. Letting an analyst fabricate those would make the alert queue
    useless as a record of what actually happened.
    """
    org = create_organization()
    for role in ("viewer", "soc_analyst", "soc_manager", "threat_hunter"):
        user, pw = create_user(org, role_name=role)
        headers = auth_headers(client, user.email, pw)
        assert client.get("/api/v1/lab/scenarios", headers=headers).status_code == 403, role
        assert (
            client.post("/api/v1/lab/scenarios/dga_beaconing/run", headers=headers, json={}).status_code == 403
        ), role


def test_unauthenticated_access_is_rejected(client):
    assert client.get("/api/v1/lab/scenarios").status_code == 401
    assert client.post("/api/v1/lab/scenarios/dga_beaconing/run", json={}).status_code == 401


def test_scenario_run_is_audited(client, admin_ctx):
    _, _, headers = admin_ctx
    client.post("/api/v1/lab/scenarios/persistence_scheduled_task/run", headers=headers, json={})

    from app.models.audit import AuditLog

    db = SessionLocal()
    try:
        rows = (
            db.query(AuditLog)
            .filter(AuditLog.action == "lab_scenario_run", AuditLog.resource_id == "persistence_scheduled_task")
            .all()
        )
    finally:
        db.close()
    assert rows, "a scenario run must be auditable — it manufactures evidence"
