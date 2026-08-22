"""
Cloud / IAM security (Phase 11): the cloud_events projection, identity
derivation from observed activity, IAM attack-path reconstruction and its
bounds, the three Cloud/IAM agent tools, and RBAC / tenant isolation —
including the cross-tenant leak that scoping on account_id alone would
have produced.
"""
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.ai.agents.permissions import AGENT_TOOL_ALLOWLIST, ToolPermissionError, invoke_agent_tool
from app.ai.tools.registry import TOOL_REGISTRY
from app.cloud_iam.attack_paths import MAX_ACTIONS_PER_IDENTITY, reconstruct_attack_path
from app.cloud_iam.projection import classify_action
from app.db.session import SessionLocal
from app.models.cloud import CloudEvent, CloudIdentity
from app.models.enums import ActionEffect, AgentType
from tests.factories import auth_headers, create_organization, create_user

_BASE = datetime(2026, 7, 1, 9, 0, 0, tzinfo=timezone.utc)
ACCOUNT = "111122223333"


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


@pytest.fixture()
def cloud_ctx(client):
    org = create_organization()
    user, pw = create_user(org, role_name="admin", is_superuser=True)
    return org, user, auth_headers(client, user.email, pw)


def _cloud_event(client, headers, *, event_name, user="dev-alice", offset=0, extra=None, account=ACCOUNT, region="eu-west-1"):
    body = {
        "source": "cloudtrail",
        "timestamp": (_BASE + timedelta(minutes=offset)).isoformat(),
        "event_type": event_name,
        "user": user,
        "cloud_account": account,
        "cloud_region": region,
        "src_ip": "203.0.113.7",
        "extra": extra or {},
    }
    resp = client.post("/api/v1/events", headers=headers, json=body)
    assert resp.status_code == 201, resp.text
    return resp.json()


def _build_escalation_chain(client, headers, *, actor="dev-alice", account=ACCOUNT):
    """actor -> AssumeRole(DeployRole) -> DeployRole attaches a policy, then stops logging."""
    _cloud_event(
        client, headers, event_name="AssumeRole", user=actor, offset=0,
        extra={"request_parameters": {"roleArn": f"arn:aws:iam::{account}:role/DeployRole"}}, account=account,
    )
    _cloud_event(
        client, headers, event_name="AttachRolePolicy", user="DeployRole", offset=5,
        extra={"request_parameters": {"roleName": "DeployRole", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}},
        account=account,
    )
    _cloud_event(
        client, headers, event_name="StopLogging", user="DeployRole", offset=9,
        extra={"request_parameters": {"trailName": "org-trail"}}, account=account,
    )


# --------------------------------------------------------------------------
# Action classification
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "event_name,expected",
    [
        ("AssumeRole", "role_assumption"),
        ("AttachRolePolicy", "privilege_escalation"),
        ("CreateAccessKey", "privilege_escalation"),
        ("StopLogging", "defense_evasion"),
        ("DeleteTrail", "defense_evasion"),
        ("GetObject", "access"),
        ("DescribeInstances", "access"),
    ],
)
def test_action_classification(event_name, expected):
    assert classify_action(event_name) == expected


def test_defense_evasion_outranks_privilege_escalation_in_severity():
    """
    Turning off logging is treated as worse than gaining a permission:
    it removes the defender's ability to see everything that follows.
    """
    from app.cloud_iam.attack_paths import _SEVERITY_BY_SIGNAL, _SEVERITY_RANK

    assert _SEVERITY_RANK[_SEVERITY_BY_SIGNAL["defense_evasion"]] > _SEVERITY_RANK[_SEVERITY_BY_SIGNAL["privilege_escalation"]]


# --------------------------------------------------------------------------
# Projection
# --------------------------------------------------------------------------


def test_cloudtrail_ingest_projects_a_cloud_event_and_derives_identities(client, cloud_ctx):
    org, _, headers = cloud_ctx
    event = _cloud_event(
        client, headers, event_name="AssumeRole",
        extra={"request_parameters": {"roleArn": f"arn:aws:iam::{ACCOUNT}:role/DeployRole"}},
    )

    db = SessionLocal()
    try:
        cloud_event = db.query(CloudEvent).filter(CloudEvent.event_id == uuid.UUID(event["id"])).one()
        assert cloud_event.event_name == "AssumeRole"
        assert cloud_event.actor_identity == "dev-alice"
        assert cloud_event.assumed_role_arn.endswith("role/DeployRole")
        # The projection always points back at the generic event row it
        # came from — it is never a second source of truth.
        assert cloud_event.event_id == uuid.UUID(event["id"])

        names = {
            i.identity_name
            for i in db.query(CloudIdentity).filter(CloudIdentity.organization_id == org.id).all()
        }
        assert {"dev-alice", "DeployRole"} <= names
    finally:
        db.close()


def test_non_cloudtrail_events_get_no_projection(client, cloud_ctx):
    _, _, headers = cloud_ctx
    resp = client.post(
        "/api/v1/events",
        headers=headers,
        json={
            "source": "windows_sysmon",
            "timestamp": _BASE.isoformat(),
            "host": "WIN-01",
            "event_type": "process_creation",
            "process": "cmd.exe",
        },
    )
    assert resp.status_code == 201
    db = SessionLocal()
    try:
        assert db.query(CloudEvent).filter(CloudEvent.event_id == uuid.UUID(resp.json()["id"])).one_or_none() is None
    finally:
        db.close()


def test_identity_upsert_is_idempotent_and_widens_the_seen_window(client, cloud_ctx):
    org, _, headers = cloud_ctx
    _cloud_event(client, headers, event_name="GetObject", user="dev-bob", offset=0)
    _cloud_event(client, headers, event_name="GetObject", user="dev-bob", offset=120)

    db = SessionLocal()
    try:
        rows = (
            db.query(CloudIdentity)
            .filter(CloudIdentity.organization_id == org.id, CloudIdentity.identity_name == "dev-bob")
            .all()
        )
        assert len(rows) == 1, "one identity row regardless of how many times it acts"
        assert rows[0].last_seen_at > rows[0].first_seen_at
    finally:
        db.close()


def test_privileged_flag_is_a_naming_heuristic_and_is_labelled_as_one(client, cloud_ctx):
    _, _, headers = cloud_ctx
    _cloud_event(client, headers, event_name="GetObject", user="org-admin-break-glass")

    identities = client.get("/api/v1/cloud/identities", headers=headers, params={"privileged_only": True}).json()
    assert "org-admin-break-glass" in [i["identity_name"] for i in identities]

    db = SessionLocal()
    try:
        result = invoke_agent_tool(
            db, agent_type=AgentType.CLOUD_IAM, tool_name="get_cloud_identity",
            organization_id=identities[0] and uuid.UUID(client.get("/api/v1/auth/me", headers=headers).json()["organization_id"]),
            identity_name="org-admin-break-glass",
        )
    finally:
        db.close()
    # The tool names it a heuristic in the payload, so a model summarising
    # it cannot honestly report it as an IAM policy fact.
    assert result["is_privileged_heuristic"] is True
    assert "is_privileged" not in result


# --------------------------------------------------------------------------
# Attack-path reconstruction
# --------------------------------------------------------------------------


def test_reconstructs_the_full_escalation_chain(client, cloud_ctx):
    _, _, headers = cloud_ctx
    _build_escalation_chain(client, headers)

    resp = client.post(
        "/api/v1/cloud/attack-paths",
        headers=headers,
        json={"account_id": ACCOUNT, "seed_identity": "dev-alice", "start_time": _BASE.isoformat(), "window_hours": 24},
    )
    assert resp.status_code == 201, resp.text
    path = resp.json()

    node_ids = {n["id"] for n in path["path_nodes"]}
    assert "dev-alice" in node_ids
    assert "DeployRole" in node_ids, "the assumed role became a node in the chain"

    signals = {e["signal"] for e in path["path_edges"]}
    assert "role_assumption" in signals
    assert "privilege_escalation" in signals
    assert "defense_evasion" in signals

    assert path["privilege_escalation_detected"] is True
    assert path["severity"] == "CRITICAL", "defense evasion drives the path severity"
    assert "DeployRole" in path["explanation"]
    assert "observed, not permissions that were theoretically reachable" in path["explanation"]


def test_every_edge_cites_the_cloud_event_it_came_from(client, cloud_ctx):
    _, _, headers = cloud_ctx
    _build_escalation_chain(client, headers)
    path = client.post(
        "/api/v1/cloud/attack-paths",
        headers=headers,
        json={"account_id": ACCOUNT, "seed_identity": "dev-alice", "start_time": _BASE.isoformat()},
    ).json()

    db = SessionLocal()
    try:
        for edge in path["path_edges"]:
            assert edge["cloud_event_id"], "an edge with no citable row is an unfalsifiable claim"
            row = db.query(CloudEvent).filter(CloudEvent.id == uuid.UUID(edge["cloud_event_id"])).one_or_none()
            assert row is not None, f"edge cites {edge['cloud_event_id']} which does not resolve"
    finally:
        db.close()


def test_a_seed_with_no_activity_produces_no_path(client, cloud_ctx):
    _, _, headers = cloud_ctx
    resp = client.post(
        "/api/v1/cloud/attack-paths",
        headers=headers,
        json={"account_id": ACCOUNT, "seed_identity": "nobody-here", "start_time": _BASE.isoformat()},
    )
    assert resp.status_code == 404
    assert "No cloud activity found" in resp.json()["detail"]


def test_activity_outside_the_window_is_excluded(client, cloud_ctx):
    _, _, headers = cloud_ctx
    _cloud_event(client, headers, event_name="AttachRolePolicy", user="late-carol", offset=60 * 48)

    resp = client.post(
        "/api/v1/cloud/attack-paths",
        headers=headers,
        json={
            "account_id": ACCOUNT, "seed_identity": "late-carol",
            "start_time": _BASE.isoformat(), "window_hours": 1,
        },
    )
    assert resp.status_code == 404, "an event two days later is not in a one-hour window"


def test_walk_truncation_is_declared_not_hidden(client, cloud_ctx):
    """
    Same discipline as Phase 7's hunt truncation: a bounded answer must
    never be presented as a complete one.
    """
    org, _, headers = cloud_ctx
    for i in range(MAX_ACTIONS_PER_IDENTITY + 5):
        _cloud_event(client, headers, event_name="GetObject", user="noisy-dave", offset=i)

    db = SessionLocal()
    try:
        path = reconstruct_attack_path(
            db,
            organization_id=org.id,
            account_id=ACCOUNT,
            seed_identity="noisy-dave",
            start_time=_BASE,
            persist=False,
        )
    finally:
        db.close()

    assert path is not None
    assert len(path.path_edges) == MAX_ACTIONS_PER_IDENTITY
    assert "TRUNCATED" in path.explanation


def test_cyclic_role_assumption_terminates(client, cloud_ctx):
    """A -> B -> A is legitimate in some architectures and must not hang the walk."""
    org, _, headers = cloud_ctx
    _cloud_event(
        client, headers, event_name="AssumeRole", user="RoleA", offset=0,
        extra={"request_parameters": {"roleArn": f"arn:aws:iam::{ACCOUNT}:role/RoleB"}},
    )
    _cloud_event(
        client, headers, event_name="AssumeRole", user="RoleB", offset=1,
        extra={"request_parameters": {"roleArn": f"arn:aws:iam::{ACCOUNT}:role/RoleA"}},
    )

    db = SessionLocal()
    try:
        path = reconstruct_attack_path(
            db, organization_id=org.id, account_id=ACCOUNT, seed_identity="RoleA",
            start_time=_BASE, persist=False,
        )
    finally:
        db.close()
    assert path is not None
    assert {n["id"] for n in path.path_nodes} == {"RoleA", "RoleB"}


# --------------------------------------------------------------------------
# Cloud API
# --------------------------------------------------------------------------


def test_cloud_event_search_filters(client, cloud_ctx):
    _, _, headers = cloud_ctx
    _build_escalation_chain(client, headers)
    _cloud_event(client, headers, event_name="GetObject", user="dev-alice", offset=20, extra={"error_code": "AccessDenied"})

    by_actor = client.get("/api/v1/cloud/events", headers=headers, params={"actor": "DeployRole"}).json()
    assert by_actor and all(e["actor_identity"] == "DeployRole" for e in by_actor)

    by_name = client.get("/api/v1/cloud/events", headers=headers, params={"event_name": "StopLogging"}).json()
    assert len(by_name) == 1

    errors = client.get("/api/v1/cloud/events", headers=headers, params={"errors_only": True}).json()
    assert errors and all(e["error_code"] for e in errors)


def test_identity_detail_lists_activity_and_roles_assumed(client, cloud_ctx):
    _, _, headers = cloud_ctx
    _build_escalation_chain(client, headers)

    identities = client.get("/api/v1/cloud/identities", headers=headers, params={"search": "dev-alice"}).json()
    detail = client.get(f"/api/v1/cloud/identities/{identities[0]['id']}", headers=headers)
    assert detail.status_code == 200, detail.text
    body = detail.json()
    assert body["recent_activity"]
    assert any("DeployRole" in arn for arn in body["roles_assumed"])


def test_attack_paths_list_and_detail(client, cloud_ctx):
    _, _, headers = cloud_ctx
    _build_escalation_chain(client, headers)
    created = client.post(
        "/api/v1/cloud/attack-paths",
        headers=headers,
        json={"account_id": ACCOUNT, "seed_identity": "dev-alice", "start_time": _BASE.isoformat()},
    ).json()

    listed = client.get("/api/v1/cloud/attack-paths", headers=headers, params={"privilege_escalation_only": True}).json()
    assert created["id"] in [p["id"] for p in listed]

    detail = client.get(f"/api/v1/cloud/attack-paths/{created['id']}", headers=headers)
    assert detail.status_code == 200
    assert detail.json()["explanation"] == created["explanation"]


def test_building_an_attack_path_is_audited(client, cloud_ctx):
    _, _, headers = cloud_ctx
    _build_escalation_chain(client, headers)
    created = client.post(
        "/api/v1/cloud/attack-paths",
        headers=headers,
        json={"account_id": ACCOUNT, "seed_identity": "dev-alice", "start_time": _BASE.isoformat()},
    ).json()

    from app.models.audit import AuditLog

    db = SessionLocal()
    try:
        actions = {r.action for r in db.query(AuditLog).filter(AuditLog.resource_id == created["id"]).all()}
    finally:
        db.close()
    assert "iam_attack_path_built" in actions


# --------------------------------------------------------------------------
# Agent tools
# --------------------------------------------------------------------------


def test_phase_11_tools_are_read_only_and_granted_only_to_the_cloud_agent():
    for name in ("get_cloud_identity", "get_role_assumptions", "search_cloud_events"):
        assert TOOL_REGISTRY[name].effect is ActionEffect.READ_ONLY
        granted = {a for a, tools in AGENT_TOOL_ALLOWLIST.items() if name in tools}
        assert granted == {AgentType.CLOUD_IAM}, f"{name} granted to {granted}"


def test_cloud_agent_ceiling_is_still_read_only():
    from app.ai.agents.permissions import AGENT_MAX_EFFECT

    assert AGENT_MAX_EFFECT[AgentType.CLOUD_IAM] is ActionEffect.READ_ONLY


@pytest.mark.parametrize("agent_type", [AgentType.TRIAGE, AgentType.INVESTIGATION, AgentType.THREAT_HUNT, AgentType.RESPONSE])
def test_other_agents_cannot_call_the_cloud_tools(agent_type):
    org = create_organization()
    db = SessionLocal()
    try:
        with pytest.raises(ToolPermissionError) as exc:
            invoke_agent_tool(
                db, agent_type=agent_type, tool_name="search_cloud_events",
                organization_id=org.id, actor="dev-alice",
            )
        assert exc.value.reason == "tool_not_in_agent_allowlist"
    finally:
        db.close()


def test_get_role_assumptions_returns_the_chain(client, cloud_ctx):
    org, _, headers = cloud_ctx
    _build_escalation_chain(client, headers)

    db = SessionLocal()
    try:
        result = invoke_agent_tool(
            db, agent_type=AgentType.CLOUD_IAM, tool_name="get_role_assumptions",
            organization_id=org.id, identity_name="dev-alice",
        )
    finally:
        db.close()
    assert result["count"] == 1
    assert result["assumptions"][0]["assumed_role_arn"].endswith("role/DeployRole")
    assert result["assumptions"][0]["event_id"], "must trace back to a real events row"


def test_no_cloud_tool_can_mutate_anything():
    for name in ("get_cloud_identity", "get_role_assumptions", "search_cloud_events"):
        assert TOOL_REGISTRY[name].effect is ActionEffect.READ_ONLY
    forbidden = {"revoke_cloud_credentials", "detach_role_policy", "delete_access_key", "disable_cloud_identity"}
    assert forbidden.isdisjoint(TOOL_REGISTRY)


# --------------------------------------------------------------------------
# Tenant isolation — the account_id trap
# --------------------------------------------------------------------------


def test_two_tenants_monitoring_the_same_aws_account_cannot_see_each_other(client, cloud_ctx):
    """
    The specific leak that scoping cloud_events on `account_id` alone
    would have produced. A managed-service provider watching a shared
    account is a real deployment shape, so this is not hypothetical.
    """
    org_a, _, headers_a = cloud_ctx
    org_b = create_organization()
    user_b, pw_b = create_user(org_b, role_name="admin", is_superuser=True)
    headers_b = auth_headers(client, user_b.email, pw_b)

    _cloud_event(client, headers_a, event_name="AttachRolePolicy", user="tenant-a-actor", account=ACCOUNT)
    _cloud_event(client, headers_b, event_name="AttachRolePolicy", user="tenant-b-actor", account=ACCOUNT)

    a_actors = {e["actor_identity"] for e in client.get("/api/v1/cloud/events", headers=headers_a).json()}
    b_actors = {e["actor_identity"] for e in client.get("/api/v1/cloud/events", headers=headers_b).json()}

    assert "tenant-a-actor" in a_actors and "tenant-b-actor" not in a_actors
    assert "tenant-b-actor" in b_actors and "tenant-a-actor" not in b_actors


def test_attack_path_walk_cannot_cross_a_tenant_boundary(client, cloud_ctx):
    org_a, _, headers_a = cloud_ctx
    org_b = create_organization()
    user_b, pw_b = create_user(org_b, role_name="admin", is_superuser=True)
    headers_b = auth_headers(client, user_b.email, pw_b)

    # Same identity name, same account, two tenants.
    _cloud_event(client, headers_a, event_name="GetObject", user="shared-name", offset=0)
    _cloud_event(client, headers_b, event_name="StopLogging", user="shared-name", offset=1)

    db = SessionLocal()
    try:
        path_a = reconstruct_attack_path(
            db, organization_id=org_a.id, account_id=ACCOUNT, seed_identity="shared-name",
            start_time=_BASE, persist=False,
        )
    finally:
        db.close()

    actions = {e["action"] for e in path_a.path_edges}
    assert actions == {"GetObject"}, "tenant B's StopLogging must not appear in tenant A's graph"


def test_attack_paths_are_tenant_isolated(client, cloud_ctx):
    _, _, headers = cloud_ctx
    other_org = create_organization()
    other_user, other_pw = create_user(other_org, role_name="admin", is_superuser=True)
    other_headers = auth_headers(client, other_user.email, other_pw)

    _build_escalation_chain(client, other_headers, actor="their-actor")
    foreign = client.post(
        "/api/v1/cloud/attack-paths",
        headers=other_headers,
        json={"account_id": ACCOUNT, "seed_identity": "their-actor", "start_time": _BASE.isoformat()},
    ).json()

    assert client.get(f"/api/v1/cloud/attack-paths/{foreign['id']}", headers=headers).status_code == 404
    assert foreign["id"] not in [p["id"] for p in client.get("/api/v1/cloud/attack-paths", headers=headers).json()]


def test_identities_are_tenant_isolated(client, cloud_ctx):
    _, _, headers = cloud_ctx
    other_org = create_organization()
    other_user, other_pw = create_user(other_org, role_name="admin", is_superuser=True)
    other_headers = auth_headers(client, other_user.email, other_pw)

    _cloud_event(client, other_headers, event_name="GetObject", user="their-identity")
    foreign = client.get("/api/v1/cloud/identities", headers=other_headers, params={"search": "their-identity"}).json()
    assert foreign

    assert client.get(f"/api/v1/cloud/identities/{foreign[0]['id']}", headers=headers).status_code == 404
    mine = [i["identity_name"] for i in client.get("/api/v1/cloud/identities", headers=headers).json()]
    assert "their-identity" not in mine


# --------------------------------------------------------------------------
# RBAC
# --------------------------------------------------------------------------


def test_viewer_has_read_access_to_cloud_and_iam(client, cloud_ctx):
    org, _, headers = cloud_ctx
    _build_escalation_chain(client, headers)
    viewer, pw = create_user(org, role_name="viewer")
    viewer_headers = auth_headers(client, viewer.email, pw)

    assert client.get("/api/v1/cloud/identities", headers=viewer_headers).status_code == 200
    assert client.get("/api/v1/cloud/events", headers=viewer_headers).status_code == 200
    assert client.get("/api/v1/cloud/attack-paths", headers=viewer_headers).status_code == 200


def test_unauthenticated_access_is_rejected(client):
    for path in ("/api/v1/cloud/identities", "/api/v1/cloud/events", "/api/v1/cloud/attack-paths"):
        assert client.get(path).status_code == 401
    assert client.post(
        "/api/v1/cloud/attack-paths", json={"account_id": ACCOUNT, "seed_identity": "x"}
    ).status_code == 401
