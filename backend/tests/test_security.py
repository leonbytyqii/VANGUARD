"""
Phase 13 — the adversarial suite.

Every other test file asks "does this feature work?". This one asks "can
I break the security model?", and it is organized by *attacker goal*
rather than by module, because that is how the threat model in
docs/SECURITY.md is organized and how a reviewer will read it.

Two rules kept this file honest while writing it:

1. **Every test here must be able to fail.** A test that asserts a
   boundary nothing could ever cross proves nothing. Where a control is
   structural (a tool that isn't in a registry, a route that doesn't
   exist), the test asserts the *absence* directly, so deleting the
   control breaks the test.
2. **Nothing here duplicates a feature test.** Where an existing file
   already proves a boundary, this file attacks it from a different
   direction — a different actor, a different entry point, or a
   composition of two features that are each safe alone.
"""
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from jose import jwt

from app.ai.agents.permissions import AGENT_MAX_EFFECT, AGENT_TOOL_ALLOWLIST, ToolPermissionError, invoke_agent_tool
from app.ai.tools.registry import PRIVILEGED_ACTION_CATALOG, TOOL_REGISTRY
from app.core.config import settings
from app.core.permissions import PERMISSIONS, ROLE_PERMISSIONS
from app.db.session import SessionLocal
from app.models.alert import Alert
from app.models.automation import ResponseAction
from app.models.enums import ActionEffect, AgentType
from tests.factories import auth_headers, create_organization, create_user

ALL_ROLES = ["viewer", "threat_hunter", "soc_analyst", "soc_manager", "admin"]


# ==========================================================================
# Goal: make the platform execute something privileged without a human
# ==========================================================================


def test_no_privileged_action_is_reachable_through_the_agent_tool_registry():
    """
    The structural control. Deleting it — by adding a privileged tool to
    the registry — fails this immediately.
    """
    assert PRIVILEGED_ACTION_CATALOG, "the catalog should list the dangerous actions"
    for action_type in PRIVILEGED_ACTION_CATALOG:
        assert action_type not in TOOL_REGISTRY, f"{action_type} became agent-dispatchable"
    for name, tool in TOOL_REGISTRY.items():
        assert tool.effect is not ActionEffect.PRIVILEGED_ACTION, f"{name} is classified privileged_action"


def test_no_agent_has_a_ceiling_that_permits_privileged_action():
    for agent_type, ceiling in AGENT_MAX_EFFECT.items():
        assert ceiling is not ActionEffect.PRIVILEGED_ACTION, agent_type


def test_every_allowlisted_tool_exists_and_is_within_its_agents_ceiling():
    """
    Catches a misconfigured allowlist — an agent granted a tool riskier
    than its declared ceiling, or a tool name that silently does nothing
    because it was renamed.
    """
    order = {ActionEffect.READ_ONLY: 0, ActionEffect.PROPOSE_ONLY: 1, ActionEffect.PRIVILEGED_ACTION: 2}
    for agent_type, tools in AGENT_TOOL_ALLOWLIST.items():
        for name in tools:
            assert name in TOOL_REGISTRY, f"{agent_type} is allowed non-existent tool {name}"
            assert order[TOOL_REGISTRY[name].effect] <= order[AGENT_MAX_EFFECT[agent_type]], (
                f"{agent_type} may call {name}, which exceeds its ceiling"
            )


@pytest.mark.parametrize("agent_type", list(AgentType))
@pytest.mark.parametrize("action", sorted(PRIVILEGED_ACTION_CATALOG))
def test_no_agent_can_dispatch_any_privileged_action_by_name(agent_type, action):
    org = create_organization()
    db = SessionLocal()
    try:
        with pytest.raises(ToolPermissionError) as exc:
            invoke_agent_tool(db, agent_type=agent_type, tool_name=action, organization_id=org.id, target="X")
        assert exc.value.reason == "tool_not_registered"
    finally:
        db.close()


def test_an_agent_cannot_approve_the_action_it_just_filed(client):
    """
    End-to-end composition: the Response Agent files a request, and there
    is no tool anywhere that could move it out of `pending`.
    """
    org = create_organization()
    db = SessionLocal()
    try:
        result = invoke_agent_tool(
            db,
            agent_type=AgentType.RESPONSE,
            tool_name="request_response_approval",
            organization_id=org.id,
            action_type="isolate_host",
            target="SEC-HOST-01",
            justification="adversarial test",
        )
        action_id = uuid.UUID(result["response_action_id"])
        assert result["status"] == "pending"

        # Nothing in the registry can approve, execute, or delete it.
        for name in TOOL_REGISTRY:
            assert "approve" not in name, f"{name} looks like an approval tool"
            assert "execute" not in name, f"{name} looks like an execution tool"

        row = db.query(ResponseAction).filter(ResponseAction.id == action_id).one()
        assert row.status == "pending"
        assert row.approved_by_id is None
        assert row.executed_at is None
    finally:
        db.close()


def test_execution_requires_approval_even_when_called_at_the_service_layer(client):
    """
    Bypassing the HTTP route does not bypass the state machine — the check
    lives in the service, not the router.
    """
    from app.services.response_actions import (
        ResponseActionError,
        create_response_action_request,
        execute_response_action,
    )

    org = create_organization()
    user, _ = create_user(org, role_name="admin", is_superuser=True)
    db = SessionLocal()
    try:
        actor = db.merge(user)
        action = create_response_action_request(
            db,
            organization_id=org.id,
            action_type="block_ip",
            target="203.0.113.7",
            justification="adversarial test",
            requested_by_user=actor,
        )
        with pytest.raises(ResponseActionError) as exc:
            execute_response_action(db, action, executor=actor)
        assert exc.value.status_code == 409
    finally:
        db.close()


def test_a_superuser_flag_does_not_bypass_the_approval_state_machine(client):
    org = create_organization()
    admin, pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, pw)

    created = client.post(
        "/api/v1/response/actions",
        headers=headers,
        json={"action_type": "disable_account", "target": "victim", "justification": "test"},
    )
    action_id = created.json()["id"]

    # Even an admin superuser must approve before executing.
    early = client.post(f"/api/v1/response/actions/{action_id}/execute", headers=headers)
    assert early.status_code == 409


# ==========================================================================
# Goal: read another tenant's data
# ==========================================================================


def _foreign_org_with_data(client):
    org = create_organization()
    user, pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, user.email, pw)
    client.post(
        "/api/v1/events",
        headers=headers,
        json={
            "source": "windows_sysmon",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "host": "FOREIGN-01",
            "user": "foreign-user",
            "event_type": "process_creation",
            "process": "powershell.exe",
            "command_line": "powershell.exe -enc SQBFAFgA==",
        },
    )
    alerts = client.get("/api/v1/alerts", headers=headers, params={"host": "FOREIGN-01"}).json()
    incident = client.post(
        "/api/v1/incidents", headers=headers, json={"title": "Foreign case", "severity": "HIGH"}
    ).json()
    return org, headers, alerts[0] if alerts else None, incident


def test_no_list_endpoint_leaks_another_tenants_rows(client):
    _, _, foreign_alert, foreign_incident = _foreign_org_with_data(client)

    org = create_organization()
    user, pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, user.email, pw)

    assert client.get("/api/v1/alerts", headers=headers).json() == []
    assert client.get("/api/v1/events", headers=headers).json() == []
    assert client.get("/api/v1/incidents", headers=headers).json() == []
    assert client.get("/api/v1/threat-intel/iocs", headers=headers).json() == []
    assert client.get("/api/v1/cloud/identities", headers=headers).json() == []
    assert client.get("/api/v1/ai/investigations", headers=headers).json() == []
    assert client.get("/api/v1/hunting/executions", headers=headers).json() == []
    assert client.get("/api/v1/response/actions", headers=headers).json() == []
    assert foreign_alert is not None and foreign_incident is not None


def test_cross_tenant_reads_are_404_not_403(client):
    """
    A 403 confirms the resource exists. The platform returns 404 for both
    "no such id" and "someone else's id" precisely so an attacker cannot
    enumerate another tenant's ids by status code.
    """
    _, _, foreign_alert, foreign_incident = _foreign_org_with_data(client)

    org = create_organization()
    user, pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, user.email, pw)

    real_but_foreign = client.get(f"/api/v1/incidents/{foreign_incident['id']}", headers=headers)
    nonexistent = client.get(f"/api/v1/incidents/{uuid.uuid4()}", headers=headers)
    assert real_but_foreign.status_code == nonexistent.status_code == 404
    assert real_but_foreign.json() == nonexistent.json(), "the two must be indistinguishable"

    assert client.get(f"/api/v1/alerts/{foreign_alert['id']}", headers=headers).status_code == 404


def test_agent_tools_are_tenant_scoped_even_when_the_agent_is_told_otherwise(client):
    """
    An agent's `organization_id` comes from the investigation, not from
    the model. Even so, every handler re-filters — so a hypothetical
    prompt-injected argument cannot widen the read.
    """
    foreign_org, _, _, _ = _foreign_org_with_data(client)
    org = create_organization()

    db = SessionLocal()
    try:
        result = invoke_agent_tool(
            db,
            agent_type=AgentType.INVESTIGATION,
            tool_name="search_events",
            organization_id=org.id,
            host_name="FOREIGN-01",
        )
        assert result["count"] == 0, "an agent must not see another tenant's events"

        host = invoke_agent_tool(
            db,
            agent_type=AgentType.INVESTIGATION,
            tool_name="get_host_info",
            organization_id=org.id,
            hostname="FOREIGN-01",
        )
        assert host["found"] is False
    finally:
        db.close()
    assert foreign_org is not None


# ==========================================================================
# Goal: escalate privilege within a tenant
# ==========================================================================


@pytest.mark.parametrize("role", ["viewer", "threat_hunter", "soc_analyst"])
def test_lower_roles_cannot_reach_admin_endpoints(client, role):
    org = create_organization()
    user, pw = create_user(org, role_name=role)
    headers = auth_headers(client, user.email, pw)

    assert client.get("/api/v1/admin/users", headers=headers).status_code == 403
    assert client.post(
        "/api/v1/admin/users",
        headers=headers,
        json={"email": "new@example.com", "full_name": "N", "password": "Sup3r$ecurePassw0rd!", "role": "admin"},
    ).status_code == 403


def test_an_analyst_cannot_grant_themselves_a_permission_by_editing_their_own_user(client):
    org = create_organization()
    analyst, pw = create_user(org, role_name="soc_analyst")
    headers = auth_headers(client, analyst.email, pw)

    resp = client.patch(f"/api/v1/admin/users/{analyst.id}", headers=headers, json={"role": "admin"})
    assert resp.status_code == 403

    me = client.get("/api/v1/auth/me", headers=headers).json()
    assert me["role"] == "soc_analyst"


def test_a_revoked_permission_takes_effect_on_the_very_next_request(client):
    """
    Permissions are re-read from the database per request, never trusted
    from the token's cached `perms` claim. This is the test that proves
    the claim is decorative.
    """
    from app.models.user import Role

    org = create_organization()
    manager, pw = create_user(org, role_name="soc_manager")
    headers = auth_headers(client, manager.email, pw)

    assert client.get("/api/v1/audit", headers=headers).status_code == 200

    db = SessionLocal()
    removed = []
    try:
        role = db.query(Role).filter(Role.name == "soc_manager").one()
        removed = [p for p in role.permissions if p.code == "audit.read"]
        for perm in removed:
            role.permissions.remove(perm)
        db.add(role)
        db.commit()
    finally:
        db.close()

    try:
        # Same token, no re-login.
        assert client.get("/api/v1/audit", headers=headers).status_code == 403
    finally:
        db = SessionLocal()
        try:
            role = db.query(Role).filter(Role.name == "soc_manager").one()
            for perm in removed:
                role.permissions.append(db.merge(perm))
            db.add(role)
            db.commit()
        finally:
            db.close()


def test_the_permission_catalog_and_role_grants_are_internally_consistent():
    """A role granted a permission that does not exist would silently never match."""
    for role, codes in ROLE_PERMISSIONS.items():
        assert len(codes) == len(set(codes)), f"{role} has a duplicated grant"
        for code in codes:
            assert code in PERMISSIONS, f"{role} is granted unknown permission {code}"


def test_role_grants_are_monotonically_increasing_in_privilege():
    """
    viewer ⊂ threat_hunter is not required, but analyst ⊂ manager ⊂ admin
    is: a SOC manager who cannot do something their analyst can is a
    real-world escalation-by-delegation bug waiting to happen.
    """
    analyst = set(ROLE_PERMISSIONS["soc_analyst"])
    manager = set(ROLE_PERMISSIONS["soc_manager"])
    admin = set(ROLE_PERMISSIONS["admin"])
    assert analyst <= manager, f"analyst has what manager lacks: {analyst - manager}"
    assert manager <= admin, f"manager has what admin lacks: {manager - admin}"


def test_viewer_holds_no_write_permission():
    for code in ROLE_PERMISSIONS["viewer"]:
        assert not any(
            code.endswith(suffix)
            for suffix in (".create", ".update", ".assign", ".approve", ".request", ".manage", ".write", ".ingest")
        ), f"viewer holds write-shaped permission {code}"


# ==========================================================================
# Goal: forge or replay authentication
# ==========================================================================


def test_a_token_signed_with_the_wrong_key_is_rejected(client):
    org = create_organization()
    user, _ = create_user(org, role_name="admin", is_superuser=True)
    forged = jwt.encode(
        {
            "sub": str(user.id),
            "type": "access",
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        },
        "not-the-real-signing-key",
        algorithm=settings.JWT_ALGORITHM,
    )
    resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {forged}"})
    assert resp.status_code == 401


def test_a_refresh_token_cannot_be_used_as_an_access_token(client):
    """Token type confusion — the `type` claim is checked, not just the signature."""
    org = create_organization()
    user, _ = create_user(org, role_name="admin", is_superuser=True)
    refresh_shaped = jwt.encode(
        {
            "sub": str(user.id),
            "type": "refresh",
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        },
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )
    resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {refresh_shaped}"})
    assert resp.status_code == 401


def test_an_expired_token_is_rejected(client):
    org = create_organization()
    user, _ = create_user(org, role_name="admin", is_superuser=True)
    expired = jwt.encode(
        {
            "sub": str(user.id),
            "type": "access",
            "exp": datetime.now(timezone.utc) - timedelta(minutes=1),
        },
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )
    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {expired}"}).status_code == 401


def test_a_token_for_a_deactivated_user_stops_working_immediately(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    admin_headers = auth_headers(client, admin.email, admin_pw)
    victim, victim_pw = create_user(org, role_name="soc_analyst")
    victim_headers = auth_headers(client, victim.email, victim_pw)

    assert client.get("/api/v1/auth/me", headers=victim_headers).status_code == 200
    client.patch(f"/api/v1/admin/users/{victim.id}", headers=admin_headers, json={"is_active": False})
    assert client.get("/api/v1/auth/me", headers=victim_headers).status_code == 401


def test_a_token_whose_subject_does_not_exist_is_rejected(client):
    orphan = jwt.encode(
        {"sub": str(uuid.uuid4()), "type": "access", "exp": datetime.now(timezone.utc) + timedelta(hours=1)},
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )
    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {orphan}"}).status_code == 401


def test_login_does_not_reveal_whether_an_account_exists(client):
    org = create_organization()
    user, _ = create_user(org, role_name="viewer")

    wrong_password = client.post("/api/v1/auth/login", json={"email": user.email, "password": "WrongPassword!123"})
    no_such_user = client.post(
        "/api/v1/auth/login", json={"email": "definitely-not-here@example.com", "password": "WrongPassword!123"}
    )
    assert wrong_password.status_code == no_such_user.status_code == 401
    assert wrong_password.json() == no_such_user.json()


def test_malformed_authorization_headers_are_rejected_cleanly(client):
    for header in ({"Authorization": "Bearer"}, {"Authorization": "Basic abc"}, {"Authorization": "Bearer not.a.jwt"}):
        resp = client.get("/api/v1/auth/me", headers=header)
        assert resp.status_code == 401, header


# ==========================================================================
# Goal: tamper with the record of what happened
# ==========================================================================


def test_there_is_no_write_route_for_the_audit_log(client):
    org = create_organization()
    admin, pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, pw)

    for method in ("POST", "PATCH", "PUT", "DELETE"):
        resp = client.request(method, "/api/v1/audit", headers=headers, json={"action": "forged"})
        assert resp.status_code in (404, 405), f"{method} /audit should not exist (got {resp.status_code})"


def test_there_is_no_write_route_for_an_incident_timeline(client):
    org = create_organization()
    admin, pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, pw)
    incident = client.post(
        "/api/v1/incidents", headers=headers, json={"title": "Tamper target", "severity": "LOW"}
    ).json()

    for method in ("POST", "PATCH", "PUT", "DELETE"):
        resp = client.request(
            method,
            f"/api/v1/incidents/{incident['id']}/timeline",
            headers=headers,
            json={"kind": "status_change", "actor": "attacker@evil.test"},
        )
        assert resp.status_code == 405


def test_permission_denials_are_recorded_with_the_actor_and_the_route(client):
    org = create_organization()
    viewer, pw = create_user(org, role_name="viewer")
    headers = auth_headers(client, viewer.email, pw)

    client.post("/api/v1/incidents", headers=headers, json={"title": "nope", "severity": "LOW"})

    from app.models.audit import AuditLog

    db = SessionLocal()
    try:
        denial = (
            db.query(AuditLog)
            .filter(AuditLog.action == "permission_denied", AuditLog.actor_label == viewer.email)
            .order_by(AuditLog.timestamp.desc())
            .first()
        )
    finally:
        db.close()

    assert denial is not None, "a refused request must leave a trace"
    assert denial.outcome == "denied"
    assert denial.resource_id == "/api/v1/incidents"
    assert denial.details["required_permission"] == "incidents.create"


def test_refused_agent_tool_calls_are_audited(client):
    org = create_organization()
    db = SessionLocal()
    try:
        with pytest.raises(ToolPermissionError):
            invoke_agent_tool(
                db, agent_type=AgentType.TRIAGE, tool_name="request_response_approval",
                organization_id=org.id, action_type="isolate_host", target="x", justification="y",
            )

        from app.models.audit import AuditLog

        denial = (
            db.query(AuditLog)
            .filter(AuditLog.action == "ai_tool_permission_denied")
            .order_by(AuditLog.timestamp.desc())
            .first()
        )
    finally:
        db.close()
    assert denial is not None
    assert denial.details["reason"] == "tool_not_in_agent_allowlist"


# ==========================================================================
# Goal: get the AI to assert something it cannot support
# ==========================================================================


def test_a_citation_that_does_not_resolve_is_rejected_by_the_orchestrator(client):
    from app.ai.orchestrator import EvidenceValidationError, _validate_investigation_result

    org = create_organization()
    db = SessionLocal()
    try:
        payload = {
            "severity": "HIGH",
            "risk_score": 80,
            "confidence": 0.9,
            "summary": "Fabricated.",
            "observed_evidence": [
                {
                    "claim": "An event that never happened.",
                    "source_tool": "search_events",
                    "source_event_id": str(uuid.uuid4()),
                    "source_table": "events",
                    "confidence": 0.99,
                }
            ],
        }
        with pytest.raises(EvidenceValidationError):
            _validate_investigation_result(db, org.id, payload, set())
    finally:
        db.close()


def test_containment_recommendations_cannot_opt_out_of_approval():
    """
    `requires_approval` is `Literal[True]` at the schema level, so an
    action that skips approval is a type error rather than a validation
    rule a later edit could relax.
    """
    from pydantic import ValidationError

    from app.schemas.ai_investigation import RecommendedContainmentAction

    ok = RecommendedContainmentAction(action="isolate_host", target="H", reasoning="r")
    assert ok.requires_approval is True

    with pytest.raises(ValidationError):
        RecommendedContainmentAction(action="isolate_host", target="H", reasoning="r", requires_approval=False)


def test_no_agent_tool_can_write_to_the_case_file_or_the_alert_queue():
    """
    Agents gained read access to incidents in Phase 9 and to cloud
    telemetry in Phase 11. Neither may become write access.
    """
    forbidden_substrings = ("create_", "update_", "delete_", "close_", "assign_", "approve_", "execute_")
    for name, tool in TOOL_REGISTRY.items():
        if name in ("draft_containment_plan", "request_response_approval"):
            continue  # propose-only by design; covered above
        assert not any(name.startswith(s) for s in forbidden_substrings), f"{name} looks mutating"
        assert tool.effect is ActionEffect.READ_ONLY, f"{name} is not read_only"


def test_a_human_cannot_post_an_ai_attributed_note(client):
    org = create_organization()
    analyst, pw = create_user(org, role_name="soc_analyst")
    headers = auth_headers(client, analyst.email, pw)
    incident = client.post(
        "/api/v1/incidents", headers=headers, json={"title": "Provenance target", "severity": "LOW"}
    ).json()

    note = client.post(
        f"/api/v1/incidents/{incident['id']}/notes",
        headers=headers,
        json={"body": "Trust me, the AI said this.", "is_ai_generated": True},
    ).json()
    assert note["is_ai_generated"] is False


# ==========================================================================
# Goal: abuse input handling
# ==========================================================================


def test_oversized_and_malformed_ingest_payloads_are_rejected(client):
    org = create_organization()
    admin, pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, pw)

    # Unknown source
    assert client.post(
        "/api/v1/events",
        headers=headers,
        json={"source": "not-a-real-source", "timestamp": datetime.now(timezone.utc).isoformat()},
    ).status_code == 422

    # Missing the adapter's required field
    assert client.post(
        "/api/v1/events",
        headers=headers,
        json={"source": "dns", "timestamp": datetime.now(timezone.utc).isoformat(), "host": "H"},
    ).status_code == 422

    # Batch over the declared cap
    oversized = {
        "events": [
            {"source": "synthetic_lab", "timestamp": datetime.now(timezone.utc).isoformat(), "host": "H"}
            for _ in range(501)
        ]
    }
    assert client.post("/api/v1/events/batch", headers=headers, json=oversized).status_code == 422


def test_sql_shaped_input_is_treated_as_data_not_as_sql(client):
    """
    Everything goes through SQLAlchemy's parameter binding; this asserts
    the behaviour rather than the mechanism, so it would catch a future
    hand-rolled query too.
    """
    org = create_organization()
    admin, pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, pw)

    payload = "'; DROP TABLE alerts; --"
    resp = client.get("/api/v1/alerts", headers=headers, params={"host": payload})
    assert resp.status_code == 200
    assert resp.json() == []

    # The table is still there and still queryable.
    db = SessionLocal()
    try:
        db.query(Alert).count()
    finally:
        db.close()


def test_a_hunt_condition_cannot_execute_arbitrary_code(client):
    """
    The Sigma/hunt condition evaluator walks a restricted AST — there is
    no eval(). An attempted call or attribute access must be refused.
    """
    from app.hunting.engine import HuntQueryError, validate_query_definition

    for condition in (
        "__import__('os').system('echo pwned')",
        "selection.__class__",
        "open('/etc/passwd')",
        "selection and (lambda: 1)()",
    ):
        with pytest.raises(HuntQueryError):
            validate_query_definition({"selection": {"process": "x"}, "condition": condition})


def test_unicode_and_control_characters_in_a_hostname_do_not_break_ingestion(client):
    org = create_organization()
    admin, pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, pw)

    resp = client.post(
        "/api/v1/events",
        headers=headers,
        json={
            "source": "synthetic_lab",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "host": "hÖst-​-01",
            "user": "üser",
            "event_type": "generic",
        },
    )
    assert resp.status_code in (201, 422), resp.text


# ==========================================================================
# Goal: find a secret
# ==========================================================================


def test_no_endpoint_returns_a_password_hash_or_a_secret(client):
    org = create_organization()
    admin, pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, pw)

    # Deliberately not a bare search for "password": `must_change_password`
    # is a legitimate boolean flag on the user contract. The strings below
    # are ones that can only appear if an actual secret leaked.
    for path in ("/api/v1/auth/me", "/api/v1/admin/users", "/api/v1/admin/roles"):
        body = client.get(path, headers=headers).text.lower()
        for forbidden in ("hashed_password", "$argon2", "jwt_secret", "secret_key", "\"password\"", pw.lower()):
            assert forbidden not in body, f"{path} leaked {forbidden}"


def test_settings_contain_no_hardcoded_production_secret():
    """
    The default JWT key is an obvious placeholder, and the config module
    reads every credential from the environment. A real key committed here
    would fail this.
    """
    assert "CHANGE_ME" in settings.model_fields["JWT_SECRET_KEY"].default
    for field_name in ("AI_API_KEY", "VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY", "OTX_API_KEY"):
        assert settings.model_fields[field_name].default is None, f"{field_name} has a baked-in default"


def test_threat_intel_raw_responses_are_redacted_of_key_shaped_material():
    from app.threat_intel.providers.live import _redact

    dirty = {"apiKey": "abc", "nested": {"Authorization": "Bearer xyz", "ok": 1}, "list": [{"token": "t"}]}
    clean = _redact(dirty)
    assert clean["apiKey"] == "[redacted]"
    assert clean["nested"]["Authorization"] == "[redacted]"
    assert clean["nested"]["ok"] == 1
    assert clean["list"][0]["token"] == "[redacted]"


# ==========================================================================
# Goal: exhaust or wedge the platform
# ==========================================================================


def test_list_endpoints_enforce_a_maximum_page_size(client):
    org = create_organization()
    admin, pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, pw)

    for path in ("/api/v1/alerts", "/api/v1/events", "/api/v1/incidents", "/api/v1/threat-intel/iocs"):
        resp = client.get(path, headers=headers, params={"limit": 100000})
        assert resp.status_code == 422, f"{path} accepted an unbounded limit"


def test_negative_and_absurd_pagination_is_rejected(client):
    org = create_organization()
    admin, pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, pw)

    assert client.get("/api/v1/alerts", headers=headers, params={"limit": -1}).status_code == 422
    assert client.get("/api/v1/alerts", headers=headers, params={"offset": -5}).status_code == 422


def test_an_agent_loop_cannot_run_unbounded():
    """`AI_MAX_TOOL_ITERATIONS` bounds every phase; an unbounded default would be a DoS on ourselves."""
    assert 0 < settings.AI_MAX_TOOL_ITERATIONS <= 50
