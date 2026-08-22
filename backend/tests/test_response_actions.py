"""
Human-in-the-loop approval state machine tests. The central guarantee:
status can only ever reach 'executed' by pending -> approved -> executed,
and the 'approved' transition can only be performed by an authenticated
human User holding response.approve — there is no code path (agent tool,
service function, or API route) that skips it.
"""
import pytest

from app.ai.agents.permissions import invoke_agent_tool
from app.db.session import SessionLocal
from app.models.automation import ResponseAction
from app.models.enums import AgentType
from app.services.response_actions import (
    ResponseActionError,
    approve_response_action,
    execute_response_action,
)
from tests.factories import auth_headers, create_organization, create_user


def test_ai_agent_originated_request_starts_pending_and_stays_pending(client):
    """
    Simulates the Response Agent 'requesting host isolation' the way
    Phase 8's agentic loop will. Confirms it lands as a pending
    ResponseAction with the agent identity recorded as requester, and that
    nothing about creating the request moves it any further.
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
            target="WIN-EVIL-01",
            justification="Beaconing to a known-bad C2 domain observed on this host.",
        )
        action = db.query(ResponseAction).filter(ResponseAction.id == result["response_action_id"]).one()
        assert action.status == "pending"
        assert action.requested_by_agent_type == "response"
        assert action.requested_by_id is None
        assert action.approved_by_id is None
        assert action.executed_at is None
    finally:
        db.close()


def test_cannot_execute_a_pending_action_directly():
    org = create_organization()
    db = SessionLocal()
    try:
        result = invoke_agent_tool(
            db,
            agent_type=AgentType.RESPONSE,
            tool_name="request_response_approval",
            organization_id=org.id,
            action_type="disable_account",
            target="jdoe",
            justification="Credential compromise suspected.",
        )
        action = db.query(ResponseAction).filter(ResponseAction.id == result["response_action_id"]).one()

        manager, _ = create_user(org, role_name="soc_manager")
        with pytest.raises(ResponseActionError):
            execute_response_action(db, action, executor=manager)
    finally:
        db.close()


def test_cannot_approve_an_action_twice():
    org = create_organization()
    db = SessionLocal()
    try:
        result = invoke_agent_tool(
            db,
            agent_type=AgentType.RESPONSE,
            tool_name="request_response_approval",
            organization_id=org.id,
            action_type="block_ip",
            target="203.0.113.9",
            justification="C2 IP.",
        )
        action = db.query(ResponseAction).filter(ResponseAction.id == result["response_action_id"]).one()
        manager, _ = create_user(org, role_name="soc_manager")

        approve_response_action(db, action, approver=manager)
        with pytest.raises(ResponseActionError):
            approve_response_action(db, action, approver=manager)
    finally:
        db.close()


def test_full_lifecycle_via_api_agent_request_human_approval_execution(client):
    """
    End-to-end: agent files the request (service-level, since agents have
    no HTTP session) -> SOC Manager approves via the API -> SOC Manager
    executes via the API -> result + full audit trail present.
    """
    org = create_organization()
    manager, manager_pw = create_user(org, role_name="soc_manager")

    db = SessionLocal()
    try:
        result = invoke_agent_tool(
            db,
            agent_type=AgentType.RESPONSE,
            tool_name="request_response_approval",
            organization_id=org.id,
            action_type="isolate_host",
            target="WIN-07",
            justification="Ransomware-like file activity detected.",
        )
        action_id = result["response_action_id"]
    finally:
        db.close()

    headers = auth_headers(client, manager.email, manager_pw)

    # Cannot execute before approval.
    premature_exec = client.post(f"/api/v1/response/actions/{action_id}/execute", headers=headers)
    assert premature_exec.status_code == 409

    approve_resp = client.patch(f"/api/v1/response/actions/{action_id}/approve", headers=headers)
    assert approve_resp.status_code == 200
    assert approve_resp.json()["status"] == "approved"
    assert approve_resp.json()["approved_by_id"] is not None

    exec_resp = client.post(f"/api/v1/response/actions/{action_id}/execute", headers=headers)
    assert exec_resp.status_code == 200
    body = exec_resp.json()
    assert body["status"] == "executed"
    assert body["result"]["simulated"] is True
    assert body["executed_by_id"] is not None


def test_rejected_action_cannot_later_be_approved(client):
    org = create_organization()
    manager, manager_pw = create_user(org, role_name="soc_manager")

    db = SessionLocal()
    try:
        result = invoke_agent_tool(
            db,
            agent_type=AgentType.RESPONSE,
            tool_name="request_response_approval",
            organization_id=org.id,
            action_type="block_domain",
            target="evil.example",
            justification="DNS beacon.",
        )
        action_id = result["response_action_id"]
    finally:
        db.close()

    headers = auth_headers(client, manager.email, manager_pw)
    reject_resp = client.patch(
        f"/api/v1/response/actions/{action_id}/reject", headers=headers, json={"reason": "False positive — known scanner."}
    )
    assert reject_resp.status_code == 200
    assert reject_resp.json()["status"] == "rejected"

    approve_after_reject = client.patch(f"/api/v1/response/actions/{action_id}/approve", headers=headers)
    assert approve_after_reject.status_code == 409


def test_response_actions_are_tenant_scoped(client):
    org_a = create_organization()
    org_b = create_organization()
    manager_a, pw_a = create_user(org_a, role_name="soc_manager")

    db = SessionLocal()
    try:
        result = invoke_agent_tool(
            db,
            agent_type=AgentType.RESPONSE,
            tool_name="request_response_approval",
            organization_id=org_b.id,
            action_type="isolate_host",
            target="ORG-B-HOST",
            justification="x",
        )
        action_id = result["response_action_id"]
    finally:
        db.close()

    headers_a = auth_headers(client, manager_a.email, pw_a)
    cross_tenant_approve = client.patch(f"/api/v1/response/actions/{action_id}/approve", headers=headers_a)
    assert cross_tenant_approve.status_code == 404
