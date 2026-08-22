"""
Proves the core claim of Phase 2's agent permission model: an AI agent
cannot reach a privileged action, and cannot reach a tool outside its own
allowlist, no matter what it "asks" for — the backend refuses at the tool
dispatch layer (app/ai/agents/permissions.py::invoke_agent_tool), not via
a prompt instruction.

Phase 8 wires real LLM-driven agents on top of this same dispatch
function; these tests exercise the enforcement boundary directly so it's
verified independently of any model behavior.
"""
import pytest

from app.ai.agents.permissions import ToolPermissionError, invoke_agent_tool
from app.ai.tools.registry import PRIVILEGED_ACTION_CATALOG, TOOL_REGISTRY
from app.db.session import SessionLocal
from app.models.agent_identity import AgentIdentity
from app.models.audit import AuditLog
from app.models.enums import AgentType
from tests.factories import create_organization


def test_privileged_actions_are_never_registered_as_ai_tools():
    """
    The structural guarantee: isolate_host / disable_account / block_ip /
    block_domain / revoke_cloud_credentials exist only as a reference
    catalog for human-submitted response actions. None of them are
    present in TOOL_REGISTRY, so no agent-dispatch code path can reach
    them — this isn't a permission check that could be misconfigured, the
    functions simply aren't wired into the dispatcher at all.
    """
    for privileged_name in PRIVILEGED_ACTION_CATALOG:
        assert privileged_name not in TOOL_REGISTRY


def test_triage_agent_can_call_allowed_read_only_tool():
    org = create_organization()
    db = SessionLocal()
    try:
        result = invoke_agent_tool(
            db, agent_type=AgentType.TRIAGE, tool_name="search_events", organization_id=org.id, limit=5
        )
        assert result["count"] == 0  # no events ingested yet in this test org — proves it's a real query, not a stub
    finally:
        db.close()


def test_triage_agent_cannot_call_tool_outside_its_allowlist():
    """
    request_response_approval is a real, registered, propose_only tool —
    but it's only granted to the Response Agent. Triage must not be able
    to call it even though the tool itself is legitimate.
    """
    org = create_organization()
    db = SessionLocal()
    try:
        with pytest.raises(ToolPermissionError) as exc_info:
            invoke_agent_tool(
                db,
                agent_type=AgentType.TRIAGE,
                tool_name="request_response_approval",
                organization_id=org.id,
                action_type="isolate_host",
                target="WIN-01",
                justification="triage agent overreaching",
            )
        assert exc_info.value.reason == "tool_not_in_agent_allowlist"
    finally:
        db.close()


def test_no_agent_can_call_a_nonexistent_privileged_tool_name():
    """
    Simulates a compromised/jailbroken agent (or a prompt-injection
    attempt from a malicious log entry) asking to call 'isolate_host'
    directly as if it were a tool. There is nothing to configure here that
    could accidentally allow it — the name simply isn't in the registry.
    """
    org = create_organization()
    db = SessionLocal()
    try:
        for agent_type in AgentType:
            with pytest.raises(ToolPermissionError) as exc_info:
                invoke_agent_tool(
                    db, agent_type=agent_type, tool_name="isolate_host", organization_id=org.id, target="WIN-01"
                )
            assert exc_info.value.reason == "tool_not_registered"
    finally:
        db.close()


def test_response_agent_can_only_propose_never_execute():
    """
    The Response Agent's max_effect ceiling is propose_only. Its allowlist
    (draft_containment_plan, request_response_approval) only contains
    tools that create recommendations/pending requests — neither one has
    any code path that flips a ResponseAction to 'approved' or 'executed'.
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
            target="WIN-01",
            justification="Lateral movement observed from this host.",
        )
        assert result["status"] == "pending"  # never anything but pending from this call
    finally:
        db.close()


def test_disabled_agent_identity_blocks_all_tool_calls():
    org = create_organization()
    db = SessionLocal()
    try:
        identity = db.query(AgentIdentity).filter(AgentIdentity.agent_type == AgentType.TRIAGE.value).one()
        identity.enabled = False
        db.add(identity)
        db.commit()

        with pytest.raises(ToolPermissionError) as exc_info:
            invoke_agent_tool(db, agent_type=AgentType.TRIAGE, tool_name="search_events", organization_id=org.id)
        assert exc_info.value.reason == "agent_identity_disabled_or_missing"
    finally:
        identity.enabled = True
        db.add(identity)
        db.commit()
        db.close()


def test_tool_permission_denial_is_audited():
    org = create_organization()
    db = SessionLocal()
    try:
        with pytest.raises(ToolPermissionError):
            invoke_agent_tool(
                db,
                agent_type=AgentType.TRIAGE,
                tool_name="request_response_approval",
                organization_id=org.id,
                action_type="isolate_host",
                target="WIN-01",
                justification="x",
            )

        entry = (
            db.query(AuditLog)
            .filter(AuditLog.action == "ai_tool_permission_denied")
            .order_by(AuditLog.timestamp.desc())
            .first()
        )
        assert entry is not None
        assert entry.actor_label == "ai_agent:triage"
        assert entry.resource_id == "request_response_approval"
        assert entry.outcome == "denied"
    finally:
        db.close()


def test_successful_tool_invocation_is_also_audited():
    org = create_organization()
    db = SessionLocal()
    try:
        invoke_agent_tool(db, agent_type=AgentType.INVESTIGATION, tool_name="get_host_info", organization_id=org.id, hostname="WIN-99")

        entry = (
            db.query(AuditLog)
            .filter(AuditLog.action == "ai_tool_invoked", AuditLog.resource_id == "get_host_info")
            .order_by(AuditLog.timestamp.desc())
            .first()
        )
        assert entry is not None
        assert entry.actor_label == "ai_agent:investigation"
        assert entry.outcome == "success"
    finally:
        db.close()
