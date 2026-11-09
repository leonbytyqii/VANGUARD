"""
The agentic AI SOC Analyst (Phase 8): the Triage -> Investigation ->
handoff orchestrator, the MockProvider offline-safe LLM stand-in, the
evidence-citation "never fabricate" gate, tool-permission enforcement for
the new Phase 8 tools, SOC Blueprint matching, and the /api/v1/ai/*
RBAC/IDOR-gated API.
"""
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.ai.agents.permissions import ToolPermissionError, invoke_agent_tool
from app.ai.orchestrator import run_investigation
from app.ai.providers.base import ProviderResponse
from app.core.config import settings
from app.db.session import SessionLocal
from app.models.ai import AIInvestigation
from app.models.alert import Alert
from app.models.automation import ResponseAction, SOCBlueprint
from app.models.enums import AgentType
from tests.factories import auth_headers, create_organization, create_user

_BASE_TIME = datetime.now(timezone.utc)


def _ts(offset_minutes: float = 0) -> str:
    return (_BASE_TIME + timedelta(minutes=offset_minutes)).isoformat()


def _ingest(client, headers, body):
    resp = client.post("/api/v1/events", headers=headers, json=body)
    assert resp.status_code == 201, resp.text
    return resp.json()


def _encoded_powershell_event(host, user="alice", offset_minutes=0):
    return {
        "source": "windows_sysmon",
        "timestamp": _ts(offset_minutes),
        "host": host,
        "user": user,
        "event_type": "process_creation",
        "process": "powershell.exe",
        "command_line": "powershell.exe -enc SQBFAFgA==",
    }


def _get_alerts(client, headers, **params):
    resp = client.get("/api/v1/alerts", headers=headers, params=params)
    assert resp.status_code == 200, resp.text
    return resp.json()


def _create_low_risk_alert(org_id, *, host_name="LOWRISK-01", user="carol") -> Alert:
    db = SessionLocal()
    try:
        alert = Alert(
            organization_id=org_id,
            title="Benign anomaly",
            description="Below the investigation threshold.",
            severity="INFO",
            risk_score=5,
            status="new",
            source="manual_test",
            host_name=host_name,
            user=user,
            alert_timestamp=datetime.now(timezone.utc),
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        return alert
    finally:
        db.close()


# --- full pipeline, via the real API, driven by MockProvider ---


def test_full_investigation_pipeline_runs_triage_investigation_and_handoffs(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, admin_pw)

    _ingest(client, headers, _encoded_powershell_event("AI-FULL-01"))
    alerts = _get_alerts(client, headers, host="AI-FULL-01")
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["severity"] == "HIGH"

    resp = client.post("/api/v1/ai/investigations", headers=headers, json={"alert_id": alert["id"]})
    assert resp.status_code == 201, resp.text
    investigation = resp.json()
    assert investigation["status"] == "completed"
    assert investigation["error"] is None
    assert investigation["ai_provider"] == "mock"
    assert investigation["ai_model"] == "mock-deterministic-analyst"

    result = investigation["result"]
    assert result["severity"] == "HIGH"
    assert result["observed_evidence"], "expected at least one grounded evidence item"
    # Every event-level citation must resolve to a real event id this
    # session actually retrieved via search_events — the exact thing the
    # evidence-validation gate in app/ai/orchestrator.py checks.
    event_citations = [e for e in result["observed_evidence"] if e["source_event_id"]]
    assert event_citations
    assert result["mitre_attack"], "the firing rule is MITRE-tagged, so a technique should have been mapped"
    assert result["mitre_attack"][0]["technique_id"] in {"T1059.001", "T1027"}
    # HIGH severity + a known host_name -> the mock always recommends isolation.
    assert any(c["action"] == "isolate_host" for c in result["recommended_containment"])
    assert all(c["requires_approval"] is True for c in result["recommended_containment"])

    steps_resp = client.get(f"/api/v1/ai/investigations/{investigation['id']}/steps", headers=headers)
    assert steps_resp.status_code == 200, steps_resp.text
    steps = steps_resp.json()
    step_numbers = [s["step_number"] for s in steps]
    assert step_numbers == sorted(step_numbers)
    assert step_numbers == list(range(1, len(steps) + 1)), "one monotonic sequence across every phase"

    agent_types_seen = {s["agent_type"] for s in steps}
    assert "triage" in agent_types_seen
    assert "investigation" in agent_types_seen
    assert "threat_hunt" in agent_types_seen, "a MITRE-tagged result should trigger the threat-hunt handoff"
    assert "response" in agent_types_seen, "a recommended containment action should trigger the response handoff"

    conclude_steps = [s for s in steps if s["action"] == "conclude" and s["agent_type"] == "investigation"]
    assert len(conclude_steps) == 1
    assert conclude_steps[0]["evidence"], "the concluding investigation step should have persisted AgentEvidence rows"

    # The response handoff must have actually filed a real, pending
    # ResponseAction reachable through the existing human-approval API —
    # never executed, never auto-approved.
    actions_resp = client.get("/api/v1/response/actions", headers=headers)
    assert actions_resp.status_code == 200
    actions = [a for a in actions_resp.json() if a["action_type"] == "isolate_host" and a["target"] == "AI-FULL-01"]
    assert len(actions) == 1
    action = actions[0]
    assert action["status"] == "pending"
    assert action["requested_by_agent_type"] == "response"

    db = SessionLocal()
    try:
        db_action = db.query(ResponseAction).filter(ResponseAction.id == uuid.UUID(action["id"])).one()
        assert str(db_action.investigation_id) == investigation["id"]
    finally:
        db.close()

    approve_resp = client.patch(f"/api/v1/response/actions/{action['id']}/approve", headers=headers)
    assert approve_resp.status_code == 200, approve_resp.text
    assert approve_resp.json()["status"] == "approved"


# --- triage short-circuit ---


def test_low_risk_alert_short_circuits_at_triage(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, admin_pw)

    alert = _create_low_risk_alert(org.id)

    resp = client.post("/api/v1/ai/investigations", headers=headers, json={"alert_id": str(alert.id)})
    assert resp.status_code == 201, resp.text
    investigation = resp.json()
    assert investigation["status"] == "completed"
    assert investigation["result"]["triage_only"] is True
    assert investigation["result"]["triage"]["proceed"] is False

    steps_resp = client.get(f"/api/v1/ai/investigations/{investigation['id']}/steps", headers=headers)
    steps = steps_resp.json()
    agent_types_seen = {s["agent_type"] for s in steps}
    assert agent_types_seen == {"triage"}, "triage-only should never reach the investigation/handoff phases"


# --- evidence-citation "never fabricate" gate ---


class _FabricatingProvider:
    """A stand-in for a compromised/hallucinating provider: always claims proceed, then always cites a real-looking but never-retrieved event id."""

    def complete(self, *, messages, tools, response_schema):
        if "proceed" in response_schema.get("properties", {}):
            return ProviderResponse(
                final_output={"proceed": True, "initial_severity": "HIGH", "confidence": 0.9, "reasoning": "fabricated"},
                reasoning_note="",
            )
        return ProviderResponse(
            final_output={
                "severity": "HIGH",
                "risk_score": 90,
                "confidence": 0.9,
                "summary": "A fabricated account of events that were never actually retrieved.",
                "observed_evidence": [
                    {
                        "claim": "A malicious process ran.",
                        "source_tool": "search_events",
                        "source_event_id": str(uuid.uuid4()),
                        "source_table": "events",
                        "confidence": 0.9,
                    }
                ],
                "hypotheses": [],
                "mitre_attack": [],
                "affected_assets": [],
                "recommended_investigation": [],
                "recommended_containment": [],
                "false_positive_indicators": [],
            },
            reasoning_note="",
        )


def test_evidence_validation_rejects_fabricated_event_citation(client, monkeypatch):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, admin_pw)

    _ingest(client, headers, _encoded_powershell_event("AI-FABRICATE-01"))
    alert = _get_alerts(client, headers, host="AI-FABRICATE-01")[0]

    monkeypatch.setattr("app.ai.orchestrator.get_provider", lambda: _FabricatingProvider())
    monkeypatch.setattr(settings, "AI_MAX_TOOL_ITERATIONS", 2)

    resp = client.post("/api/v1/ai/investigations", headers=headers, json={"alert_id": alert["id"]})
    assert resp.status_code == 201, resp.text
    investigation = resp.json()
    assert investigation["status"] == "failed"
    assert investigation["result"] is None
    assert "never actually retrieved" in investigation["error"] or "exceeded" in investigation["error"]

    steps_resp = client.get(f"/api/v1/ai/investigations/{investigation['id']}/steps", headers=headers)
    steps = steps_resp.json()
    rejected = [s for s in steps if s["action"] == "conclude_rejected"]
    assert rejected, "every fabricated submission should be persisted as a rejected step, not silently dropped"
    assert "never actually retrieved" in rejected[0]["tool_output"]["error"]


# --- tool-permission enforcement for the new Phase 8 tools ---


def test_investigation_agent_cannot_call_response_only_tool(db_session):
    org = create_organization()
    with pytest.raises(ToolPermissionError) as exc_info:
        invoke_agent_tool(
            db_session,
            agent_type=AgentType.INVESTIGATION,
            tool_name="request_response_approval",
            organization_id=org.id,
            action_type="isolate_host",
            target="HOST-X",
            justification="test",
        )
    assert exc_info.value.reason == "tool_not_in_agent_allowlist"


def test_response_agent_cannot_call_investigation_only_tool(db_session):
    org = create_organization()
    with pytest.raises(ToolPermissionError) as exc_info:
        invoke_agent_tool(
            db_session,
            agent_type=AgentType.RESPONSE,
            tool_name="get_process_tree",
            organization_id=org.id,
            hostname="HOST-X",
        )
    assert exc_info.value.reason == "tool_not_in_agent_allowlist"


def test_triage_agent_cannot_call_new_phase8_investigation_tools(db_session):
    org = create_organization()
    for tool_name, kwargs in (
        ("get_process_tree", {"hostname": "HOST-X"}),
        ("get_network_connections", {"hostname": "HOST-X"}),
        ("map_mitre_technique", {"technique_id": "T1059.001"}),
    ):
        with pytest.raises(ToolPermissionError) as exc_info:
            invoke_agent_tool(db_session, agent_type=AgentType.TRIAGE, tool_name=tool_name, organization_id=org.id, **kwargs)
        assert exc_info.value.reason == "tool_not_in_agent_allowlist"


def test_investigation_agent_can_call_its_new_phase8_tools(db_session):
    org = create_organization()
    result = invoke_agent_tool(
        db_session, agent_type=AgentType.INVESTIGATION, tool_name="map_mitre_technique",
        organization_id=org.id, technique_id="T1059.001",
    )
    assert result["found"] is True
    assert result["technique_id"] == "T1059.001"


def test_threat_hunt_agent_can_call_search_by_technique(db_session):
    org = create_organization()
    result = invoke_agent_tool(
        db_session, agent_type=AgentType.THREAT_HUNT, tool_name="search_by_technique",
        organization_id=org.id, technique_id="T1059.001",
    )
    assert result["found"] is True
    assert result["count"] == 0


def test_privileged_actions_are_unreachable_through_the_tool_gateway(db_session):
    """isolate_host/disable_account/etc. are never in TOOL_REGISTRY at all, for any agent — see app/ai/tools/registry.py."""
    org = create_organization()
    for agent_type in AgentType:
        with pytest.raises(ToolPermissionError) as exc_info:
            invoke_agent_tool(db_session, agent_type=agent_type, tool_name="isolate_host", organization_id=org.id, target="HOST-X")
        assert exc_info.value.reason in {"tool_not_registered", "agent_identity_disabled_or_missing"}


# --- SOC Blueprint matching ---


def test_matching_soc_blueprint_is_linked_and_its_checklist_reaches_the_provider(client, monkeypatch):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, admin_pw)

    db = SessionLocal()
    try:
        blueprint = SOCBlueprint(
            organization_id=org.id,
            name="Suspicious PowerShell Playbook",
            description="Starting checklist for encoded PowerShell alerts.",
            applies_to={"detection_rule": "sigma_suspicious_powershell_encoded"},
            suggested_steps=[{"description": "Confirm whether the encoded command decodes to something malicious."}],
            enabled=True,
        )
        db.add(blueprint)
        db.commit()
        db.refresh(blueprint)
        blueprint_id = blueprint.id
    finally:
        db.close()

    from app.ai.providers.mock import MockProvider

    recorded_messages: list[list[dict]] = []

    class _RecordingProvider(MockProvider):
        def complete(self, *, messages, tools, response_schema):
            recorded_messages.append(messages)
            return super().complete(messages=messages, tools=tools, response_schema=response_schema)

    monkeypatch.setattr("app.ai.orchestrator.get_provider", lambda: _RecordingProvider())

    _ingest(client, headers, _encoded_powershell_event("AI-BLUEPRINT-01"))
    alert = _get_alerts(client, headers, host="AI-BLUEPRINT-01")[0]

    resp = client.post("/api/v1/ai/investigations", headers=headers, json={"alert_id": alert["id"]})
    assert resp.status_code == 201, resp.text
    investigation = resp.json()
    assert investigation["blueprint_id"] == str(blueprint_id)

    checklist_messages = [
        m for batch in recorded_messages for m in batch if m.get("name") == "blueprint_checklist"
    ]
    assert checklist_messages, "the blueprint's checklist should have been included in at least one phase's transcript"
    assert "Suspicious PowerShell Playbook" in checklist_messages[0]["content"]
    assert "decodes to something malicious" in checklist_messages[0]["content"]


def test_non_matching_alert_leaves_blueprint_id_unset(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, admin_pw)

    db = SessionLocal()
    try:
        blueprint = SOCBlueprint(
            organization_id=org.id,
            name="Unrelated Blueprint",
            applies_to={"detection_rule": "some_other_rule_id"},
            suggested_steps=[],
            enabled=True,
        )
        db.add(blueprint)
        db.commit()
    finally:
        db.close()

    _ingest(client, headers, _encoded_powershell_event("AI-NOBLUEPRINT-01"))
    alert = _get_alerts(client, headers, host="AI-NOBLUEPRINT-01")[0]

    resp = client.post("/api/v1/ai/investigations", headers=headers, json={"alert_id": alert["id"]})
    assert resp.status_code == 201, resp.text
    assert resp.json()["blueprint_id"] is None


# --- RBAC / IDOR on /api/v1/ai/* ---


def test_viewer_can_read_but_not_trigger_investigations(client):
    org = create_organization()
    viewer, viewer_pw = create_user(org, role_name="viewer")
    headers = auth_headers(client, viewer.email, viewer_pw)

    alert = _create_low_risk_alert(org.id, host_name="AI-RBAC-01")

    list_resp = client.get("/api/v1/ai/investigations", headers=headers)
    assert list_resp.status_code == 200

    create_resp = client.post("/api/v1/ai/investigations", headers=headers, json={"alert_id": str(alert.id)})
    assert create_resp.status_code == 403


def test_create_investigation_404s_for_alert_in_another_organization(client):
    org_a = create_organization()
    org_b = create_organization()
    admin_a, admin_a_pw = create_user(org_a, role_name="admin", is_superuser=True)
    admin_b, admin_b_pw = create_user(org_b, role_name="admin", is_superuser=True)
    headers_b = auth_headers(client, admin_b.email, admin_b_pw)

    alert = _create_low_risk_alert(org_a.id, host_name="AI-IDOR-01")

    resp = client.post("/api/v1/ai/investigations", headers=headers_b, json={"alert_id": str(alert.id)})
    assert resp.status_code == 404


def test_investigation_retrieval_404s_across_organizations(client):
    org_a = create_organization()
    org_b = create_organization()
    admin_a, admin_a_pw = create_user(org_a, role_name="admin", is_superuser=True)
    admin_b, admin_b_pw = create_user(org_b, role_name="admin", is_superuser=True)
    headers_a = auth_headers(client, admin_a.email, admin_a_pw)
    headers_b = auth_headers(client, admin_b.email, admin_b_pw)

    alert = _create_low_risk_alert(org_a.id, host_name="AI-IDOR-02")
    resp = client.post("/api/v1/ai/investigations", headers=headers_a, json={"alert_id": str(alert.id)})
    assert resp.status_code == 201
    investigation_id = resp.json()["id"]

    cross_org_resp = client.get(f"/api/v1/ai/investigations/{investigation_id}", headers=headers_b)
    assert cross_org_resp.status_code == 404

    cross_org_steps_resp = client.get(f"/api/v1/ai/investigations/{investigation_id}/steps", headers=headers_b)
    assert cross_org_steps_resp.status_code == 404

    same_org_resp = client.get(f"/api/v1/ai/investigations/{investigation_id}", headers=headers_a)
    assert same_org_resp.status_code == 200


def test_create_investigation_404s_for_unknown_alert_id(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, admin_pw)

    resp = client.post("/api/v1/ai/investigations", headers=headers, json={"alert_id": str(uuid.uuid4())})
    assert resp.status_code == 404


# --- run_investigation never raises out to the caller ---


def test_run_investigation_never_raises_when_alert_belongs_to_another_organization():
    """
    alert_id carries a real FK constraint (a fully non-existent id can't
    even be inserted), so the realistic "not found" case this exercises is
    an AIInvestigation whose organization_id doesn't match its alert's —
    exactly what run_investigation's tenant-scoped lookup must still
    refuse to return, without ever raising out to the caller.
    """
    org_a = create_organization()
    org_b = create_organization()
    alert_in_org_b = _create_low_risk_alert(org_b.id, host_name="AI-CROSSORG-01")

    db = SessionLocal()
    try:
        investigation = AIInvestigation(
            organization_id=org_a.id,
            alert_id=alert_in_org_b.id,
            status="pending",
            ai_provider="mock",
            ai_model="mock-deterministic-analyst",
        )
        db.add(investigation)
        db.commit()
        db.refresh(investigation)

        result = run_investigation(db, investigation)
        assert result.status == "failed"
        assert "Alert not found" in result.error
    finally:
        db.close()
