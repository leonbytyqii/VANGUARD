"""
Agent identity resolution + enforced tool dispatch.

This is the function every agent implementation (Phase 8) will call
instead of ever invoking a tool handler directly:

    invoke_agent_tool(db, agent_type=AgentType.INVESTIGATION, tool_name="search_events", ...)

It enforces, in order:
1. The agent identity exists, is enabled, in the database (not just a
   string constant in code — an admin can disable an agent type at
   runtime via `admin.agents`).
2. The requested tool exists in TOOL_REGISTRY at all. Privileged actions
   never do (see app/ai/tools/registry.py), so this alone makes them
   unreachable regardless of what any other check says.
3. The tool is in *this specific agent's* `allowed_tools` allowlist — a
   Triage Agent cannot call `request_response_approval` even though that
   tool exists and is only propose_only, because triage was never granted
   it. This is the "specialized agents get narrow scopes" guarantee.
4. The tool's effect classification does not exceed the agent's
   `max_effect` ceiling (defense in depth vs. #3 — protects against a
   future bug where an agent's allowlist is misconfigured to include a
   tool riskier than its intended ceiling).

Every denial is audited via app.services.audit with action
"ai_tool_permission_denied" so a SOC Manager reviewing the audit log can
see exactly which agent tried to do what and why it was refused.
"""
from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.orm import Session

from app.ai.tools.registry import TOOL_REGISTRY
from app.models.agent_identity import AgentIdentity
from app.models.enums import ActionEffect, AgentType
from app.services.audit import log_audit_event

_EFFECT_ORDER = {
    ActionEffect.READ_ONLY: 0,
    ActionEffect.PROPOSE_ONLY: 1,
    ActionEffect.PRIVILEGED_ACTION: 2,
}

# Source of truth for what gets seeded into agent_identities (app/db/seed.py)
# and re-validated at dispatch time. Kept in code (not only in the DB) so
# it's reviewable in a diff/PR like any other security control.
#
# Phase 8 additions match exactly what docs/ARCHITECTURE.md §4.2's agent-
# roster table already promised each agent would grow into: the
# Investigation Agent gains get_process_tree/get_network_connections/
# map_mitre_technique, and the Threat Hunt Agent gains search_by_technique.
AGENT_TOOL_ALLOWLIST: dict[AgentType, list[str]] = {
    AgentType.TRIAGE: ["get_alert", "search_events", "get_host_info"],
    AgentType.INVESTIGATION: [
        "get_alert", "search_events", "get_host_info", "enrich_ioc",
        "get_process_tree", "get_network_connections", "map_mitre_technique",
    ],
    AgentType.THREAT_HUNT: ["search_events", "enrich_ioc", "search_by_technique"],
    # Phase 11 delivers exactly the three tools ARCHITECTURE.md §4.2
    # promised this agent. All read_only: reconstructing an identity chain
    # is analysis over telemetry already ingested, and nothing here can
    # touch a cloud account.
    AgentType.CLOUD_IAM: [
        "search_events", "get_host_info",
        "get_cloud_identity", "get_role_assumptions", "search_cloud_events",
    ],
    # Phase 9 grants the Response Agent `check_related_incidents` — the exact
    # growth docs/ARCHITECTURE.md §4.2 promised it. It is `read_only`, well
    # under this agent's `propose_only` ceiling, and it is granted to *only*
    # this agent: knowing which cases are already open is a response-planning
    # concern, and widening it to Triage would hand the cheapest, most
    # frequently-run agent a view of the whole incident queue for no
    # investigative gain.
    AgentType.RESPONSE: ["draft_containment_plan", "request_response_approval", "check_related_incidents"],
}

AGENT_MAX_EFFECT: dict[AgentType, ActionEffect] = {
    AgentType.TRIAGE: ActionEffect.READ_ONLY,
    AgentType.INVESTIGATION: ActionEffect.READ_ONLY,
    AgentType.THREAT_HUNT: ActionEffect.READ_ONLY,
    AgentType.CLOUD_IAM: ActionEffect.READ_ONLY,
    AgentType.RESPONSE: ActionEffect.PROPOSE_ONLY,  # never privileged_action, for any agent, ever
}


class ToolPermissionError(Exception):
    def __init__(self, message: str, *, reason: str):
        self.reason = reason
        super().__init__(message)


def invoke_agent_tool(
    db: Session,
    *,
    agent_type: AgentType,
    tool_name: str,
    organization_id: uuid.UUID,
    source_ip: str | None = None,
    **tool_kwargs: Any,
) -> dict[str, Any]:
    identity = db.query(AgentIdentity).filter(AgentIdentity.agent_type == agent_type.value).one_or_none()

    def _deny(reason: str, message: str) -> None:
        log_audit_event(
            db,
            action="ai_tool_permission_denied",
            actor_label=f"ai_agent:{agent_type.value}",
            resource_type="ai_tool",
            resource_id=tool_name,
            outcome="denied",
            source_ip=source_ip,
            details={"reason": reason, "agent_type": agent_type.value},
        )
        raise ToolPermissionError(message, reason=reason)

    if identity is None or not identity.enabled:
        _deny("agent_identity_disabled_or_missing", f"Agent identity '{agent_type.value}' is not enabled.")

    tool = TOOL_REGISTRY.get(tool_name)
    if tool is None:
        # Includes the case where tool_name is a privileged action
        # (isolate_host, disable_account, ...) — those are simply never in
        # this registry, so "not found" and "not permitted" are the same
        # code path for anything privileged.
        _deny("tool_not_registered", f"Tool '{tool_name}' is not an available AI tool.")

    if tool_name not in identity.allowed_tools:
        _deny("tool_not_in_agent_allowlist", f"Agent '{agent_type.value}' is not permitted to call '{tool_name}'.")

    if _EFFECT_ORDER[tool.effect] > _EFFECT_ORDER[ActionEffect(identity.max_effect)]:
        _deny(
            "tool_effect_exceeds_agent_ceiling",
            f"Tool '{tool_name}' effect '{tool.effect.value}' exceeds agent max effect '{identity.max_effect}'.",
        )

    result = tool.handler(db, organization_id, agent_type=agent_type.value, **tool_kwargs)

    log_audit_event(
        db,
        action="ai_tool_invoked",
        actor_label=f"ai_agent:{agent_type.value}",
        resource_type="ai_tool",
        resource_id=tool_name,
        outcome="success",
        source_ip=source_ip,
        details={"agent_type": agent_type.value},
    )
    return result
