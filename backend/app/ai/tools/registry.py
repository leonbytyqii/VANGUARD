"""
The AI tool registry. This is the enforcement boundary described in
docs/ARCHITECTURE.md §6 and docs/SECURITY.md: **an AI agent can only ever
call a function that appears in TOOL_REGISTRY, and TOOL_REGISTRY contains
zero `privileged_action` tools.** Isolating a host, disabling an account,
blocking an IP, revoking cloud credentials — none of those are reachable
through this dispatch path no matter what an agent (or a prompt-injected
attacker controlling agent input) asks for. They exist only as
PRIVILEGED_ACTION_CATALOG entries, which is metadata used to validate
human-submitted / human-approved response actions in
app/api/v1/response.py — not something any tool-calling code path can
invoke.

Handlers here are intentionally simple, real DB-backed implementations
(not mocks) even though the tables they read are still mostly empty until
Phase 3 (ingestion) and Phase 4 (detection) land — the point of Phase 2 is
proving the permission boundary works, and it's easiest to trust that proof
against a real query path rather than a stub that always returns {}.

`get_process_tree`, `get_network_connections`, `map_mitre_technique`, and
`search_by_technique` were added in Phase 8 — the growth docs/ARCHITECTURE.md
§4.2's agent-roster table already promised the Investigation and Threat
Hunt Agents for "Phase 7/8". All four are `read_only`, tenant-scoped via a
join through `events.organization_id` (Process/NetworkConnection have no
`organization_id` column of their own — see app/models/event.py — so
scoping through the Event they were derived from, rather than their
nullable `host_id`, is what actually prevents a cross-tenant read).

`check_related_incidents` was added in Phase 9 — likewise the growth §4.2
promised the Response Agent. It is `read_only` despite belonging to the
one agent whose ceiling is `propose_only`: reading the incident queue is
not a proposal, and classifying it by the agent that happens to own it
rather than by what it does would weaken the effect-ceiling check into a
tautology.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Callable

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.enums import ActionEffect
from app.models.event import Event, NetworkConnection, Process
from app.models.host import Host
from app.models.mitre import MitreTechnique


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    effect: ActionEffect
    description: str
    handler: Callable[..., dict[str, Any]]
    # JSON-schema `parameters` object for the tool-calling function
    # signature offered to a real LLM provider
    # (app/ai/providers/openai_compatible.py). Permissive by default —
    # the actual safety boundary is TOOL_REGISTRY membership + the agent
    # allowlist + effect ceiling (app/ai/agents/permissions.py), not
    # parameter-schema strictness, so most tools just document their
    # kwargs here for a real model's benefit rather than hand-authoring
    # exhaustive per-field schemas.
    parameters: dict[str, Any] = field(default_factory=lambda: {"type": "object", "additionalProperties": True})


def _get_alert(db: Session, organization_id: uuid.UUID, *, alert_id: str, **_) -> dict[str, Any]:
    alert = (
        db.query(Alert)
        .filter(Alert.id == uuid.UUID(alert_id), Alert.organization_id == organization_id)
        .one_or_none()
    )
    if alert is None:
        return {"found": False, "alert_id": alert_id}
    return {
        "found": True,
        "alert_id": str(alert.id),
        "title": alert.title,
        "severity": alert.severity,
        "risk_score": alert.risk_score,
        "status": alert.status,
        "host_name": alert.host_name,
        "user": alert.user,
    }


def _search_events(
    db: Session,
    organization_id: uuid.UUID,
    *,
    host_name: str | None = None,
    user: str | None = None,
    process: str | None = None,
    src_ip: str | None = None,
    since_hours: int = 72,
    limit: int = 25,
    **_,
) -> dict[str, Any]:
    # Default to a 72-hour lookback so investigations are scoped to recent
    # context rather than scanning the entire event table, which can be large
    # on a long-running deployment. The agent can pass a larger since_hours
    # (up to 720 = 30 days) for wider historical searches.
    from datetime import datetime, timedelta, timezone
    cutoff = datetime.now(timezone.utc) - timedelta(hours=min(max(since_hours, 1), 720))

    q = db.query(Event).filter(
        Event.organization_id == organization_id,
        Event.event_timestamp >= cutoff,
    )
    if host_name:
        q = q.filter(Event.host_name_raw == host_name)
    if user:
        q = q.filter(Event.user == user)
    if process:
        q = q.filter(Event.process == process)
    if src_ip:
        q = q.filter(Event.src_ip == src_ip)
    rows = q.order_by(Event.event_timestamp.desc()).limit(min(limit, 100)).all()
    return {
        "count": len(rows),
        "events": [
            {
                "event_id": str(e.id),
                "timestamp": e.event_timestamp.isoformat(),
                "category": e.category,
                "process": e.process,
                "parent_process": e.parent_process,
                "user": e.user,
                "host": e.host_name_raw,
            }
            for e in rows
        ],
    }


def _get_host_info(db: Session, organization_id: uuid.UUID, *, hostname: str, **_) -> dict[str, Any]:
    host = (
        db.query(Host)
        .filter(Host.hostname == hostname, Host.organization_id == organization_id)
        .one_or_none()
    )
    if host is None:
        return {"found": False, "hostname": hostname}
    return {
        "found": True,
        "hostname": host.hostname,
        "ip_address": host.ip_address,
        "os_family": host.os_family,
        "criticality": host.criticality,
    }


def _enrich_ioc(db: Session, organization_id: uuid.UUID, *, ioc_type: str, value: str, **_) -> dict[str, Any]:
    """
    read_only. Phase 10 replaced the Phase 2 stub with the real
    enrichment service.

    Two properties matter for an agent-callable tool:

    * **It never force-refreshes.** An agent loop can call a tool many
      times per investigation; letting it bypass the cache would hand a
      model the ability to burn a paid, shared, rate-limited provider
      quota. Cache bypass stays a human decision behind
      `threat_intel.manage`.
    * **It returns `unknown` rather than raising** when the value is
      malformed, because the agent loop only catches
      `ToolPermissionError` — anything else would abort the whole
      investigation instead of becoming a correctable tool result.

    The IOC row it creates is real and tenant-scoped, so a claim the
    agent grounds in this tool resolves to an actual database row, same
    as every other evidence source.
    """
    from app.services.threat_intel import ThreatIntelError, lookup_and_enrich

    try:
        ioc, from_cache = lookup_and_enrich(
            db, organization_id=organization_id, ioc_type=ioc_type, value=value, force_refresh=False
        )
    except ThreatIntelError as exc:
        return {"ioc_type": ioc_type, "value": value, "reputation": "unknown", "error": str(exc)}

    return {
        "ioc_id": str(ioc.id),
        "ioc_type": ioc.ioc_type,
        "value": ioc.value,
        "reputation": ioc.reputation,
        "threat_score": ioc.threat_score,
        "from_cache": from_cache,
        "providers": [
            {"provider": e.provider, "reputation": e.reputation, "confidence": e.confidence, "failed": e.lookup_failed}
            for e in ioc.enrichments
        ],
    }


def _get_process_tree(db: Session, organization_id: uuid.UUID, *, hostname: str, limit: int = 50, **_) -> dict[str, Any]:
    rows = (
        db.query(Process)
        .join(Event, Process.event_id == Event.id)
        .filter(Event.organization_id == organization_id, Event.host_name_raw == hostname)
        .order_by(Process.process_timestamp.desc())
        .limit(min(limit, 100))
        .all()
    )
    return {
        "hostname": hostname,
        "count": len(rows),
        "processes": [
            {
                "process_name": p.process_name,
                "parent_process_name": p.parent_process_name,
                "command_line": p.command_line,
                "user": p.user,
                "timestamp": p.process_timestamp.isoformat(),
            }
            for p in rows
        ],
    }


def _get_network_connections(
    db: Session,
    organization_id: uuid.UUID,
    *,
    hostname: str | None = None,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    limit: int = 50,
    **_,
) -> dict[str, Any]:
    q = db.query(NetworkConnection).join(Event, NetworkConnection.event_id == Event.id).filter(
        Event.organization_id == organization_id
    )
    if hostname:
        q = q.filter(Event.host_name_raw == hostname)
    if src_ip:
        q = q.filter(NetworkConnection.src_ip == src_ip)
    if dst_ip:
        q = q.filter(NetworkConnection.dst_ip == dst_ip)
    rows = q.order_by(NetworkConnection.connection_timestamp.desc()).limit(min(limit, 100)).all()
    return {
        "count": len(rows),
        "connections": [
            {
                "src_ip": c.src_ip,
                "dst_ip": c.dst_ip,
                "src_port": c.src_port,
                "dst_port": c.dst_port,
                "protocol": c.protocol,
                "process_name": c.process_name,
                "timestamp": c.connection_timestamp.isoformat(),
            }
            for c in rows
        ],
    }


def _map_mitre_technique(db: Session, organization_id: uuid.UUID, *, technique_id: str, **_) -> dict[str, Any]:
    """MitreTechnique is shared reference data (Phase 6), not tenant-scoped — same posture as app/api/v1/mitre.py."""
    technique = db.query(MitreTechnique).filter(MitreTechnique.technique_id == technique_id).one_or_none()
    if technique is None:
        return {"found": False, "technique_id": technique_id}
    return {
        "found": True,
        "technique_id": technique.technique_id,
        "name": technique.name,
        "tactic_name": technique.tactic.name if technique.tactic else None,
        "is_subtechnique": technique.is_subtechnique,
    }


def _search_by_technique(db: Session, organization_id: uuid.UUID, *, technique_id: str, limit: int = 25, **_) -> dict[str, Any]:
    """The Threat Hunt Agent's 'has this happened elsewhere?' pivot (docs/ARCHITECTURE.md §4.2) — every alert this org has that's tagged with the given technique, via the relational tagging Phase 6 built."""
    technique = db.query(MitreTechnique).filter(MitreTechnique.technique_id == technique_id).one_or_none()
    if technique is None:
        return {"found": False, "technique_id": technique_id, "alerts": []}

    alerts = (
        db.query(Alert)
        .filter(Alert.organization_id == organization_id, Alert.mitre_techniques.any(MitreTechnique.id == technique.id))
        .order_by(Alert.alert_timestamp.desc())
        .limit(min(limit, 100))
        .all()
    )
    return {
        "found": True,
        "technique_id": technique_id,
        "count": len(alerts),
        "alerts": [
            {
                "alert_id": str(a.id),
                "title": a.title,
                "host_name": a.host_name,
                "user": a.user,
                "severity": a.severity,
                "alert_timestamp": a.alert_timestamp.isoformat(),
            }
            for a in alerts
        ],
    }


def _draft_containment_plan(
    db: Session, organization_id: uuid.UUID, *, target: str, action_type: str, reasoning: str, **_
) -> dict[str, Any]:
    """
    propose_only: returns a recommendation object. Does not create a
    ResponseAction row and has no side effects — see `request_response_approval`
    for the tool that actually files a request.
    """
    return {
        "action_type": action_type,
        "target": target,
        "reasoning": reasoning,
        "requires_approval": True,
    }


def _request_response_approval(
    db: Session,
    organization_id: uuid.UUID,
    *,
    action_type: str,
    target: str,
    justification: str,
    agent_type: str,
    investigation_id: str | None = None,
    incident_id: str | None = None,
    **_,
) -> dict[str, Any]:
    """
    propose_only: creates a *pending* ResponseAction. This is the only way
    an agent can move a containment idea into the system, and it never
    results in execution by itself — see app/services/response_actions.py.
    """
    from app.services.response_actions import create_response_action_request

    action = create_response_action_request(
        db,
        organization_id=organization_id,
        action_type=action_type,
        target=target,
        justification=justification,
        requested_by_agent_type=agent_type,
        investigation_id=uuid.UUID(investigation_id) if investigation_id else None,
        incident_id=uuid.UUID(incident_id) if incident_id else None,
    )
    return {"response_action_id": str(action.id), "status": action.status}


def _check_related_incidents(
    db: Session,
    organization_id: uuid.UUID,
    *,
    hostname: str | None = None,
    username: str | None = None,
    include_closed: bool = False,
    limit: int = 10,
    **_,
) -> dict[str, Any]:
    """
    read_only (Phase 9): "is this asset already part of an open case?"

    This is the growth docs/ARCHITECTURE.md §4.2 promised the Response
    Agent for Phase 9, and it exists to stop a specific, realistic failure
    mode: the agent proposing to isolate a host that a human analyst
    isolated forty minutes ago on an incident the agent could not see.
    Filing a duplicate containment request is not harmless — it costs a
    second human approval decision and muddies the case file.

    Matching is done through the incident's *linked alerts* rather than
    by string-searching titles and summaries. An incident is related to a
    host because an alert about that host is attached to it; free-text
    matching would let an unrelated case mentioning a hostname in prose
    masquerade as containment that already happened.

    Both parameters are optional at the signature level, and a call with
    neither returns a structured `error` rather than raising: the agent
    loop only catches `ToolPermissionError`, so a `TypeError` from a
    missing keyword would abort the whole investigation instead of
    becoming a tool result the model can correct from.
    """
    from app.models.enums import IncidentStatus
    from app.models.incident import Incident, incident_alerts

    if not hostname and not username:
        return {"error": "check_related_incidents requires at least one of 'hostname' or 'username'."}

    criteria = []
    if hostname:
        criteria.append(Alert.host_name == hostname)
    if username:
        criteria.append(Alert.user == username)

    q = (
        db.query(Incident)
        .join(incident_alerts, incident_alerts.c.incident_id == Incident.id)
        .join(Alert, Alert.id == incident_alerts.c.alert_id)
        .filter(Incident.organization_id == organization_id, or_(*criteria))
    )
    if not include_closed:
        q = q.filter(Incident.status != IncidentStatus.CLOSED.value)

    incidents = q.distinct().order_by(Incident.created_at.desc()).limit(min(limit, 50)).all()

    return {
        "count": len(incidents),
        "queried": {"hostname": hostname, "username": username, "include_closed": include_closed},
        "incidents": [
            {
                "incident_id": str(i.id),
                "reference": f"INC-{i.incident_number:06d}" if i.incident_number is not None else None,
                "title": i.title,
                "status": i.status,
                "severity": i.severity,
                "contained_at": i.contained_at.isoformat() if i.contained_at else None,
                "assigned": i.assigned_to_id is not None,
            }
            for i in incidents
        ],
    }


TOOL_REGISTRY: dict[str, ToolDefinition] = {
    "get_alert": ToolDefinition(
        "get_alert", ActionEffect.READ_ONLY, "Fetch an alert by id.", _get_alert,
        parameters={"type": "object", "properties": {"alert_id": {"type": "string"}}, "required": ["alert_id"]},
    ),
    "search_events": ToolDefinition(
        "search_events", ActionEffect.READ_ONLY,
        "Search normalized events by host/user/process/ip within a lookback window (default 72h, max 720h).",
        _search_events,
        parameters={
            "type": "object",
            "properties": {
                "host_name": {"type": "string"},
                "user": {"type": "string"},
                "process": {"type": "string"},
                "src_ip": {"type": "string"},
                "since_hours": {"type": "integer", "description": "How far back to look (1–720). Default 72."},
                "limit": {"type": "integer"},
            },
        },
    ),
    "get_host_info": ToolDefinition(
        "get_host_info", ActionEffect.READ_ONLY, "Fetch host metadata.", _get_host_info,
        parameters={"type": "object", "properties": {"hostname": {"type": "string"}}, "required": ["hostname"]},
    ),
    "enrich_ioc": ToolDefinition(
        "enrich_ioc", ActionEffect.READ_ONLY, "Look up IOC reputation.", _enrich_ioc,
        parameters={
            "type": "object",
            "properties": {"ioc_type": {"type": "string", "enum": ["ip", "domain", "url", "file_hash"]}, "value": {"type": "string"}},
            "required": ["ioc_type", "value"],
        },
    ),
    "get_process_tree": ToolDefinition(
        "get_process_tree", ActionEffect.READ_ONLY,
        "Fetch recent process-creation lineage (process/parent_process/command_line) for a host.", _get_process_tree,
        parameters={
            "type": "object",
            "properties": {"hostname": {"type": "string"}, "limit": {"type": "integer"}},
            "required": ["hostname"],
        },
    ),
    "get_network_connections": ToolDefinition(
        "get_network_connections", ActionEffect.READ_ONLY,
        "Fetch recent network connections, optionally filtered by host/source IP/destination IP.",
        _get_network_connections,
        parameters={
            "type": "object",
            "properties": {
                "hostname": {"type": "string"}, "src_ip": {"type": "string"}, "dst_ip": {"type": "string"},
                "limit": {"type": "integer"},
            },
        },
    ),
    "map_mitre_technique": ToolDefinition(
        "map_mitre_technique", ActionEffect.READ_ONLY,
        "Look up a MITRE ATT&CK technique's name and parent tactic by technique ID.", _map_mitre_technique,
        parameters={"type": "object", "properties": {"technique_id": {"type": "string"}}, "required": ["technique_id"]},
    ),
    "search_by_technique": ToolDefinition(
        "search_by_technique", ActionEffect.READ_ONLY,
        "Find every alert in this organization tagged with a given MITRE technique — 'has this happened elsewhere?'.",
        _search_by_technique,
        parameters={
            "type": "object",
            "properties": {"technique_id": {"type": "string"}, "limit": {"type": "integer"}},
            "required": ["technique_id"],
        },
    ),
    "draft_containment_plan": ToolDefinition(
        "draft_containment_plan", ActionEffect.PROPOSE_ONLY, "Draft (do not file) a containment recommendation.",
        _draft_containment_plan,
        parameters={
            "type": "object",
            "properties": {"target": {"type": "string"}, "action_type": {"type": "string"}, "reasoning": {"type": "string"}},
            "required": ["target", "action_type", "reasoning"],
        },
    ),
    "request_response_approval": ToolDefinition(
        "request_response_approval", ActionEffect.PROPOSE_ONLY,
        "File a pending, human-approvable response action request.", _request_response_approval,
        parameters={
            "type": "object",
            "properties": {
                "action_type": {"type": "string"}, "target": {"type": "string"}, "justification": {"type": "string"},
                "investigation_id": {"type": "string"}, "incident_id": {"type": "string"},
            },
            "required": ["action_type", "target", "justification"],
        },
    ),
    "check_related_incidents": ToolDefinition(
        "check_related_incidents", ActionEffect.READ_ONLY,
        "Check whether a host or user is already part of an existing incident before proposing containment.",
        _check_related_incidents,
        parameters={
            "type": "object",
            "properties": {
                "hostname": {"type": "string"},
                "username": {"type": "string"},
                "include_closed": {"type": "boolean"},
                "limit": {"type": "integer"},
            },
        },
    ),
}


# Reference catalog only — deliberately NOT dispatchable through
# invoke_agent_tool(). Used to validate action_type on human-submitted /
# human-approved response actions (app/api/v1/response.py) so the set of
# "things that could ever happen" is centrally defined, without making any
# of them callable by an agent.
PRIVILEGED_ACTION_CATALOG: dict[str, str] = {
    "isolate_host": "Disconnect a host from the network except for management traffic.",
    "disable_account": "Disable a user or service account.",
    "block_ip": "Add an IP address to the network block list.",
    "block_domain": "Add a domain to the DNS/proxy block list.",
    "revoke_cloud_credentials": "Revoke active sessions/keys for a cloud identity.",
}


# ---------------------------------------------------------------------------
# Phase 11: cloud / IAM tools for the Cloud/IAM Agent
# ---------------------------------------------------------------------------


def _get_cloud_identity(db: Session, organization_id: uuid.UUID, *, identity_name: str, account_id: str | None = None, **_) -> dict[str, Any]:
    """read_only. Resolve one cloud identity the platform has observed acting."""
    from app.models.cloud import CloudIdentity

    q = db.query(CloudIdentity).filter(
        CloudIdentity.organization_id == organization_id,
        CloudIdentity.identity_name == identity_name,
    )
    if account_id:
        q = q.filter(CloudIdentity.account_id == account_id)
    identity = q.one_or_none()
    if identity is None:
        return {"found": False, "identity_name": identity_name}
    return {
        "found": True,
        "identity_name": identity.identity_name,
        "identity_type": identity.identity_type,
        "account_id": identity.account_id,
        "arn": identity.arn,
        # Flagged as a naming heuristic in the payload itself, so a model
        # summarising this cannot honestly report it as a policy fact.
        "is_privileged_heuristic": identity.is_privileged,
        "first_seen_at": identity.first_seen_at.isoformat() if identity.first_seen_at else None,
        "last_seen_at": identity.last_seen_at.isoformat() if identity.last_seen_at else None,
    }


def _get_role_assumptions(db: Session, organization_id: uuid.UUID, *, identity_name: str, limit: int = 25, **_) -> dict[str, Any]:
    """read_only. Every AssumeRole this identity performed, oldest first — the raw material of an attack path."""
    from app.cloud_iam.attack_paths import scoped_cloud_events
    from app.models.cloud import CloudEvent

    rows = (
        scoped_cloud_events(db, organization_id)
        .filter(CloudEvent.actor_identity == identity_name, CloudEvent.event_name.ilike("assumerole"))
        .order_by(CloudEvent.event_timestamp.asc())
        .limit(min(limit, 100))
        .all()
    )
    return {
        "identity_name": identity_name,
        "count": len(rows),
        "assumptions": [
            {
                "cloud_event_id": str(r.id),
                "event_id": str(r.event_id) if r.event_id else None,
                "assumed_role_arn": r.assumed_role_arn,
                "timestamp": r.event_timestamp.isoformat(),
                "source_ip": r.source_ip,
                "error_code": r.error_code,
            }
            for r in rows
        ],
    }


def _search_cloud_events(
    db: Session,
    organization_id: uuid.UUID,
    *,
    actor: str | None = None,
    event_name: str | None = None,
    account_id: str | None = None,
    errors_only: bool = False,
    limit: int = 25,
    **_,
) -> dict[str, Any]:
    """read_only. Tenant-scoped through the originating `events` row, never on account_id alone."""
    from app.cloud_iam.attack_paths import scoped_cloud_events
    from app.models.cloud import CloudEvent

    q = scoped_cloud_events(db, organization_id)
    if actor:
        q = q.filter(CloudEvent.actor_identity == actor)
    if event_name:
        q = q.filter(CloudEvent.event_name == event_name)
    if account_id:
        q = q.filter(CloudEvent.account_id == account_id)
    if errors_only:
        q = q.filter(CloudEvent.error_code.isnot(None))
    rows = q.order_by(CloudEvent.event_timestamp.desc()).limit(min(limit, 100)).all()
    return {
        "count": len(rows),
        "events": [
            {
                "cloud_event_id": str(r.id),
                "event_id": str(r.event_id) if r.event_id else None,
                "timestamp": r.event_timestamp.isoformat(),
                "event_name": r.event_name,
                "actor": r.actor_identity,
                "assumed_role_arn": r.assumed_role_arn,
                "account_id": r.account_id,
                "source_ip": r.source_ip,
                "error_code": r.error_code,
            }
            for r in rows
        ],
    }


TOOL_REGISTRY["get_cloud_identity"] = ToolDefinition(
    "get_cloud_identity", ActionEffect.READ_ONLY,
    "Look up a cloud/IAM identity the platform has observed acting.", _get_cloud_identity,
    parameters={
        "type": "object",
        "properties": {"identity_name": {"type": "string"}, "account_id": {"type": "string"}},
        "required": ["identity_name"],
    },
)
TOOL_REGISTRY["get_role_assumptions"] = ToolDefinition(
    "get_role_assumptions", ActionEffect.READ_ONLY,
    "List every AssumeRole performed by a cloud identity.", _get_role_assumptions,
    parameters={
        "type": "object",
        "properties": {"identity_name": {"type": "string"}, "limit": {"type": "integer"}},
        "required": ["identity_name"],
    },
)
TOOL_REGISTRY["search_cloud_events"] = ToolDefinition(
    "search_cloud_events", ActionEffect.READ_ONLY,
    "Search normalized CloudTrail-style events by actor, event name, or account.", _search_cloud_events,
    parameters={
        "type": "object",
        "properties": {
            "actor": {"type": "string"}, "event_name": {"type": "string"},
            "account_id": {"type": "string"}, "errors_only": {"type": "boolean"}, "limit": {"type": "integer"},
        },
    },
)
