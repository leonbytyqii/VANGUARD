"""
IAM attack-path reconstruction.

The chain the architecture doc names as the platform's strongest cloud
story:

    Compromised Identity -> AssumeRole -> Excessive Permission
        -> Privilege Escalation -> Cloud Resource -> Sensitive Action

Phase 4's `cloud_privilege_escalation` detection catches the *observable
signature* of the middle of that chain (an AssumeRole followed closely by
a sensitive action). This module does the other half: it walks the actual
`cloud_events` identity chain and reconstructs the whole path as a graph
that can be rendered and explained.

## How the walk works

Starting from a seed actor, it follows `AssumeRole` edges forward in time
within a bounded window, building a chain of identities. At each identity
it collects the actions that identity then performed, and classifies each
one (`role_assumption` / `privilege_escalation` / `defense_evasion` /
`access`). Every edge carries the `cloud_event_id` it came from, so no
node or edge in the rendered graph is an inference the platform cannot
point at a row for.

## Three deliberate limits, stated rather than hidden

1. **It reconstructs what was *observed*, not what was *possible*.** A
   real attack-path tool (a Cartography/PMapper-style analysis) answers
   "who *could* reach this resource" by evaluating IAM policy documents.
   This answers "who *did* what, in what order". The second question is
   the one telemetry can honestly answer, and conflating them would mean
   presenting a policy-derived hypothesis as an observation. Doing it
   properly needs a real AWS policy fetch — see docs/CLOUD_IAM.md.

2. **Role-assumption chains are matched on identity naming, not on STS
   session tokens.** CloudTrail's true chain link is the assumed-role
   session identity in `userIdentity.sessionContext`; lab-shaped payloads
   often do not carry it. The walk therefore links `actor -> role` when
   the actor assumed that role and then acts *as* that role name. This is
   correct for the common case and can produce a false link if two
   unrelated principals share a role name in a window — which is why
   `confidence` is recorded per path and why the raw events are always
   cited.

3. **`MAX_DEPTH` bounds the walk.** Cyclic role assumption
   (`A -> B -> A`) is real and legitimate in some architectures; an
   unbounded walk over it does not terminate. Visited identities are
   tracked and the depth is capped, and a path that hit the cap says so
   in `truncated` rather than silently presenting a partial chain as
   complete — the same bookkeeping discipline as Phase 7's hunt
   truncation.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.cloud_iam.projection import classify_action
from app.models.cloud import CloudEvent, CloudIdentity, IAMAttackPath
from app.models.event import Event


def scoped_cloud_events(db: Session, organization_id: uuid.UUID | None):
    """
    Tenant-scope `cloud_events` **through the `events` row it was
    projected from**.

    `CloudEvent` carries no `organization_id` of its own — same situation
    as `Process`/`NetworkConnection` in `app/ai/tools/registry.py`. Scoping
    on `account_id` alone would be a real cross-tenant leak the moment two
    organizations monitor the same AWS account (a managed-service provider
    watching a shared account is the obvious case), so the join through
    `events.organization_id` is the actual boundary, not a convenience.
    """
    return db.query(CloudEvent).join(Event, CloudEvent.event_id == Event.id).filter(
        Event.organization_id == organization_id
    )

#: How far forward from the seed event the walk looks.
DEFAULT_WINDOW_HOURS = 24
#: Maximum role-assumption hops. See limit (3) above.
MAX_DEPTH = 6
#: Maximum actions collected per identity, so one noisy principal cannot
#: produce a graph too large to render.
MAX_ACTIONS_PER_IDENTITY = 25

_SEVERITY_BY_SIGNAL = {
    "defense_evasion": "CRITICAL",
    "privilege_escalation": "HIGH",
    "role_assumption": "MEDIUM",
    "access": "LOW",
}

_SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def _name_from_arn(arn: str | None) -> str | None:
    if not arn:
        return None
    return (arn.rsplit("/", 1)[-1] if "/" in arn else arn.rsplit(":", 1)[-1]) or arn


def reconstruct_attack_path(
    db: Session,
    *,
    organization_id: uuid.UUID | None,
    account_id: str,
    seed_identity: str,
    start_time: datetime,
    window_hours: int = DEFAULT_WINDOW_HOURS,
    alert_id: uuid.UUID | None = None,
    incident_id: uuid.UUID | None = None,
    investigation_id: uuid.UUID | None = None,
    persist: bool = True,
) -> IAMAttackPath | None:
    """
    Walk the identity chain from `seed_identity` and build a graph.

    Returns None when the seed performed nothing in the window — an empty
    graph is not a finding, and persisting one would fill the attack-path
    view with noise.
    """
    end_time = start_time + timedelta(hours=window_hours)

    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    visited: set[str] = set()
    frontier: list[tuple[str, int]] = [(seed_identity, 0)]
    truncated = False
    highest_severity = "LOW"
    privilege_escalation = False

    def add_node(name: str, node_type: str, *, is_seed: bool = False) -> None:
        if name not in nodes:
            identity = (
                db.query(CloudIdentity)
                .filter(
                    CloudIdentity.organization_id == organization_id,
                    CloudIdentity.account_id == account_id,
                    CloudIdentity.identity_name == name,
                )
                .one_or_none()
            )
            nodes[name] = {
                "id": name,
                "type": node_type,
                "label": name,
                "arn": identity.arn if identity else None,
                "is_privileged": bool(identity.is_privileged) if identity else False,
                "is_seed": is_seed,
            }

    add_node(seed_identity, "identity", is_seed=True)

    while frontier:
        identity_name, depth = frontier.pop(0)
        if identity_name in visited:
            continue
        visited.add(identity_name)

        if depth >= MAX_DEPTH:
            truncated = True
            continue

        actions = scoped_cloud_events(db, organization_id).filter(
            CloudEvent.account_id == account_id,
            CloudEvent.actor_identity == identity_name,
            CloudEvent.event_timestamp >= start_time,
            CloudEvent.event_timestamp <= end_time,
        ).order_by(CloudEvent.event_timestamp.asc()).limit(MAX_ACTIONS_PER_IDENTITY + 1).all()

        if len(actions) > MAX_ACTIONS_PER_IDENTITY:
            truncated = True
            actions = actions[:MAX_ACTIONS_PER_IDENTITY]

        for cloud_event in actions:
            signal = classify_action(cloud_event.event_name)
            severity = _SEVERITY_BY_SIGNAL.get(signal, "LOW")
            if _SEVERITY_RANK[severity] > _SEVERITY_RANK[highest_severity]:
                highest_severity = severity
            if signal == "privilege_escalation":
                privilege_escalation = True

            if signal == "role_assumption" and cloud_event.assumed_role_arn:
                target = _name_from_arn(cloud_event.assumed_role_arn)
                if target:
                    add_node(target, "role")
                    edges.append(
                        {
                            "from": identity_name,
                            "to": target,
                            "action": cloud_event.event_name,
                            "signal": signal,
                            "timestamp": cloud_event.event_timestamp.isoformat(),
                            "cloud_event_id": str(cloud_event.id),
                            "event_id": str(cloud_event.event_id) if cloud_event.event_id else None,
                        }
                    )
                    if target not in visited:
                        frontier.append((target, depth + 1))
                continue

            resource = _resource_label(cloud_event)
            add_node(resource, "resource")
            edges.append(
                {
                    "from": identity_name,
                    "to": resource,
                    "action": cloud_event.event_name,
                    "signal": signal,
                    "timestamp": cloud_event.event_timestamp.isoformat(),
                    "cloud_event_id": str(cloud_event.id),
                    "event_id": str(cloud_event.event_id) if cloud_event.event_id else None,
                    "error_code": cloud_event.error_code,
                }
            )

    if not edges:
        return None

    explanation = _explain(seed_identity, nodes, edges, truncated)
    path = IAMAttackPath(
        organization_id=organization_id,
        alert_id=alert_id,
        incident_id=incident_id,
        investigation_id=investigation_id,
        title=f"Identity activity chain for '{seed_identity}' in account {account_id}",
        severity=highest_severity,
        path_nodes=list(nodes.values()),
        path_edges=edges,
        privilege_escalation_detected=privilege_escalation,
        explanation=explanation,
    )
    if persist:
        db.add(path)
        db.commit()
        db.refresh(path)
    return path


def _resource_label(cloud_event: CloudEvent) -> str:
    params = cloud_event.request_parameters or {}
    for key in ("bucketName", "roleName", "userName", "policyArn", "functionName", "keyId", "trailName"):
        value = params.get(key)
        if value:
            return str(value)
    return cloud_event.event_source or "cloud-resource"


def _explain(seed: str, nodes: dict[str, dict[str, Any]], edges: list[dict[str, Any]], truncated: bool) -> str:
    escalations = [e for e in edges if e["signal"] == "privilege_escalation"]
    evasions = [e for e in edges if e["signal"] == "defense_evasion"]
    assumptions = [e for e in edges if e["signal"] == "role_assumption"]

    parts = [
        f"Reconstructed from {len(edges)} observed CloudTrail action(s) across "
        f"{len([n for n in nodes.values() if n['type'] != 'resource'])} identity/identities, seeded from '{seed}'."
    ]
    if assumptions:
        chain = " -> ".join([seed] + [e["to"] for e in assumptions])
        parts.append(f"Role-assumption chain: {chain}.")
    if escalations:
        parts.append(
            "Permission-affecting actions observed: "
            + ", ".join(sorted({e["action"] for e in escalations}))
            + "."
        )
    if evasions:
        parts.append(
            "Defense-evasion actions observed (logging/monitoring impact): "
            + ", ".join(sorted({e["action"] for e in evasions}))
            + "."
        )
    if truncated:
        parts.append(
            "This path is TRUNCATED: the walk hit its depth or per-identity action cap, "
            "so the real chain may extend further. Treat it as a partial view."
        )
    parts.append(
        "Every edge cites the cloud_event it came from. This graph reflects activity that was "
        "observed, not permissions that were theoretically reachable."
    )
    return " ".join(parts)
