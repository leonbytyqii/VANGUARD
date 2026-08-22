"""
Projecting CloudTrail-shaped events into the cloud-specific tables.

Phase 3's adapter writes every ingested log into the generic `events`
table. That table is deliberately flat — one row, one set of normalized
columns — which is right for search and detection but wrong for
reconstructing an identity chain, because the question "who assumed what,
and what did that assumed identity then do?" is a graph question over
`actor -> role -> action` triples.

So Phase 11 adds a **projection**, not a replacement: a `cloud_events`
row alongside the `events` row it came from, carrying the identity-chain
fields (`actor_identity`, `actor_arn`, `assumed_role_arn`,
`request_parameters`, `response_elements`, `error_code`) that the flat
schema has nowhere to put. `cloud_events.event_id` always points back at
the originating `events` row, so nothing here is a second source of truth
— the raw payload remains the only evidence, and every cloud row can be
traced to it.

`cloud_identities` is likewise derived, not declared: an identity exists
in this platform because it was *observed acting*, not because somebody
imported an IAM inventory. That means the identity table reflects actual
telemetry, and an identity that never appears in logs never appears here
— which is honest about what the platform can actually see. Importing a
real IAM inventory (and therefore being able to report on unused
identities) needs an AWS integration that does not exist; see
docs/CLOUD_IAM.md §"What this does not do".
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.cloud import CloudEvent, CloudIdentity
from app.models.event import Event

#: Event names that grant, widen, or expose permissions. An actor
#: performing one of these has changed the security posture of the
#: account, which is what makes an edge in the attack graph interesting
#: rather than merely present.
PRIVILEGE_AFFECTING_ACTIONS = frozenset(
    {
        "attachuserpolicy",
        "attachrolepolicy",
        "attachgrouppolicy",
        "putuserpolicy",
        "putrolepolicy",
        "putgrouppolicy",
        "createaccesskey",
        "createuser",
        "createrole",
        "createloginprofile",
        "updateloginprofile",
        "updateassumerolepolicy",
        "addusertogroup",
        "createpolicyversion",
        "setdefaultpolicyversion",
        "passrole",
        "deactivatemfadevice",
    }
)

#: Actions that reduce the defender's visibility. Treated separately from
#: privilege escalation because "the attacker turned off logging" is a
#: different, and arguably worse, signal than "the attacker gained a
#: permission".
DEFENSE_EVASION_ACTIONS = frozenset(
    {
        "stoplogging",
        "deletetrail",
        "updatetrail",
        "deleteflowlogs",
        "putbucketlogging",
        "deletebucketpolicy",
        "disablekey",
        "scheduledeletion",
        "deleteloggroup",
    }
)

#: Identity names/ARNs that imply administrative reach when observed.
_PRIVILEGED_MARKERS = ("admin", "root", "poweruser", "superuser", "breakglass")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _arn_identity_type(arn: str | None, fallback: str = "user") -> str:
    if not arn:
        return fallback
    lowered = arn.lower()
    if ":role/" in lowered or ":assumed-role/" in lowered:
        return "role"
    if ":user/" in lowered:
        return "user"
    if lowered.endswith(".amazonaws.com") or ":service/" in lowered:
        return "service"
    return fallback


def _name_from_arn(arn: str) -> str:
    tail = arn.rsplit("/", 1)[-1] if "/" in arn else arn.rsplit(":", 1)[-1]
    return tail or arn


def upsert_cloud_identity(
    db: Session,
    *,
    organization_id: uuid.UUID | None,
    account_id: str,
    identity_name: str,
    arn: str | None = None,
    identity_type: str | None = None,
    observed_at: datetime | None = None,
    provider: str = "aws",
) -> CloudIdentity:
    """
    Record that an identity was observed. Idempotent per
    `(organization_id, account_id, identity_name)`.

    `is_privileged` is a *heuristic based on naming*, and deliberately
    conservative about saying so: without a real IAM policy fetch the
    platform cannot know a role's effective permissions, so it infers from
    the name and records that inference in `attached_policies` as an
    explicit marker rather than presenting it as fact.
    """
    observed_at = observed_at or _now()
    resolved_type = identity_type or _arn_identity_type(arn)

    identity = (
        db.query(CloudIdentity)
        .filter(
            CloudIdentity.organization_id == organization_id,
            CloudIdentity.account_id == account_id,
            CloudIdentity.identity_name == identity_name,
        )
        .one_or_none()
    )

    if identity is None:
        identity = CloudIdentity(
            organization_id=organization_id,
            provider=provider,
            account_id=account_id,
            identity_type=resolved_type,
            identity_name=identity_name,
            arn=arn,
            attached_policies=[],
            effective_permissions=[],
            is_privileged=any(m in identity_name.lower() for m in _PRIVILEGED_MARKERS),
            first_seen_at=observed_at,
            last_seen_at=observed_at,
        )
        db.add(identity)
        try:
            db.flush()
        except IntegrityError:
            db.rollback()
            return (
                db.query(CloudIdentity)
                .filter(
                    CloudIdentity.organization_id == organization_id,
                    CloudIdentity.account_id == account_id,
                    CloudIdentity.identity_name == identity_name,
                )
                .one()
            )
        return identity

    if identity.last_seen_at is None or observed_at > identity.last_seen_at:
        identity.last_seen_at = observed_at
    if identity.first_seen_at is None or observed_at < identity.first_seen_at:
        identity.first_seen_at = observed_at
    if arn and not identity.arn:
        identity.arn = arn
    if identity_type and identity.identity_type != identity_type:
        identity.identity_type = identity_type
    db.add(identity)
    return identity


def project_cloud_event(db: Session, event: Event, raw_payload: dict[str, Any] | None = None) -> CloudEvent | None:
    """
    Build the `cloud_events` row for a freshly ingested CloudTrail event,
    plus the `cloud_identities` rows for the actors it names.

    Returns None for anything that is not cloud/IAM telemetry — this is
    called unconditionally from the ingest path, and a Sysmon event has
    no cloud projection.
    """
    if event.source != "cloudtrail" or event.category not in ("cloud", "iam"):
        return None
    if not event.cloud_account:
        return None

    raw = raw_payload or event.raw_event or {}
    extra = raw.get("extra") or {}

    actor = event.user
    actor_arn = extra.get("actor_arn") or extra.get("userIdentityArn")
    assumed_role_arn = extra.get("assumed_role_arn") or extra.get("assumedRoleArn")

    # An AssumeRole names its target in requestParameters.roleArn; falling
    # back to the flat `iam_role` column keeps the simpler lab payloads
    # working without a nested requestParameters block.
    request_parameters = extra.get("request_parameters") or extra.get("requestParameters") or {}
    response_elements = extra.get("response_elements") or extra.get("responseElements") or {}
    if not assumed_role_arn:
        assumed_role_arn = request_parameters.get("roleArn") or event.iam_role

    cloud_event = CloudEvent(
        event_id=event.id,
        event_timestamp=event.event_timestamp,
        provider="aws",
        account_id=event.cloud_account,
        region=event.cloud_region,
        event_name=event.action or event.event_type or "unknown",
        event_source=extra.get("event_source") or extra.get("eventSource") or "cloudtrail",
        actor_identity=actor,
        actor_arn=actor_arn,
        assumed_role_arn=assumed_role_arn,
        source_ip=event.src_ip,
        user_agent=extra.get("user_agent") or extra.get("userAgent"),
        request_parameters=request_parameters if isinstance(request_parameters, dict) else {},
        response_elements=response_elements if isinstance(response_elements, dict) else {},
        error_code=extra.get("error_code") or extra.get("errorCode"),
        raw_event=raw,
    )
    db.add(cloud_event)

    if actor:
        upsert_cloud_identity(
            db,
            organization_id=event.organization_id,
            account_id=event.cloud_account,
            identity_name=actor,
            arn=actor_arn,
            observed_at=event.event_timestamp,
        )
    if assumed_role_arn:
        upsert_cloud_identity(
            db,
            organization_id=event.organization_id,
            account_id=event.cloud_account,
            identity_name=_name_from_arn(assumed_role_arn),
            arn=assumed_role_arn,
            identity_type="role",
            observed_at=event.event_timestamp,
        )

    db.flush()
    return cloud_event


def classify_action(event_name: str) -> str:
    """`privilege_escalation` / `defense_evasion` / `access` — used to weight graph edges."""
    lowered = (event_name or "").lower()
    if lowered in DEFENSE_EVASION_ACTIONS or any(a in lowered for a in DEFENSE_EVASION_ACTIONS):
        return "defense_evasion"
    if lowered in PRIVILEGE_AFFECTING_ACTIONS or any(a in lowered for a in PRIVILEGE_AFFECTING_ACTIONS):
        return "privilege_escalation"
    if lowered == "assumerole":
        return "role_assumption"
    return "access"
