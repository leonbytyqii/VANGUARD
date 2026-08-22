"""
IOC lifecycle and enrichment orchestration (docs/THREAT_INTEL.md).

Responsibilities, in the order a request usually hits them:

1. **Resolve or create the IOC row**, unique per `(organization_id,
   ioc_type, value)`. Indicators are tenant-scoped like every other
   resource: one organization observing `203.0.113.7` says nothing about
   whether another has.
2. **Serve from cache when a fresh verdict exists.** Enrichment is the
   one place in this platform that costs money per call and is
   rate-limited by somebody else, so a non-expired
   `ThreatIntelligence` row is reused rather than re-queried. Cache
   entries expire (`ENRICHMENT_TTL_HOURS`) because a verdict is a
   point-in-time observation, not a permanent property of an indicator.
3. **Query every supporting provider**, record each answer as its own row
   — including failures — and fold them into the IOC's aggregate
   verdict via `app.threat_intel.registry.aggregate`.

Nothing in here blocks, retries indefinitely, or raises on provider
failure: providers are contractually non-raising (see
`app/threat_intel/providers/base.py`), and a failed lookup degrades the
answer to `unknown` rather than to `clean`.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.enums import IncidentTimelineKind, IOCType
from app.models.event import Event
from app.models.threat_intel import IOC, ThreatIntelligence
from app.models.user import User
from app.services.audit import log_audit_event
from app.services.incident_timeline import record_timeline_event
from app.threat_intel.extraction import extract_from_events
from app.threat_intel.registry import aggregate, get_providers

#: How long a provider verdict is reused before it is re-queried.
ENRICHMENT_TTL_HOURS = 24
#: A failed lookup is retried much sooner than a successful one — the
#: provider being down for a minute should not blind the platform to that
#: indicator for a day.
FAILED_LOOKUP_TTL_MINUTES = 15

_VALID_IOC_TYPES = {t.value for t in IOCType}


class ThreatIntelError(Exception):
    def __init__(self, message: str, *, status_code: int = 400):
        self.status_code = status_code
        super().__init__(message)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def normalize_value(ioc_type: str, value: str) -> str:
    cleaned = value.strip().lower()
    if not cleaned:
        raise ThreatIntelError("IOC value cannot be empty.", status_code=422)
    if len(cleaned) > 512:
        raise ThreatIntelError("IOC value exceeds 512 characters.", status_code=422)
    return cleaned


def get_or_create_ioc(
    db: Session,
    *,
    organization_id: uuid.UUID | None,
    ioc_type: str,
    value: str,
    added_by: User | None = None,
    tags: list[str] | None = None,
    notes: str = "",
    commit: bool = True,
) -> IOC:
    if ioc_type not in _VALID_IOC_TYPES:
        raise ThreatIntelError(
            f"Unknown ioc_type '{ioc_type}' (expected one of: {', '.join(sorted(_VALID_IOC_TYPES))}).",
            status_code=422,
        )
    normalized = normalize_value(ioc_type, value)

    existing = (
        db.query(IOC)
        .filter(IOC.organization_id == organization_id, IOC.ioc_type == ioc_type, IOC.value == normalized)
        .one_or_none()
    )
    if existing is not None:
        existing.last_seen_at = _now()
        if tags:
            existing.tags = sorted(set(existing.tags or []) | set(tags))
        db.add(existing)
        if commit:
            db.commit()
            db.refresh(existing)
        return existing

    now = _now()
    ioc = IOC(
        organization_id=organization_id,
        ioc_type=ioc_type,
        value=normalized,
        first_seen_at=now,
        last_seen_at=now,
        tags=sorted(set(tags or [])),
        notes=notes,
        added_by_id=added_by.id if added_by else None,
    )
    db.add(ioc)
    try:
        db.flush()
    except IntegrityError:
        # Lost a race against a concurrent extraction of the same
        # indicator. The unique constraint is the authority; re-read the
        # winner rather than failing the caller's request.
        db.rollback()
        return (
            db.query(IOC)
            .filter(IOC.organization_id == organization_id, IOC.ioc_type == ioc_type, IOC.value == normalized)
            .one()
        )

    if commit:
        db.commit()
        db.refresh(ioc)
    return ioc


def _fresh_enrichments(db: Session, ioc: IOC) -> list[ThreatIntelligence]:
    now = _now()
    return [
        e
        for e in ioc.enrichments
        if e.expires_at is not None and e.expires_at > now
    ]


def enrich_ioc(
    db: Session,
    ioc: IOC,
    *,
    force_refresh: bool = False,
    actor: User | None = None,
    source_ip: str | None = None,
    commit: bool = True,
) -> tuple[IOC, bool]:
    """
    Score an indicator across every supporting provider.

    Returns `(ioc, from_cache)`. `from_cache=True` means no provider was
    contacted — surfaced to the caller rather than hidden, because
    "this verdict is 20 hours old" is something an analyst acting on it
    is entitled to know.
    """
    if not force_refresh:
        cached = _fresh_enrichments(db, ioc)
        if cached:
            return ioc, True

    providers = [p for p in get_providers() if p.supports(ioc.ioc_type)]
    now = _now()
    results = []

    for provider in providers:
        result = provider.lookup(ioc.ioc_type, ioc.value)
        results.append(result)
        ttl = (
            timedelta(minutes=FAILED_LOOKUP_TTL_MINUTES)
            if result.lookup_failed
            else timedelta(hours=ENRICHMENT_TTL_HOURS)
        )
        db.add(
            ThreatIntelligence(
                ioc_id=ioc.id,
                provider=result.provider,
                reputation=result.reputation,
                confidence=result.confidence,
                first_seen=result.first_seen,
                last_seen=result.last_seen,
                raw_response=result.raw,
                queried_at=now,
                expires_at=now + ttl,
                lookup_failed=result.lookup_failed,
                error=result.error,
            )
        )

    reputation, score = aggregate(results)
    ioc.reputation = reputation
    ioc.threat_score = score
    ioc.last_enriched_at = now
    ioc.last_seen_at = now
    db.add(ioc)
    db.flush()

    log_audit_event(
        db,
        action="ioc_enriched",
        actor_id=actor.id if actor else None,
        actor_label=actor.email if actor else "system",
        resource_type="ioc",
        resource_id=str(ioc.id),
        outcome="success",
        source_ip=source_ip,
        details={
            "ioc_type": ioc.ioc_type,
            "reputation": reputation,
            "threat_score": score,
            "providers_queried": [r.provider for r in results],
            "providers_failed": [r.provider for r in results if r.lookup_failed],
        },
        commit=False,
    )

    if commit:
        db.commit()
        db.refresh(ioc)
    return ioc, False


def lookup_and_enrich(
    db: Session,
    *,
    organization_id: uuid.UUID | None,
    ioc_type: str,
    value: str,
    force_refresh: bool = False,
    actor: User | None = None,
    source_ip: str | None = None,
) -> tuple[IOC, bool]:
    ioc = get_or_create_ioc(
        db, organization_id=organization_id, ioc_type=ioc_type, value=value, added_by=actor, commit=False
    )
    return enrich_ioc(db, ioc, force_refresh=force_refresh, actor=actor, source_ip=source_ip)


def enrich_alert_indicators(
    db: Session,
    alert: Alert,
    *,
    actor: User | None = None,
    source_ip: str | None = None,
) -> list[IOC]:
    """
    Extract every candidate indicator from the events an alert cites, then
    enrich each one and record the alert on it.

    Driven off `alert.related_event_ids` — the events the detection
    engine actually used as evidence — rather than "every event on that
    host", so an enriched indicator is always one the alert genuinely
    rests on.
    """
    event_ids: list[uuid.UUID] = []
    for raw in alert.related_event_ids or []:
        try:
            event_ids.append(uuid.UUID(str(raw)))
        except (TypeError, ValueError):
            continue

    if not event_ids:
        return []

    events = (
        db.query(Event)
        .filter(Event.id.in_(event_ids), Event.organization_id == alert.organization_id)
        .all()
    )
    extracted = extract_from_events(events)

    enriched: list[IOC] = []
    for candidate in extracted:
        ioc = get_or_create_ioc(
            db,
            organization_id=alert.organization_id,
            ioc_type=candidate.ioc_type,
            value=candidate.value,
            added_by=actor,
            tags=[f"from:{candidate.source_field}"],
            commit=False,
        )
        related = set(ioc.related_alert_ids or [])
        related.add(str(alert.id))
        ioc.related_alert_ids = sorted(related)
        enrich_ioc(db, ioc, actor=actor, source_ip=source_ip, commit=False)
        enriched.append(ioc)

    db.commit()
    for ioc in enriched:
        db.refresh(ioc)
    return enriched


def attach_ioc_to_incident(
    db: Session,
    incident,
    ioc: IOC,
    *,
    actor: User | None = None,
    source_ip: str | None = None,
) -> bool:
    """
    Link an indicator to a case. Returns True if newly attached.

    Cross-tenant attachment is impossible by construction: both objects
    are resolved through `scoped_query` at the route before they get here,
    and this asserts the invariant rather than trusting it.
    """
    if ioc.organization_id != incident.organization_id:
        raise ThreatIntelError("IOC and incident belong to different organizations.", status_code=404)

    if any(existing.id == ioc.id for existing in incident.iocs):
        return False

    incident.iocs.append(ioc)
    related = set(ioc.related_incident_ids or [])
    related.add(str(incident.id))
    ioc.related_incident_ids = sorted(related)
    db.add(incident)
    db.add(ioc)
    db.flush()

    record_timeline_event(
        db,
        incident_id=incident.id,
        kind=IncidentTimelineKind.IOC_ADDED,
        actor=actor.email if actor else None,
        details={
            "ioc_id": str(ioc.id),
            "ioc_type": ioc.ioc_type,
            "value": ioc.value,
            "reputation": ioc.reputation,
            "threat_score": ioc.threat_score,
        },
        commit=False,
    )
    log_audit_event(
        db,
        action="incident_ioc_attached",
        actor_id=actor.id if actor else None,
        actor_label=actor.email if actor else None,
        resource_type="incident",
        resource_id=str(incident.id),
        outcome="success",
        source_ip=source_ip,
        details={"ioc_id": str(ioc.id), "value": ioc.value},
        commit=False,
    )
    db.commit()
    return True


def detach_ioc_from_incident(
    db: Session, incident, ioc: IOC, *, actor: User | None = None, source_ip: str | None = None
) -> None:
    match = next((existing for existing in incident.iocs if existing.id == ioc.id), None)
    if match is None:
        raise ThreatIntelError("IOC is not attached to this incident.", status_code=404)

    incident.iocs.remove(match)
    ioc.related_incident_ids = sorted(set(ioc.related_incident_ids or []) - {str(incident.id)})
    db.add(incident)
    db.add(ioc)
    db.flush()
    record_timeline_event(
        db,
        incident_id=incident.id,
        kind=IncidentTimelineKind.IOC_ADDED,
        actor=actor.email if actor else None,
        details={"action": "detached", "ioc_id": str(ioc.id), "value": ioc.value},
        commit=False,
    )
    db.commit()


def serialize_enrichment(entry: ThreatIntelligence) -> dict[str, Any]:
    return {
        "provider": entry.provider,
        "reputation": entry.reputation,
        "confidence": entry.confidence,
        "queried_at": entry.queried_at,
        "expires_at": entry.expires_at,
        "lookup_failed": entry.lookup_failed,
        "error": entry.error,
        "raw_response": entry.raw_response,
    }
