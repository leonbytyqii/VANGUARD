"""
The ingestion pipeline: LOG COLLECTOR -> NORMALIZATION ENGINE -> EVENT
PIPELINE from docs/ARCHITECTURE.md's top-level diagram, in one function.
Deliberately synchronous and simple for Phase 3 — Phase 4 hangs detection
execution off the same insert path (directly here, or via a queued job
once Celery/Redis is wired in) rather than a separate pipeline, so every
event that lands in the DB has a chance to be evaluated.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models.event import Event, NetworkConnection, Process
from app.models.host import Host
from app.schemas.event import EventIngestRequest
from app.services.ingestion.adapters.base import AdapterValidationError
from app.services.ingestion.registry import ADAPTER_REGISTRY, get_adapter


class IngestionError(ValueError):
    def __init__(self, message: str, *, status_code: int = 422):
        self.status_code = status_code
        super().__init__(message)


def _get_or_create_host(db: Session, organization_id: uuid.UUID, hostname: str, ip_address: str | None) -> Host:
    host = db.query(Host).filter(Host.organization_id == organization_id, Host.hostname == hostname).one_or_none()
    now = datetime.now(timezone.utc)
    if host is None:
        host = Host(
            organization_id=organization_id,
            hostname=hostname,
            ip_address=ip_address,
            first_seen_at=now,
            last_seen_at=now,
        )
        db.add(host)
        db.flush()
    else:
        host.last_seen_at = now
        if ip_address and not host.ip_address:
            host.ip_address = ip_address
        db.add(host)
    return host


def ingest_event(db: Session, *, organization_id: uuid.UUID, payload: EventIngestRequest) -> Event:
    adapter = get_adapter(payload.source)
    if adapter is None:
        raise IngestionError(
            f"Unknown event source '{payload.source}'. "
            f"Registered adapters: {', '.join(sorted(ADAPTER_REGISTRY))}."
        )

    try:
        normalized = adapter.normalize(payload)
    except AdapterValidationError as exc:
        raise IngestionError(str(exc)) from exc

    host = None
    if payload.host:
        host = _get_or_create_host(db, organization_id, payload.host, payload.src_ip)

    now = datetime.now(timezone.utc)
    event = Event(
        organization_id=organization_id,
        event_timestamp=payload.timestamp,
        source=payload.source,
        category=normalized.category,
        action=normalized.action,
        event_type=payload.event_type,
        host_id=host.id if host else None,
        host_name_raw=payload.host,
        user=payload.user,
        src_ip=payload.src_ip,
        dst_ip=payload.dst_ip,
        src_port=payload.src_port,
        dst_port=payload.dst_port,
        process=payload.process,
        parent_process=payload.parent_process,
        command_line=payload.command_line,
        file_hash=payload.file_hash,
        domain=payload.domain,
        url=payload.url,
        cloud_account=payload.cloud_account,
        cloud_region=payload.cloud_region,
        iam_role=payload.iam_role,
        ingested_at=now,
        # Evidence integrity: the full submitted payload, untouched, not
        # just the fields the adapter cared about.
        raw_event=payload.model_dump(mode="json"),
    )
    db.add(event)
    db.flush()  # populate event.id for the derived rows below

    if normalized.category == "process" and payload.process:
        db.add(
            Process(
                event_id=event.id,
                host_id=host.id if host else None,
                process_name=payload.process,
                process_guid=payload.process_guid,
                parent_process_name=payload.parent_process,
                parent_process_guid=payload.parent_process_guid,
                command_line=payload.command_line,
                user=payload.user,
                file_hash=payload.file_hash,
                process_timestamp=payload.timestamp,
            )
        )

    if normalized.category in ("network", "firewall") and payload.src_ip and payload.dst_ip:
        db.add(
            NetworkConnection(
                event_id=event.id,
                host_id=host.id if host else None,
                src_ip=payload.src_ip,
                dst_ip=payload.dst_ip,
                src_port=payload.src_port,
                dst_port=payload.dst_port,
                protocol=payload.protocol,
                process_name=payload.process,
                connection_timestamp=payload.timestamp,
            )
        )

    # Phase 11: CloudTrail-shaped events additionally get a cloud_events
    # projection plus cloud_identities rows for the actors they name. A
    # no-op for every other source — see app/cloud_iam/projection.py for
    # why this is a projection alongside the generic event rather than a
    # replacement for it.
    from app.cloud_iam.projection import project_cloud_event  # local import: avoids a service/cloud_iam import cycle

    project_cloud_event(db, event, raw_payload=event.raw_event)

    db.commit()
    db.refresh(event)

    # Phase 4: every ingested event is evaluated against the detection
    # registry synchronously, on the same request. This keeps the system
    # simple to reason about and test end-to-end; if ingestion volume ever
    # requires it, this call is the seam to move onto a queued worker
    # (Celery/Redis, already scaffolded in docker-compose.yml) without
    # ingest_event's callers needing to change.
    from app.detections.engine import run_detections_for_event  # local import: avoids a service/detections import cycle
    from app.services.alerting import generate_alerts_for_detections  # local import: avoids a service/alerting import cycle

    fired_detections = run_detections_for_event(db, organization_id=organization_id, event=event)
    if fired_detections:
        # Phase 5: every fired detection becomes (or reinforces) an Alert,
        # scored via app/services/risk_scoring.py's documented formula.
        generate_alerts_for_detections(db, organization_id=organization_id, detections=fired_detections)

    return event
