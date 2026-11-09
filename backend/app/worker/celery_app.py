"""
Celery application and task definitions.

Currently two task families exist:

1. `run_investigation_async` — triggered by the AI investigation endpoint
   when it wants to avoid blocking the HTTP request. The investigation
   function (`run_investigation`) is entirely synchronous internally, so
   wrapping it in a Celery task is the only change needed to move it off
   the request path.

2. `run_detections_async` — a full detection sweep over a time window,
   used for scheduled re-evaluation (e.g., hourly sweep) rather than the
   per-event synchronous path that already fires inline with ingestion.
   The per-event synchronous path in app/services/ingestion/service.py
   remains the default; this task exists for replay/backfill scenarios.

Both tasks share the same DB session lifecycle: they obtain a session from
SessionLocal, do their work, and close it — no session is shared between
the Celery worker and the FastAPI worker pool.

The module is intentionally thin: all business logic lives in the service
layer (`app/ai/orchestrator.py`, `app/detections/engine.py`) and is fully
testable without Celery. This module just wires the service calls to the
queue machinery and handles errors in a way that lets Celery retry
transiently-failing tasks (DB connection hiccup, provider timeout) while
surfacing genuine failures (bad investigation ID, unrecoverable provider
error) as terminal task failures with a readable error message rather than
an infinite retry loop.
"""
from __future__ import annotations

import uuid

import structlog
from celery import Celery
from celery.utils.log import get_task_logger

from app.core.config import settings

log = structlog.get_logger()
task_log = get_task_logger(__name__)

celery_app = Celery(
    "vanguard",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    # Retry transiently-failing tasks up to 3 times with exponential
    # backoff before marking them failed. The default (no retries) is too
    # aggressive for tasks like AI investigations that may hit a provider
    # timeout on the first attempt but succeed immediately on the second.
    task_acks_late=True,
    task_reject_on_worker_lost=True,
)


@celery_app.task(
    bind=True,
    name="vanguard.run_investigation_async",
    max_retries=3,
    default_retry_delay=10,
)
def run_investigation_async(self, investigation_id: str) -> dict:
    """
    Run one AI investigation identified by its UUID.

    The investigation row must already exist in the database with
    status=pending — the HTTP handler that created it is responsible for
    that. This task only transitions it through running → completed/failed.
    Returns a summary dict (status + error) so the Celery result backend
    carries something useful without storing the entire investigation result
    (which can be large and is already in the DB).
    """
    from app.db.session import SessionLocal
    from app.models.ai import AIInvestigation

    db = SessionLocal()
    try:
        investigation = db.query(AIInvestigation).filter(
            AIInvestigation.id == uuid.UUID(investigation_id)
        ).one_or_none()

        if investigation is None:
            task_log.error("investigation_not_found", investigation_id=investigation_id)
            return {"status": "error", "error": f"Investigation {investigation_id} not found."}

        from app.ai.orchestrator import run_investigation
        investigation = run_investigation(db, investigation)
        return {"status": investigation.status, "error": investigation.error}

    except Exception as exc:
        task_log.exception("investigation_task_failed", investigation_id=investigation_id)
        try:
            raise self.retry(exc=exc)
        except self.MaxRetriesExceededError:
            return {"status": "failed", "error": str(exc)}
    finally:
        db.close()


@celery_app.task(
    bind=True,
    name="vanguard.run_detections_async",
    max_retries=1,
    default_retry_delay=30,
)
def run_detections_async(self, organization_id: str, since_iso: str | None = None) -> dict:
    """
    Full detection sweep over all events for one organization since a given
    timestamp (ISO 8601 string). Used for scheduled re-evaluation and replay
    — not the per-event synchronous path.

    Returns a summary: how many detections fired, how many alerts were
    generated/reinforced.
    """
    from datetime import datetime, timezone

    from app.db.session import SessionLocal
    from app.detections.engine import run_all_detections
    from app.services.alerting import generate_alerts_for_detections

    db = SessionLocal()
    try:
        org_uuid = uuid.UUID(organization_id)
        since = datetime.fromisoformat(since_iso).replace(tzinfo=timezone.utc) if since_iso else None

        fired = run_all_detections(db, organization_id=org_uuid, since=since)
        alerts = generate_alerts_for_detections(db, organization_id=org_uuid, detections=fired) if fired else []

        task_log.info(
            "detection_sweep_complete",
            organization_id=organization_id,
            detections_fired=len(fired),
            alerts_generated=len(alerts),
        )
        return {
            "organization_id": organization_id,
            "detections_fired": len(fired),
            "alerts_generated": len(alerts),
        }

    except Exception as exc:
        task_log.exception("detection_sweep_failed", organization_id=organization_id)
        try:
            raise self.retry(exc=exc)
        except self.MaxRetriesExceededError:
            return {"error": str(exc)}
    finally:
        db.close()
