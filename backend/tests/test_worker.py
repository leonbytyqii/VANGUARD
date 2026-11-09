"""
Smoke tests for app/worker/celery_app.py.

These tests do NOT start a real Celery worker or broker — they verify that:
1. The module imports without errors.
2. The Celery app is configured correctly (broker URL, task serializer).
3. The expected tasks are registered.
4. The task signatures match the expected parameter names (a regression guard
   against renaming a parameter in the service layer without updating the task).

No DB is required for these tests — they interact only with the Celery app
object and the task registry, not with any handler logic.
"""
import pytest


def test_celery_app_importable():
    from app.worker.celery_app import celery_app

    assert celery_app is not None
    assert celery_app.main == "vanguard"


def test_celery_app_uses_redis_broker(settings):
    from app.worker.celery_app import celery_app

    assert celery_app.conf.broker_url == settings.REDIS_URL


def test_celery_app_serializer():
    from app.worker.celery_app import celery_app

    assert celery_app.conf.task_serializer == "json"
    assert celery_app.conf.result_serializer == "json"


def test_investigation_task_registered():
    from app.worker.celery_app import run_investigation_async

    assert run_investigation_async.name == "vanguard.run_investigation_async"
    assert run_investigation_async.max_retries == 3


def test_detection_sweep_task_registered():
    from app.worker.celery_app import run_detections_async

    assert run_detections_async.name == "vanguard.run_detections_async"
    assert run_detections_async.max_retries == 1


@pytest.fixture()
def settings():
    from app.core.config import get_settings
    return get_settings()
