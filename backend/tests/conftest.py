import os

# Port 5432 is the standard Postgres port used both by CI (GitHub Actions
# postgres service) and a local `docker compose up`. On Leon's dev machine the
# portable Postgres listens on 55432 — set DATABASE_URL in the environment or
# in backend/.env before running pytest locally to override this default.
os.environ.setdefault("DATABASE_URL", "postgresql+psycopg2://socai:socai@localhost:5432/socai_test")
os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("MAX_FAILED_LOGIN_ATTEMPTS", "3")  # keep lockout tests fast
# Valid 32-byte URL-safe base64 Fernet key (all-zero bytes) for test TOTP encryption.
os.environ.setdefault("MFA_ENCRYPTION_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
# The test suite makes far more than 10 login calls per minute across many
# unrelated tests (all appearing to come from the same TestClient "IP") —
# that's a testing-harness artifact, not something the per-IP auth rate
# limit is meant to catch, so it's relaxed here. test_rate_limiting.py
# below exercises the real default directly.
os.environ.setdefault("RATE_LIMIT_AUTH", "1000/minute")

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import get_settings
from app.db.base import Base


@pytest.fixture(scope="session", autouse=True)
def _test_database():
    """
    Creates all tables against the test database once per test session and
    drops them afterward. Assumes a Postgres server reachable at
    DATABASE_URL's host with permission to create the target database
    (see scripts/create_test_db.sh for local/dev setup).
    """
    settings = get_settings()
    engine = create_engine(settings.DATABASE_URL, future=True)
    Base.metadata.create_all(engine)
    yield engine
    Base.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture(scope="session", autouse=True)
def _seed_baseline(_test_database):
    """
    Seeds the permission catalog, RBAC roles, AI agent identities,
    detection rule catalog, MITRE ATT&CK catalog (+ detection-rule
    links), and the built-in threat-hunting query library once per test
    session — the same code path app/db/seed.py uses in a real
    deployment, so a passing test suite is also proof the seed script
    produces a working baseline end to end.

    Deliberately does NOT seed an Organization or bootstrap admin here —
    individual tests build their own organizations/users via
    tests/factories.py so multi-tenant and RBAC scenarios stay explicit
    and isolated per test.
    """
    from app.db.seed import seed_agent_identities, seed_permissions, seed_roles
    from app.db.session import SessionLocal
    from app.detections.engine import sync_detection_rules
    from app.hunting.seed import sync_builtin_hunt_queries
    from app.mitre.seed import link_detection_rules_to_techniques, sync_mitre_catalog

    db = SessionLocal()
    try:
        permissions_by_code = seed_permissions(db)
        seed_roles(db, permissions_by_code)
        seed_agent_identities(db)
        sync_detection_rules(db)
        sync_mitre_catalog(db)
        link_detection_rules_to_techniques(db)
        sync_builtin_hunt_queries(db)
    finally:
        db.close()


@pytest.fixture()
def db_session(_test_database):
    SessionLocal = sessionmaker(bind=_test_database, future=True)
    session = SessionLocal()
    try:
        yield session
        session.rollback()
    finally:
        session.close()


@pytest.fixture()
def client():
    from fastapi.testclient import TestClient

    from app.main import app

    return TestClient(app)
