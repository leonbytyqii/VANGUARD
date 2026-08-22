"""
Phase 15 — deployment-posture checks.

These test the thing that runs *before* the first request: whether the
platform will refuse to serve traffic when its own configuration would
make every other control meaningless.
"""
import pytest

from app.core.config import Settings
from app.core.hardening import (
    PLACEHOLDER_JWT_SECRET,
    InsecureDeploymentError,
    collect_findings,
    run_startup_checks,
)


def _settings(**overrides) -> Settings:
    base = {
        "ENVIRONMENT": "production",
        "DEBUG": False,
        "JWT_SECRET_KEY": "a" * 48,
        "DATABASE_URL": "postgresql+psycopg2://socai:a-real-password@db:5432/socai",
        "CORS_ORIGINS": "https://soc.example.com",
        "ACCESS_TOKEN_EXPIRE_MINUTES": 30,
        "THREAT_INTEL_MODE": "mock",
        "AI_PROVIDER": "mock",
        "ADMIN_BOOTSTRAP_PASSWORD": None,
    }
    base.update(overrides)
    return Settings(**base)


def test_a_correctly_configured_production_deployment_has_no_fatal_findings():
    fatal, _ = collect_findings(_settings())
    assert fatal == []
    run_startup_checks(_settings())  # must not raise


def test_the_placeholder_signing_key_is_fatal():
    fatal, _ = collect_findings(_settings(JWT_SECRET_KEY=PLACEHOLDER_JWT_SECRET))
    assert any("JWT_SECRET_KEY" in f for f in fatal)


def test_a_short_signing_key_is_fatal():
    fatal, _ = collect_findings(_settings(JWT_SECRET_KEY="short"))
    assert any("characters" in f for f in fatal)


def test_debug_enabled_in_production_is_fatal():
    fatal, _ = collect_findings(_settings(DEBUG=True))
    assert any("DEBUG" in f for f in fatal)


def test_the_placeholder_database_password_is_fatal():
    fatal, _ = collect_findings(
        _settings(DATABASE_URL="postgresql+psycopg2://socai:change_me_in_any_shared_environment@db:5432/socai")
    )
    assert any("DATABASE_URL" in f for f in fatal)


def test_a_wildcard_cors_origin_is_fatal():
    """
    The API replies with credentials, so `*` would let any origin read an
    authenticated response.
    """
    fatal, _ = collect_findings(_settings(CORS_ORIGINS="*"))
    assert any("CORS" in f for f in fatal)


def test_production_refuses_to_start_when_a_fatal_finding_exists():
    with pytest.raises(InsecureDeploymentError) as exc:
        run_startup_checks(_settings(JWT_SECRET_KEY=PLACEHOLDER_JWT_SECRET))
    assert "JWT_SECRET_KEY" in str(exc.value)


def test_development_warns_but_still_starts():
    """
    A developer running against a local database should not have to invent
    a 48-byte secret to see the login page — but the finding is still
    logged as one that would be fatal in production.
    """
    run_startup_checks(
        _settings(ENVIRONMENT="development", DEBUG=True, JWT_SECRET_KEY=PLACEHOLDER_JWT_SECRET)
    )  # must not raise


def test_plaintext_http_origins_are_advisory_not_fatal():
    fatal, advisory = collect_findings(_settings(CORS_ORIGINS="http://soc.example.com"))
    assert fatal == []
    assert any("plaintext HTTP" in a for a in advisory)


def test_localhost_http_origin_is_not_even_advisory():
    _, advisory = collect_findings(_settings(CORS_ORIGINS="http://localhost:3000"))
    assert not any("plaintext HTTP" in a for a in advisory)


def test_long_lived_access_tokens_are_advisory():
    _, advisory = collect_findings(_settings(ACCESS_TOKEN_EXPIRE_MINUTES=1440))
    assert any("ACCESS_TOKEN_EXPIRE_MINUTES" in a for a in advisory)


def test_live_threat_intel_without_keys_is_advisory():
    _, advisory = collect_findings(_settings(THREAT_INTEL_MODE="live"))
    assert any("THREAT_INTEL_MODE" in a for a in advisory)


def test_openai_provider_without_a_key_is_advisory():
    _, advisory = collect_findings(_settings(AI_PROVIDER="openai_compatible"))
    assert any("AI_API_KEY" in a for a in advisory)


def test_bootstrap_password_in_the_environment_is_advisory():
    _, advisory = collect_findings(_settings(ADMIN_BOOTSTRAP_PASSWORD="SomethingSet!123"))
    assert any("ADMIN_BOOTSTRAP_PASSWORD" in a for a in advisory)


def test_security_headers_are_present_on_every_response(client):
    resp = client.get("/api/v1/health")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert "frame-ancestors 'none'" in resp.headers["Content-Security-Policy"]


def test_security_headers_are_present_even_on_a_rejected_request(client):
    """A 401 is exactly when a browser most needs the headers applied."""
    resp = client.get("/api/v1/alerts")
    assert resp.status_code == 401
    assert resp.headers["X-Content-Type-Options"] == "nosniff"


def test_gitignore_excludes_env_files_but_keeps_the_template():
    from pathlib import Path

    gitignore = Path(__file__).resolve().parents[2] / ".gitignore"
    assert gitignore.exists(), "the repo must have a .gitignore — a committed .env is a leaked signing key"
    body = gitignore.read_text(encoding="utf-8")
    assert ".env" in body
    assert "!.env.example" in body, "the template must stay committed"
    for pattern in ("*.pem", "*.key", ".venv/", "node_modules/"):
        assert pattern in body, f"{pattern} should be ignored"
