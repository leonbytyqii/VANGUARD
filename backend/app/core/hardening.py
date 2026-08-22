"""
Deployment-posture checks that run once, at startup (Phase 15).

The rule here is **fail closed in production, warn loudly in
development**. A platform whose entire value proposition is
"privileged actions require a human" cannot also be a platform that
boots happily with a placeholder signing key — anyone who can forge a
token is that human, as far as the API is concerned.

So `run_startup_checks` distinguishes two kinds of finding:

* **Fatal** — the deployment is not safe to serve traffic. In
  `ENVIRONMENT=production` these raise and the process exits before the
  first request. In development they are logged as warnings, because a
  developer running `uvicorn --reload` against a local Postgres should
  not have to invent a 48-byte secret to see the login page.
* **Advisory** — worth flagging in any environment, but not a reason to
  refuse to start.

Everything is checked against `settings`, never against a hard-coded
list of "known bad" values beyond the placeholders this repo itself
ships, because a check that tries to guess whether a secret is "strong
enough" gives false confidence.
"""
from __future__ import annotations

import structlog

from app.core.config import Settings

log = structlog.get_logger()

#: The placeholder this repo ships. Present in a running production
#: process, it means nobody set a real one.
PLACEHOLDER_JWT_SECRET = "CHANGE_ME_DEV_ONLY_INSECURE"
MIN_PRODUCTION_SECRET_LENGTH = 32


class InsecureDeploymentError(RuntimeError):
    """Raised at startup when a production deployment is misconfigured."""


def collect_findings(settings: Settings) -> tuple[list[str], list[str]]:
    """Returns `(fatal, advisory)` as human-readable strings."""
    fatal: list[str] = []
    advisory: list[str] = []

    secret = settings.JWT_SECRET_KEY or ""
    if secret == PLACEHOLDER_JWT_SECRET or not secret:
        fatal.append(
            "JWT_SECRET_KEY is unset or still the shipped placeholder. Every access token the platform "
            "issues would be forgeable. Generate one with: "
            'python -c "import secrets; print(secrets.token_urlsafe(48))"'
        )
    elif len(secret) < MIN_PRODUCTION_SECRET_LENGTH:
        fatal.append(
            f"JWT_SECRET_KEY is only {len(secret)} characters; at least {MIN_PRODUCTION_SECRET_LENGTH} is required."
        )

    if settings.DEBUG:
        fatal.append("DEBUG is enabled. Tracebacks and internal detail must not be served in production.")

    if "change_me" in settings.DATABASE_URL.lower():
        fatal.append("DATABASE_URL still contains the placeholder password from .env.example.")

    if any(origin == "*" for origin in settings.CORS_ORIGINS):
        fatal.append(
            "CORS_ORIGINS contains '*'. The API issues credentialed responses, so a wildcard origin would "
            "let any site read them."
        )

    for origin in settings.CORS_ORIGINS:
        if origin.startswith("http://") and "localhost" not in origin and "127.0.0.1" not in origin:
            advisory.append(f"CORS origin {origin} is plaintext HTTP; tokens would cross the network unprotected.")

    if settings.ACCESS_TOKEN_EXPIRE_MINUTES > 120:
        advisory.append(
            f"ACCESS_TOKEN_EXPIRE_MINUTES is {settings.ACCESS_TOKEN_EXPIRE_MINUTES}. Permissions are re-read "
            "from the database per request, but a long-lived token still widens the window on a stolen one."
        )

    if settings.THREAT_INTEL_MODE == "live" and not any(
        (settings.VIRUSTOTAL_API_KEY, settings.ABUSEIPDB_API_KEY, settings.OTX_API_KEY)
    ):
        advisory.append(
            "THREAT_INTEL_MODE=live but no provider key is configured; enrichment will fall back to the "
            "offline feed alone."
        )

    if settings.AI_PROVIDER == "openai_compatible" and not settings.AI_API_KEY:
        advisory.append("AI_PROVIDER=openai_compatible but AI_API_KEY is unset; investigations will fail.")

    if settings.ADMIN_BOOTSTRAP_PASSWORD:
        advisory.append(
            "ADMIN_BOOTSTRAP_PASSWORD is set in the environment. Prefer leaving it unset so seed.py generates "
            "one and prints it once, rather than leaving a credential in the process environment."
        )

    return fatal, advisory


def run_startup_checks(settings: Settings) -> None:
    fatal, advisory = collect_findings(settings)

    for message in advisory:
        log.warning("deployment_advisory", detail=message)

    if not fatal:
        log.info("startup_checks_passed", environment=settings.ENVIRONMENT)
        return

    if settings.is_production:
        for message in fatal:
            log.error("insecure_production_deployment", detail=message)
        raise InsecureDeploymentError(
            "Refusing to start in production with an insecure configuration:\n  - " + "\n  - ".join(fatal)
        )

    # Development: warn, but let the process run.
    for message in fatal:
        log.warning("insecure_configuration_would_be_fatal_in_production", detail=message)
