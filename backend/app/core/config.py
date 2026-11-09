"""
Central application configuration.

Every configurable value — DB credentials, JWT secret, AI provider settings,
threat-intel API keys — is read from the environment (optionally via a local
.env file during development). Nothing sensitive is ever hard-coded here or
committed to source control; see /.env.example for the documented list of
variables an operator must set.
"""
from functools import lru_cache
from typing import List, Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- Core ---
    APP_NAME: str = "VANGUARD"
    ENVIRONMENT: Literal["development", "staging", "production"] = "development"
    DEBUG: bool = True
    API_V1_PREFIX: str = "/api/v1"

    # --- Database ---
    DATABASE_URL: str = Field(
        default="postgresql+psycopg2://socai:socai@localhost:5432/socai",
        description="SQLAlchemy connection string for PostgreSQL",
    )

    # --- Redis / background jobs ---
    REDIS_URL: str = "redis://localhost:6379/0"

    # --- Auth / sessions ---
    JWT_SECRET_KEY: str = Field(
        default="CHANGE_ME_DEV_ONLY_INSECURE",
        description="Must be overridden via env var in any non-dev deployment",
    )
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7
    REFRESH_COOKIE_NAME: str = "vanguard_refresh"
    # Cookie path for the refresh token.
    #
    # `/api` rather than the narrower `/api/v1/auth`, because the browser
    # never talks to this service directly: the Next.js frontend rewrites
    # `/api/backend/*` to `/api/*` (see frontend/next.config.mjs), so from
    # the browser's point of view the refresh endpoint lives at
    # `/api/backend/v1/auth/refresh`. A cookie scoped to `/api/v1/auth`
    # does not match that path and is silently never sent, which made
    # refresh fail with "No refresh token presented" and logged users out
    # every 30 minutes with no way back.
    #
    # `/api` is the common ancestor of the direct and proxied paths, so it
    # works for both while still keeping the refresh token off every
    # request to the frontend's own pages.
    REFRESH_COOKIE_PATH: str = "/api"

    # --- Account lockout / brute-force protection ---
    MAX_FAILED_LOGIN_ATTEMPTS: int = 5
    ACCOUNT_LOCKOUT_MINUTES: int = 15

    # --- Password policy ---
    PASSWORD_MIN_LENGTH: int = 12

    # --- Bootstrap admin (only used by app/db/seed.py on first run) ---
    ADMIN_BOOTSTRAP_EMAIL: str = "admin@vanguard.local"
    ADMIN_BOOTSTRAP_PASSWORD: str | None = Field(
        default=None,
        description="If unset, seed.py generates a random password and prints it once — never stored in code.",
    )

    # --- CORS ---
    # Stored as a raw comma-separated string (not List[str]) because
    # pydantic-settings attempts JSON-decoding list-typed env vars before
    # any custom validator runs, which breaks plain "a,b,c" values.
    CORS_ORIGINS_RAW: str = Field(default="http://localhost:3000", alias="CORS_ORIGINS")

    # --- Rate limiting ---
    RATE_LIMIT_DEFAULT: str = "100/minute"
    RATE_LIMIT_AUTH: str = "10/minute"

    # --- AI provider abstraction (never hard-code keys) ---
    AI_PROVIDER: Literal["mock", "openai_compatible"] = "mock"
    AI_MODEL: str = "gpt-4o-mini"
    AI_API_KEY: str | None = None
    AI_BASE_URL: str | None = None  # e.g. https://api.openai.com/v1 or a local vLLM endpoint
    AI_MAX_TOOL_ITERATIONS: int = 12
    AI_REQUEST_TIMEOUT_SECONDS: int = 60

    # --- Threat intelligence providers (optional; mock mode if unset) ---
    VIRUSTOTAL_API_KEY: str | None = None
    ABUSEIPDB_API_KEY: str | None = None
    OTX_API_KEY: str | None = None
    THREAT_INTEL_MODE: Literal["mock", "live"] = "mock"

    @property
    def CORS_ORIGINS(self) -> List[str]:
        return [origin.strip() for origin in self.CORS_ORIGINS_RAW.split(",") if origin.strip()]

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
