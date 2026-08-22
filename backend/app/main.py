import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.api.v1.router import api_router
from app.core.config import settings
from app.core.hardening import run_startup_checks
from app.core.rate_limit import limiter

log = structlog.get_logger()

# Fail closed before the first request rather than after: a production
# deployment with a placeholder signing key must not serve traffic at all.
# See app/core/hardening.py.
run_startup_checks(settings)

app = FastAPI(
    title=settings.APP_NAME,
    description="Agentic AI Security Operations Center platform — SIEM + SOAR + multi-agent AI investigation.",
    version="0.1.0",
    # Interactive docs enumerate every route and schema. Useful in
    # development, gratuitous reconnaissance surface in production.
    docs_url=None if settings.is_production else "/api/docs",
    redoc_url=None if settings.is_production else "/api/redoc",
    openapi_url=None if settings.is_production else "/api/openapi.json",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    if settings.is_production:
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    # The API serves JSON only — it renders no HTML and loads no
    # subresources — so the most restrictive possible policy is also the
    # correct one. It costs nothing here and blunts any future response
    # that accidentally reflects caller-controlled content.
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    return response


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    log.error("unhandled_exception", path=request.url.path, error=str(exc))
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


app.include_router(api_router, prefix=settings.API_V1_PREFIX)


@app.get("/", tags=["meta"])
def root():
    return {"service": settings.APP_NAME, "status": "operational", "docs": "/api/docs"}
