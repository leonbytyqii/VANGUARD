"""
Confirms the slowapi wiring pattern used on /auth/login and /auth/refresh
(app.main's exception handler + app.core.rate_limit.limiter +
@limiter.limit(...) decorator) actually returns 429 once a limit is
exceeded.

This runs against a small standalone app with its own tight limit rather
than the real app/main.py — the real app's RATE_LIMIT_AUTH is relaxed to
1000/minute for the rest of the suite (see conftest.py) because dozens of
unrelated tests log in from what slowapi sees as the same client IP, which
would otherwise make every other auth test flaky. Exercising the identical
decorator + handler pattern here proves the mechanism itself works; the
real endpoints wire the exact same primitives with a production-appropriate
limit (RATE_LIMIT_AUTH, default 10/minute).
"""
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address


def test_rate_limit_decorator_returns_429_once_exceeded():
    limiter = Limiter(key_func=get_remote_address)
    app = FastAPI()
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    @app.post("/login-like-endpoint")
    @limiter.limit("2/minute")
    def endpoint(request: Request):
        return {"ok": True}

    client = TestClient(app)

    assert client.post("/login-like-endpoint").status_code == 200
    assert client.post("/login-like-endpoint").status_code == 200
    third = client.post("/login-like-endpoint")
    assert third.status_code == 429
