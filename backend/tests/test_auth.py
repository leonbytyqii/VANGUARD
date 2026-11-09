"""
Authentication security tests: login correctness, password hashing,
account lockout, JWT validity (expired/invalid/malformed), and refresh
token rotation + reuse detection.
"""
from datetime import datetime, timedelta, timezone

import pytest
from jose import jwt

from app.core.config import settings
from app.core.security import (
    PasswordPolicyError,
    hash_password,
    validate_password_policy,
    verify_password,
)
from tests.factories import create_organization, create_user, login

# --- Password hashing ---


def test_password_hashing_uses_argon2():
    hashed = hash_password("Sup3r$ecurePassw0rd!")
    assert hashed.startswith("$argon2")


def test_password_verification_round_trip():
    hashed = hash_password("Sup3r$ecurePassw0rd!")
    assert verify_password("Sup3r$ecurePassw0rd!", hashed) is True
    assert verify_password("wrong-password", hashed) is False


@pytest.mark.parametrize(
    "bad_password",
    ["short1!", "alllowercase1!", "ALLUPPERCASE1!", "NoDigitsHere!", "NoSpecialChars123", "password123!"],
)
def test_password_policy_rejects_weak_passwords(bad_password):
    with pytest.raises(PasswordPolicyError):
        validate_password_policy(bad_password)


def test_password_policy_accepts_strong_password():
    validate_password_policy("Sup3r$ecurePassw0rd!")  # should not raise


# --- Login ---


def test_login_unknown_user_returns_401(client):
    resp = login(client, "nobody@example.com", "irrelevant")
    assert resp.status_code == 401


def test_login_wrong_password_returns_401(client):
    org = create_organization()
    user, password = create_user(org, role_name="soc_analyst")
    resp = login(client, user.email, "wrong-password-entirely")
    assert resp.status_code == 401


def test_login_success_returns_access_token_and_refresh_cookie(client):
    org = create_organization()
    user, password = create_user(org, role_name="soc_analyst")
    resp = login(client, user.email, password)
    assert resp.status_code == 200
    body = resp.json()
    assert "access_token" in body
    assert body["token_type"] == "bearer"
    assert settings.REFRESH_COOKIE_NAME in resp.cookies


def test_login_does_not_leak_whether_user_exists(client):
    """Unknown-user and wrong-password both return the exact same status/shape."""
    org = create_organization()
    user, _ = create_user(org, role_name="soc_analyst")

    unknown_resp = login(client, "definitely-not-a-user@example.com", "whatever123!")
    wrong_pw_resp = login(client, user.email, "definitely-wrong-password!")

    assert unknown_resp.status_code == wrong_pw_resp.status_code == 401
    assert unknown_resp.json().keys() == wrong_pw_resp.json().keys()


# --- Account lockout (MAX_FAILED_LOGIN_ATTEMPTS=3, set in conftest env) ---


def test_account_locks_after_repeated_failed_logins(client):
    org = create_organization()
    user, password = create_user(org, role_name="soc_analyst")

    for _ in range(settings.MAX_FAILED_LOGIN_ATTEMPTS):
        resp = login(client, user.email, "wrong-password")
        assert resp.status_code in (401, 423)

    # Even the *correct* password is now rejected until the lockout window passes.
    resp = login(client, user.email, password)
    assert resp.status_code == 423


def test_successful_login_resets_failed_attempt_counter(client):
    org = create_organization()
    user, password = create_user(org, role_name="soc_analyst")

    login(client, user.email, "wrong-once")
    ok_resp = login(client, user.email, password)
    assert ok_resp.status_code == 200

    # Counter reset means we get another full run of attempts before lockout.
    for _ in range(settings.MAX_FAILED_LOGIN_ATTEMPTS - 1):
        resp = login(client, user.email, "wrong-again")
        assert resp.status_code == 401  # not yet locked


# --- Token validity ---


def test_expired_access_token_rejected(client):
    org = create_organization()
    user, password = create_user(org, role_name="soc_analyst")

    expired_payload = {
        "sub": str(user.id),
        "type": "access",
        "iat": datetime.now(timezone.utc) - timedelta(hours=2),
        "exp": datetime.now(timezone.utc) - timedelta(hours=1),
        "jti": "expired-test-token",
        "org": str(org.id),
        "role": "soc_analyst",
        "perms": [],
    }
    expired_token = jwt.encode(expired_payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

    resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {expired_token}"})
    assert resp.status_code == 401


def test_invalid_signature_token_rejected(client):
    org = create_organization()
    user, _ = create_user(org, role_name="soc_analyst")

    payload = {
        "sub": str(user.id),
        "type": "access",
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=30),
        "jti": "bad-sig-test-token",
    }
    tampered_token = jwt.encode(payload, "not-the-real-secret-key", algorithm=settings.JWT_ALGORITHM)

    resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {tampered_token}"})
    assert resp.status_code == 401


def test_malformed_token_rejected(client):
    resp = client.get("/api/v1/auth/me", headers={"Authorization": "Bearer not.a.jwt"})
    assert resp.status_code == 401


def test_missing_token_rejected(client):
    resp = client.get("/api/v1/auth/me")
    assert resp.status_code == 401


def test_refresh_token_type_cannot_be_used_as_access_token(client):
    """A refresh JWT-shaped token (type=refresh) must not authenticate API calls."""
    payload = {
        "sub": "00000000-0000-0000-0000-000000000000",
        "type": "refresh",
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=30),
        "jti": "wrong-type-test",
    }
    token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401


# --- Refresh token rotation + reuse detection ---


def _refresh_cookie(resp) -> str:
    value = resp.cookies.get(settings.REFRESH_COOKIE_NAME)
    assert value, "expected a refresh cookie on this response"
    return value


def test_refresh_rotates_token_and_old_cookie_stops_working(client):
    # Each replay is driven via an explicit `cookies={...}` on the request
    # rather than the shared client jar, so an intentionally-stale cookie
    # value never collides with whatever the jar most recently learned
    # (httpx's cookie jar keys on domain+path, which makes manually
    # re-injecting an old value into the persistent jar ambiguous).
    org = create_organization()
    user, password = create_user(org, role_name="soc_analyst")
    login_resp = login(client, user.email, password)
    old_cookie_value = _refresh_cookie(login_resp)

    refresh_resp = client.post(
        "/api/v1/auth/refresh", cookies={settings.REFRESH_COOKIE_NAME: old_cookie_value}
    )
    assert refresh_resp.status_code == 200
    new_cookie_value = _refresh_cookie(refresh_resp)
    assert new_cookie_value != old_cookie_value

    # Replay the OLD refresh token (simulating a stolen/rotated-away token).
    replay_resp = client.post(
        "/api/v1/auth/refresh", cookies={settings.REFRESH_COOKIE_NAME: old_cookie_value}
    )
    assert replay_resp.status_code == 401


def test_refresh_reuse_revokes_all_sessions(client):
    org = create_organization()
    user, password = create_user(org, role_name="soc_analyst")
    login_resp = login(client, user.email, password)
    valid_cookie = _refresh_cookie(login_resp)

    client.post("/api/v1/auth/refresh", cookies={settings.REFRESH_COOKIE_NAME: valid_cookie})
    # `valid_cookie` is now revoked (rotated away).

    # Replaying the revoked token should not just fail once — it should
    # have burned every active session for this user.
    client.post("/api/v1/auth/refresh", cookies={settings.REFRESH_COOKIE_NAME: valid_cookie})
    # ^ triggers reuse-detection: every refresh token for this user is now revoked.

    # A brand new login should still work (proves the account itself isn't locked)...
    second_login = login(client, user.email, password)
    assert second_login.status_code == 200
    fresh_cookie = _refresh_cookie(second_login)

    # ...but the token history from before the reuse event is entirely dead.
    dead_resp = client.post("/api/v1/auth/refresh", cookies={settings.REFRESH_COOKIE_NAME: valid_cookie})
    assert dead_resp.status_code == 401

    # sanity: the fresh session issued after the incident still works
    ok_resp = client.post("/api/v1/auth/refresh", cookies={settings.REFRESH_COOKIE_NAME: fresh_cookie})
    assert ok_resp.status_code == 200


def test_logout_revokes_refresh_token(client):
    org = create_organization()
    user, password = create_user(org, role_name="soc_analyst")
    login(client, user.email, password)

    logout_resp = client.post("/api/v1/auth/logout")
    assert logout_resp.status_code == 204

    refresh_resp = client.post("/api/v1/auth/refresh")
    assert refresh_resp.status_code == 401


def test_inactive_user_cannot_login(client):
    org = create_organization()
    user, password = create_user(org, role_name="soc_analyst", is_active=False)
    resp = login(client, user.email, password)
    assert resp.status_code == 403


# --- Change password ---


def test_change_password_requires_correct_current_password(client):
    org = create_organization()
    user, password = create_user(org, role_name="soc_analyst")
    headers = {"Authorization": f"Bearer {login(client, user.email, password).json()['access_token']}"}

    resp = client.post(
        "/api/v1/auth/change-password",
        headers=headers,
        json={"current_password": "wrong-current-password", "new_password": "N3wSup3r$ecure!"},
    )
    assert resp.status_code == 400


def test_change_password_success_then_old_password_stops_working(client):
    org = create_organization()
    user, password = create_user(org, role_name="soc_analyst")
    headers = {"Authorization": f"Bearer {login(client, user.email, password).json()['access_token']}"}

    resp = client.post(
        "/api/v1/auth/change-password",
        headers=headers,
        json={"current_password": password, "new_password": "N3wSup3r$ecure!"},
    )
    assert resp.status_code == 204

    old_login = login(client, user.email, password)
    assert old_login.status_code == 401

    new_login = login(client, user.email, "N3wSup3r$ecure!")
    assert new_login.status_code == 200


def test_refresh_cookie_path_covers_the_proxied_frontend_route(client):
    """
    Regression: the refresh cookie was scoped `Path=/api/v1/auth`, but the
    browser never calls that path — the Next.js frontend rewrites
    `/api/backend/*` to `/api/*`, so from the browser's side the endpoint
    is `/api/backend/v1/auth/refresh`. A cookie on the narrower path is
    silently never sent, refresh answered "No refresh token presented",
    and every session died at the 30-minute access-token expiry with no
    way to recover.

    `/api` is the common ancestor of the direct and proxied paths.
    """
    org = create_organization()
    user, password = create_user(org, role_name="soc_analyst")

    resp = client.post("/api/v1/auth/login", json={"email": user.email, "password": password})
    assert resp.status_code == 200

    set_cookie = resp.headers["set-cookie"]
    assert "Path=/api" in set_cookie, set_cookie
    assert "Path=/api/v1/auth" not in set_cookie, "too narrow for the proxied route"
    assert "HttpOnly" in set_cookie, "JavaScript must never be able to read the refresh token"

    # Both the direct and the proxied paths must sit underneath it.
    from app.core.config import settings

    for browser_visible_path in ("/api/v1/auth/refresh", "/api/backend/v1/auth/refresh"):
        assert browser_visible_path.startswith(settings.REFRESH_COOKIE_PATH), browser_visible_path


def test_refresh_issues_a_working_access_token(client):
    """The end-to-end recovery path a 30-minute-old session depends on."""
    org = create_organization()
    user, password = create_user(org, role_name="soc_analyst")

    login = client.post("/api/v1/auth/login", json={"email": user.email, "password": password})
    assert login.status_code == 200

    refreshed = client.post("/api/v1/auth/refresh")
    assert refreshed.status_code == 200, refreshed.text
    new_token = refreshed.json()["access_token"]
    assert new_token

    me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {new_token}"})
    assert me.status_code == 200
    assert me.json()["email"] == user.email
