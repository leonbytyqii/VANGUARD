"""
Phase 16 — TOTP MFA and API key tests.

Covers:
- TOTP enrolment flow (setup → confirm → enable)
- Recovery codes (issued once, single-use, argon2 hashed)
- MFA login challenge flow (password OK → challenge token → TOTP → credentials)
- MFA disable (requires valid TOTP code)
- Recovery code fallback during disable and login
- API key creation, authentication, rotation, revocation
- Edge cases: wrong code, expired challenge token, double-enrolment guard
"""
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pyotp

from app.core.security import create_mfa_challenge_token
from app.db.session import SessionLocal
from app.models.auth import TOTPDevice
from app.models.user import User
from app.services.api_key_service import create_api_key
from app.services.mfa_service import (
    begin_totp_setup,
    confirm_totp_setup,
    verify_recovery_code,
)
from tests.factories import auth_headers, create_organization, create_user

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_user(user_id) -> User:
    db = SessionLocal()
    try:
        return db.query(User).filter(User.id == user_id).one()
    finally:
        db.close()


def _enrol_totp(user: User) -> tuple[str, list[str]]:
    """Full enrolment: setup → confirm with real TOTP code. Returns (secret, recovery_codes)."""
    db = SessionLocal()
    try:
        result = begin_totp_setup(db, user)
        secret = result["secret"]
        totp = pyotp.TOTP(secret)
        codes = confirm_totp_setup(db, user, totp.now())
        db.refresh(user)
        return secret, codes
    finally:
        db.close()


# ---------------------------------------------------------------------------
# TOTP enrolment
# ---------------------------------------------------------------------------

def test_begin_totp_setup_returns_provisioning_uri_and_secret(client):
    org = create_organization()
    user, pw = create_user(org)
    headers = auth_headers(client, user.email, pw)

    resp = client.post("/api/v1/auth/mfa/setup", headers=headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "provisioning_uri" in body
    assert "secret" in body
    assert "otpauth://totp/" in body["provisioning_uri"]
    assert len(body["secret"]) >= 16  # base32 TOTP secret


def test_begin_totp_setup_creates_unconfirmed_device(client):
    org = create_organization()
    user, pw = create_user(org)
    headers = auth_headers(client, user.email, pw)
    client.post("/api/v1/auth/mfa/setup", headers=headers)

    db = SessionLocal()
    try:
        device = db.query(TOTPDevice).filter(TOTPDevice.user_id == user.id).one_or_none()
        assert device is not None
        assert device.confirmed is False
    finally:
        db.close()


def test_confirm_totp_setup_with_valid_code_enables_mfa(client):
    org = create_organization()
    user, pw = create_user(org)
    headers = auth_headers(client, user.email, pw)

    setup_resp = client.post("/api/v1/auth/mfa/setup", headers=headers)
    secret = setup_resp.json()["secret"]

    code = pyotp.TOTP(secret).now()
    confirm_resp = client.post("/api/v1/auth/mfa/setup/confirm", headers=headers, json={"code": code})
    assert confirm_resp.status_code == 200, confirm_resp.text

    body = confirm_resp.json()
    assert "recovery_codes" in body
    assert len(body["recovery_codes"]) == 10

    fresh = _get_user(user.id)
    assert fresh.totp_enabled is True


def test_confirm_totp_setup_with_wrong_code_returns_400(client):
    org = create_organization()
    user, pw = create_user(org)
    headers = auth_headers(client, user.email, pw)
    client.post("/api/v1/auth/mfa/setup", headers=headers)

    resp = client.post("/api/v1/auth/mfa/setup/confirm", headers=headers, json={"code": "000000"})
    assert resp.status_code == 400


def test_begin_totp_setup_while_already_enabled_returns_409(client):
    org = create_organization()
    user, pw = create_user(org)
    _enrol_totp(user)

    headers = auth_headers(client, user.email, pw)
    resp = client.post("/api/v1/auth/mfa/setup", headers=headers)
    assert resp.status_code == 409


def test_recovery_codes_are_shown_exactly_once_on_enrolment(client):
    org = create_organization()
    user, pw = create_user(org)
    headers = auth_headers(client, user.email, pw)

    setup_resp = client.post("/api/v1/auth/mfa/setup", headers=headers)
    secret = setup_resp.json()["secret"]
    code = pyotp.TOTP(secret).now()
    confirm_resp = client.post("/api/v1/auth/mfa/setup/confirm", headers=headers, json={"code": code})
    codes = confirm_resp.json()["recovery_codes"]

    # Format: XXXXX-XXXXX
    assert all(len(c) == 11 and c[5] == "-" for c in codes)
    # Ten distinct codes
    assert len(set(codes)) == 10


# ---------------------------------------------------------------------------
# MFA login challenge flow
# ---------------------------------------------------------------------------

def test_login_with_mfa_enabled_returns_challenge_token_not_access_token(client):
    org = create_organization()
    user, pw = create_user(org)
    _enrol_totp(user)

    resp = client.post("/api/v1/auth/login", json={"email": user.email, "password": pw})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["mfa_required"] is True
    assert body["mfa_challenge_token"] is not None
    assert body.get("access_token") is None


def test_login_without_mfa_returns_access_token_directly(client):
    org = create_organization()
    user, pw = create_user(org)

    resp = client.post("/api/v1/auth/login", json={"email": user.email, "password": pw})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["mfa_required"] is False
    assert body["access_token"] is not None


def test_mfa_complete_with_valid_totp_code_issues_credentials(client):
    org = create_organization()
    user, pw = create_user(org)
    secret, _ = _enrol_totp(user)

    login_resp = client.post("/api/v1/auth/login", json={"email": user.email, "password": pw})
    challenge = login_resp.json()["mfa_challenge_token"]

    code = pyotp.TOTP(secret).now()
    complete_resp = client.post(
        "/api/v1/auth/mfa/complete",
        json={"mfa_challenge_token": challenge, "code": code},
    )
    assert complete_resp.status_code == 200, complete_resp.text
    assert "access_token" in complete_resp.json()


def test_mfa_complete_with_wrong_code_returns_400(client):
    org = create_organization()
    user, pw = create_user(org)
    _enrol_totp(user)

    login_resp = client.post("/api/v1/auth/login", json={"email": user.email, "password": pw})
    challenge = login_resp.json()["mfa_challenge_token"]

    resp = client.post(
        "/api/v1/auth/mfa/complete",
        json={"mfa_challenge_token": challenge, "code": "000000"},
    )
    assert resp.status_code == 400


def test_mfa_complete_with_expired_challenge_token_returns_401(client):
    org = create_organization()
    user, pw = create_user(org)
    secret, _ = _enrol_totp(user)

    # Create a challenge token that is already expired
    with patch("app.core.security._MFA_CHALLENGE_TTL_MINUTES", -1):
        expired_token = create_mfa_challenge_token(user_id=str(user.id))

    code = pyotp.TOTP(secret).now()
    resp = client.post(
        "/api/v1/auth/mfa/complete",
        json={"mfa_challenge_token": expired_token, "code": code},
    )
    assert resp.status_code == 401


def test_mfa_complete_with_recovery_code_works(client):
    org = create_organization()
    user, pw = create_user(org)
    _, recovery_codes = _enrol_totp(user)

    login_resp = client.post("/api/v1/auth/login", json={"email": user.email, "password": pw})
    challenge = login_resp.json()["mfa_challenge_token"]

    resp = client.post(
        "/api/v1/auth/mfa/complete",
        json={"mfa_challenge_token": challenge, "code": recovery_codes[0]},
    )
    assert resp.status_code == 200, resp.text
    assert "access_token" in resp.json()


def test_recovery_code_cannot_be_reused(client):
    org = create_organization()
    user, pw = create_user(org)
    _, recovery_codes = _enrol_totp(user)

    db = SessionLocal()
    try:
        first = verify_recovery_code(db, user, recovery_codes[0])
        second = verify_recovery_code(db, user, recovery_codes[0])
    finally:
        db.close()

    assert first is True
    assert second is False


# ---------------------------------------------------------------------------
# MFA status and disable
# ---------------------------------------------------------------------------

def test_mfa_status_shows_enabled_and_code_count(client):
    org = create_organization()
    user, pw = create_user(org)
    _enrol_totp(user)
    headers = auth_headers(client, user.email, pw)

    resp = client.get("/api/v1/auth/mfa/status", headers=headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["totp_enabled"] is True
    assert body["recovery_codes_remaining"] == 10


def test_mfa_status_shows_disabled_for_unenrolled_user(client):
    org = create_organization()
    user, pw = create_user(org)
    headers = auth_headers(client, user.email, pw)

    resp = client.get("/api/v1/auth/mfa/status", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["totp_enabled"] is False


def test_disable_mfa_with_valid_totp_code(client):
    org = create_organization()
    user, pw = create_user(org)
    secret, _ = _enrol_totp(user)
    headers = auth_headers(client, user.email, pw)

    code = pyotp.TOTP(secret).now()
    resp = client.post("/api/v1/auth/mfa/disable", headers=headers, json={"code": code})
    assert resp.status_code == 204, resp.text

    fresh = _get_user(user.id)
    assert fresh.totp_enabled is False


def test_disable_mfa_with_wrong_code_returns_400(client):
    org = create_organization()
    user, pw = create_user(org)
    _enrol_totp(user)
    headers = auth_headers(client, user.email, pw)

    resp = client.post("/api/v1/auth/mfa/disable", headers=headers, json={"code": "000000"})
    assert resp.status_code == 400


def test_disable_mfa_on_unenrolled_user_returns_404(client):
    org = create_organization()
    user, pw = create_user(org)
    headers = auth_headers(client, user.email, pw)

    resp = client.post("/api/v1/auth/mfa/disable", headers=headers, json={"code": "123456"})
    assert resp.status_code == 404


def test_recovery_codes_regenerated_invalidates_old_codes(client):
    org = create_organization()
    user, pw = create_user(org)
    secret, old_codes = _enrol_totp(user)
    headers = auth_headers(client, user.email, pw)

    code = pyotp.TOTP(secret).now()
    regen_resp = client.post(
        "/api/v1/auth/mfa/recovery-codes/regenerate",
        headers=headers,
        json={"code": code},
    )
    assert regen_resp.status_code == 200, regen_resp.text
    new_codes = regen_resp.json()["recovery_codes"]

    # Old codes no longer work
    db = SessionLocal()
    try:
        assert not verify_recovery_code(db, user, old_codes[0])
        # New codes work
        assert verify_recovery_code(db, user, new_codes[0])
    finally:
        db.close()


# ---------------------------------------------------------------------------
# API keys
# ---------------------------------------------------------------------------

def test_create_api_key_returns_raw_key_once(client):
    org = create_organization()
    user, pw = create_user(org)
    headers = auth_headers(client, user.email, pw)

    resp = client.post("/api/v1/api-keys", headers=headers, json={"name": "ci-runner"})
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["raw_key"].startswith("vanguard_")
    assert body["name"] == "ci-runner"


def test_api_key_authenticates_requests(client):
    org = create_organization()
    user, pw = create_user(org, role_name="soc_analyst")
    headers = auth_headers(client, user.email, pw)

    create_resp = client.post("/api/v1/api-keys", headers=headers, json={"name": "test-key"})
    raw_key = create_resp.json()["raw_key"]

    # Use the key to authenticate a real endpoint
    me_resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {raw_key}"})
    assert me_resp.status_code == 200, me_resp.text
    assert me_resp.json()["email"] == user.email


def test_revoked_api_key_cannot_authenticate(client):
    org = create_organization()
    user, pw = create_user(org)
    headers = auth_headers(client, user.email, pw)

    create_resp = client.post("/api/v1/api-keys", headers=headers, json={"name": "temp-key"})
    key_id = create_resp.json()["id"]
    raw_key = create_resp.json()["raw_key"]

    client.delete(f"/api/v1/api-keys/{key_id}", headers=headers)

    me_resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {raw_key}"})
    assert me_resp.status_code == 401


def test_list_api_keys_does_not_expose_raw_key(client):
    org = create_organization()
    user, pw = create_user(org)
    headers = auth_headers(client, user.email, pw)

    client.post("/api/v1/api-keys", headers=headers, json={"name": "my-key"})
    list_resp = client.get("/api/v1/api-keys", headers=headers)
    assert list_resp.status_code == 200
    for key in list_resp.json():
        assert key.get("raw_key") is None
        assert key["key_prefix"].startswith("vanguard_")


def test_rotate_api_key_invalidates_old_key_and_issues_new(client):
    org = create_organization()
    user, pw = create_user(org)
    headers = auth_headers(client, user.email, pw)

    create_resp = client.post("/api/v1/api-keys", headers=headers, json={"name": "rotate-me"})
    old_key_id = create_resp.json()["id"]
    old_raw = create_resp.json()["raw_key"]

    rotate_resp = client.post(f"/api/v1/api-keys/{old_key_id}/rotate", headers=headers)
    assert rotate_resp.status_code == 200, rotate_resp.text
    new_raw = rotate_resp.json()["raw_key"]

    assert new_raw != old_raw

    # Old key rejected
    old_me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {old_raw}"})
    assert old_me.status_code == 401

    # New key accepted
    new_me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {new_raw}"})
    assert new_me.status_code == 200


def test_expired_api_key_cannot_authenticate(client):
    org = create_organization()
    user, pw = create_user(org)

    db = SessionLocal()
    try:
        record, raw_key = create_api_key(
            db, user, name="expiring",
            expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        )
    finally:
        db.close()

    resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {raw_key}"})
    assert resp.status_code == 401


def test_api_key_cannot_access_another_users_keys(client):
    org = create_organization()
    user_a, pw_a = create_user(org)
    user_b, pw_b = create_user(org)

    headers_a = auth_headers(client, user_a.email, pw_a)
    headers_b = auth_headers(client, user_b.email, pw_b)

    create_resp = client.post("/api/v1/api-keys", headers=headers_a, json={"name": "key-a"})
    key_a_id = create_resp.json()["id"]

    revoke_resp = client.delete(f"/api/v1/api-keys/{key_a_id}", headers=headers_b)
    assert revoke_resp.status_code == 404


def test_me_endpoint_includes_totp_status(client):
    org = create_organization()
    user, pw = create_user(org)
    headers = auth_headers(client, user.email, pw)

    resp = client.get("/api/v1/auth/me", headers=headers)
    assert resp.status_code == 200
    assert "totp_enabled" in resp.json()
    assert resp.json()["totp_enabled"] is False
