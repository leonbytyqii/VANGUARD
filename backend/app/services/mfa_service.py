"""
Phase 16 — TOTP MFA and recovery-code lifecycle.

Design decisions:
- TOTP secrets are encrypted at rest using Fernet (symmetric, authenticated
  encryption). The key comes from settings.MFA_ENCRYPTION_KEY. This is
  application-layer encryption on top of whatever the DB provides, so a
  SQL-injection dump or DB backup leak does not expose usable TOTP secrets
  without also compromising the application key.
- Recovery codes are hashed with Argon2id (same library used for passwords).
  They are NEVER stored plaintext. The raw codes are returned to the caller
  ONCE and never again.
- The MFA login challenge uses a short-lived (5-minute) signed JWT bound to
  the user's id. If that JWT is not consumed within the window the user must
  restart the login flow. The token is single-use: it is embedded in the
  access-token issuance path and the claims are verified before any tokens
  are issued.
"""
from __future__ import annotations

import hashlib
import secrets
import string
from datetime import datetime, timezone

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.auth import RecoveryCode, TOTPDevice
from app.models.user import User
from app.services.audit import log_audit_event

_ph = PasswordHasher()

_RECOVERY_CODE_ALPHABET = string.ascii_uppercase + string.digits
_RECOVERY_CODE_LENGTH = 10  # displayed as XXXXX-XXXXX


def _fernet() -> Fernet:
    key = settings.MFA_ENCRYPTION_KEY.encode()
    # If the key isn't valid base64 Fernet format (dev default), derive one
    # via SHA-256 so the dev default doesn't crash on startup.
    try:
        return Fernet(key)
    except (ValueError, Exception):
        import base64
        derived = base64.urlsafe_b64encode(hashlib.sha256(key).digest())
        return Fernet(derived)


def _encrypt_secret(plaintext: str) -> str:
    return _fernet().encrypt(plaintext.encode()).decode()


def _decrypt_secret(ciphertext: str) -> str:
    try:
        return _fernet().decrypt(ciphertext.encode()).decode()
    except InvalidToken as exc:
        raise MFAError("TOTP secret decryption failed — key mismatch or corruption.") from exc


def _generate_recovery_codes() -> list[str]:
    codes = []
    for _ in range(settings.MFA_RECOVERY_CODE_COUNT):
        raw = "".join(secrets.choice(_RECOVERY_CODE_ALPHABET) for _ in range(_RECOVERY_CODE_LENGTH))
        codes.append(f"{raw[:5]}-{raw[5:]}")
    return codes


def _hash_recovery_code(code: str) -> str:
    return _ph.hash(code.replace("-", "").upper())


def _verify_recovery_code(code: str, hashed: str) -> bool:
    try:
        return _ph.verify(hashed, code.replace("-", "").upper())
    except VerifyMismatchError:
        return False


class MFAError(Exception):
    def __init__(self, message: str, status_code: int = 400):
        self.message = message
        self.status_code = status_code
        super().__init__(message)


class MFANotEnrolledError(MFAError):
    def __init__(self):
        super().__init__("MFA is not configured for this account.", status_code=404)


class MFAAlreadyEnabledError(MFAError):
    def __init__(self):
        super().__init__("MFA is already enabled. Disable it first to re-enrol.", status_code=409)


class InvalidTOTPError(MFAError):
    def __init__(self):
        super().__init__("The provided code is incorrect or expired.", status_code=400)


# ---------------------------------------------------------------------------
# Enrolment
# ---------------------------------------------------------------------------


def begin_totp_setup(db: Session, user: User) -> dict:
    """
    Generate a new TOTP secret for the user and persist it (unconfirmed).
    Returns the provisioning URI for QR-code display and the base32 secret
    for manual entry. MFA is NOT yet active until confirm_totp_setup() is
    called with a valid code.
    """
    if user.totp_enabled:
        raise MFAAlreadyEnabledError()

    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret, issuer=settings.MFA_ISSUER)
    uri = totp.provisioning_uri(name=user.email, issuer_name=settings.MFA_ISSUER)

    existing = db.query(TOTPDevice).filter(TOTPDevice.user_id == user.id).one_or_none()
    if existing:
        existing.encrypted_secret = _encrypt_secret(secret)
        existing.confirmed = False
        existing.enrolled_at = None
        db.add(existing)
    else:
        db.add(TOTPDevice(user_id=user.id, encrypted_secret=_encrypt_secret(secret), confirmed=False))
    db.commit()

    log_audit_event(
        db, action="mfa_setup_initiated", actor_id=user.id, actor_label=user.email,
        resource_type="user", resource_id=str(user.id), outcome="success",
    )
    return {"provisioning_uri": uri, "secret": secret}


def confirm_totp_setup(db: Session, user: User, code: str) -> list[str]:
    """
    Verify the first TOTP code from the authenticator app. On success:
    - marks the device as confirmed
    - sets user.totp_enabled = True
    - generates and returns a fresh set of recovery codes (shown once)
    Returns the plaintext recovery codes.
    """
    device = db.query(TOTPDevice).filter(TOTPDevice.user_id == user.id, TOTPDevice.confirmed.is_(False)).one_or_none()
    if device is None:
        raise MFANotEnrolledError()

    secret = _decrypt_secret(device.encrypted_secret)
    totp = pyotp.TOTP(secret)
    if not totp.verify(code, valid_window=1):
        raise InvalidTOTPError()

    device.confirmed = True
    device.enrolled_at = datetime.now(timezone.utc)
    device.last_used_at = datetime.now(timezone.utc)
    db.add(device)

    user.totp_enabled = True
    db.add(user)

    plain_codes = _issue_recovery_codes(db, user)
    db.commit()

    log_audit_event(
        db, action="mfa_enabled", actor_id=user.id, actor_label=user.email,
        resource_type="user", resource_id=str(user.id), outcome="success",
        details={"recovery_codes_issued": len(plain_codes)},
    )
    return plain_codes


def disable_totp(db: Session, user: User, code: str) -> None:
    """
    Disable TOTP. Requires a valid TOTP code (or recovery code) to prevent
    an attacker who has only the user's password from silently downgrading MFA.
    """
    if not user.totp_enabled:
        raise MFANotEnrolledError()

    verify_totp_or_recovery(db, user, code)

    device = db.query(TOTPDevice).filter(TOTPDevice.user_id == user.id).one_or_none()
    if device:
        db.delete(device)

    db.query(RecoveryCode).filter(RecoveryCode.user_id == user.id).delete()

    user.totp_enabled = False
    db.add(user)
    db.commit()

    log_audit_event(
        db, action="mfa_disabled", actor_id=user.id, actor_label=user.email,
        resource_type="user", resource_id=str(user.id), outcome="success",
    )


# ---------------------------------------------------------------------------
# Verification (login challenge path)
# ---------------------------------------------------------------------------


def verify_totp(db: Session, user: User, code: str) -> None:
    """Verify a TOTP code during login. Raises InvalidTOTPError on failure."""
    device = db.query(TOTPDevice).filter(TOTPDevice.user_id == user.id, TOTPDevice.confirmed.is_(True)).one_or_none()
    if device is None:
        raise MFANotEnrolledError()

    secret = _decrypt_secret(device.encrypted_secret)
    totp = pyotp.TOTP(secret)
    if not totp.verify(code, valid_window=1):
        raise InvalidTOTPError()

    device.last_used_at = datetime.now(timezone.utc)
    db.add(device)
    db.commit()


def verify_recovery_code(db: Session, user: User, code: str) -> bool:
    """
    Try all unused recovery codes for the user. Returns True and marks the
    code used if one matches; returns False otherwise.
    """
    unused = db.query(RecoveryCode).filter(
        RecoveryCode.user_id == user.id, RecoveryCode.used_at.is_(None)
    ).all()
    for record in unused:
        if _verify_recovery_code(code, record.code_hash):
            record.used_at = datetime.now(timezone.utc)
            db.add(record)
            db.commit()
            log_audit_event(
                db, action="mfa_recovery_code_used", actor_id=user.id, actor_label=user.email,
                resource_type="user", resource_id=str(user.id), outcome="success",
            )
            return True
    return False


def verify_totp_or_recovery(db: Session, user: User, code: str) -> None:
    """
    Accepts either a 6-digit TOTP code or a XXXXX-XXXXX recovery code.
    Raises InvalidTOTPError if neither matches.
    """
    if "-" in code or len(code) == 10:
        if verify_recovery_code(db, user, code):
            return
        raise InvalidTOTPError()
    try:
        verify_totp(db, user, code)
    except InvalidTOTPError:
        # Try recovery code as fallback (user might type a 10-char code without dash)
        if not verify_recovery_code(db, user, code):
            raise


# ---------------------------------------------------------------------------
# Recovery code management
# ---------------------------------------------------------------------------


def _issue_recovery_codes(db: Session, user: User) -> list[str]:
    """Delete existing codes and issue a fresh batch. Returns plaintext codes."""
    db.query(RecoveryCode).filter(RecoveryCode.user_id == user.id).delete()
    plain_codes = _generate_recovery_codes()
    for code in plain_codes:
        db.add(RecoveryCode(user_id=user.id, code_hash=_hash_recovery_code(code)))
    return plain_codes


def regenerate_recovery_codes(db: Session, user: User, totp_code: str) -> list[str]:
    """
    Regenerate recovery codes. Requires a valid TOTP code to authorise.
    Returns the new plaintext codes (shown once).
    """
    if not user.totp_enabled:
        raise MFANotEnrolledError()
    verify_totp(db, user, totp_code)

    plain_codes = _issue_recovery_codes(db, user)
    db.commit()

    log_audit_event(
        db, action="mfa_recovery_codes_regenerated", actor_id=user.id, actor_label=user.email,
        resource_type="user", resource_id=str(user.id), outcome="success",
        details={"count": len(plain_codes)},
    )
    return plain_codes


def recovery_codes_remaining(db: Session, user: User) -> int:
    """Return the count of unused recovery codes for the user."""
    return db.query(RecoveryCode).filter(
        RecoveryCode.user_id == user.id, RecoveryCode.used_at.is_(None)
    ).count()
