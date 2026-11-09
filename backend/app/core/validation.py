"""
Lightweight email syntax validation used instead of Pydantic's `EmailStr`.

Why: `EmailStr` (via the `email-validator` package) hard-rejects any
address whose domain ends in an RFC 6761 special-use TLD — including
`.local`, which is the single most common domain suffix in real-world
Active Directory / internal corporate networks (exactly the environment a
SOC platform's analysts and default bootstrap accounts live in). Phase 2
testing caught this directly: the seeded bootstrap admin
(admin@vanguard.local) could not log in through the API because of it. A
syntax-only check avoids rejecting legitimate internal users while still
catching malformed input.
"""
import re

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def validate_email_syntax(value: str) -> str:
    value = value.strip()
    if len(value) > 254 or not _EMAIL_RE.match(value):
        raise ValueError("not a valid email address")
    return value.lower()
