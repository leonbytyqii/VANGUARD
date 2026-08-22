import uuid
from datetime import datetime

from pydantic import BaseModel, field_validator

from app.core.security import validate_password_policy
from app.core.validation import validate_email_syntax


class UserCreateRequest(BaseModel):
    email: str
    full_name: str
    password: str
    role: str  # role name, e.g. "soc_analyst"

    @field_validator("email")
    @classmethod
    def _validate_email(cls, v: str) -> str:
        return validate_email_syntax(v)

    @field_validator("password")
    @classmethod
    def _validate_policy(cls, v: str) -> str:
        validate_password_policy(v)
        return v


class UserUpdateRequest(BaseModel):
    full_name: str | None = None
    role: str | None = None
    is_active: bool | None = None


class UserOut(BaseModel):
    id: uuid.UUID
    email: str
    full_name: str
    role: str
    is_active: bool
    organization_id: uuid.UUID
    last_login_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class RoleOut(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    permissions: list[str]

    model_config = {"from_attributes": True}
