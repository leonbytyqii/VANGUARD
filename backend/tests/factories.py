"""
Test data builders. Write directly through app.db.session.SessionLocal
(the same session factory the running app uses) rather than the
`db_session` fixture, so data created here is visible to API requests made
through the `client` TestClient fixture in the same test.
"""
import uuid

from app.core.security import hash_password
from app.db.session import SessionLocal
from app.models.organization import Organization
from app.models.user import Role, User


def create_organization(slug: str | None = None, name: str | None = None) -> Organization:
    slug = slug or f"org-{uuid.uuid4().hex[:8]}"
    db = SessionLocal()
    try:
        org = Organization(name=name or slug, slug=slug)
        db.add(org)
        db.commit()
        db.refresh(org)
        return org
    finally:
        db.close()


def create_user(
    organization: Organization,
    *,
    role_name: str = "viewer",
    email: str | None = None,
    password: str = "Sup3r$ecurePassw0rd!",
    is_superuser: bool = False,
    is_active: bool = True,
) -> tuple[User, str]:
    email = email or f"user-{uuid.uuid4().hex[:10]}@example.com"
    db = SessionLocal()
    try:
        role = db.query(Role).filter(Role.name == role_name).one()
        user = User(
            email=email,
            full_name=f"Test User {email}",
            hashed_password=hash_password(password),
            role_id=role.id,
            organization_id=organization.id,
            is_superuser=is_superuser,
            is_active=is_active,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user, password
    finally:
        db.close()


def login(client, email: str, password: str):
    return client.post("/api/v1/auth/login", json={"email": email, "password": password})


def auth_headers(client, email: str, password: str) -> dict[str, str]:
    resp = login(client, email, password)
    assert resp.status_code == 200, resp.text
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
