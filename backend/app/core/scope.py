"""
Tenant-scoping helper. Every query for a TenantScopedMixin resource
(hosts, events, alerts, incidents, iocs, cloud identities, AI
investigations, playbooks, blueprints, response actions) should be built
through `scoped_query` rather than `db.query(Model)` directly, so
cross-tenant access is prevented at the query layer instead of relying on
every route handler remembering to add the filter by hand.

Today there is exactly one Organization (seeded as 'default'), so this is
mostly enforcing "you only see your own org's data" as a no-op in practice
— but the moment a second organization exists, every endpoint built on top
of this helper is already isolated, which is the point: multi-tenancy
becomes a data-seeding change, not an application rewrite.
"""
from __future__ import annotations

from typing import TypeVar

from sqlalchemy.orm import Query, Session

from app.models.user import User

ModelT = TypeVar("ModelT")


def scoped_query(db: Session, model: type[ModelT], current_user: User) -> "Query[ModelT]":
    return db.query(model).filter(model.organization_id == current_user.organization_id)


def assert_same_organization(resource_organization_id, current_user: User) -> bool:
    """
    Returns True if the resource belongs to the caller's organization.
    Route handlers should treat False the same as "not found" (404), not
    403 — confirming a resource *exists* in another tenant is itself an
    information leak (IDOR-by-enumeration).
    """
    return resource_organization_id == current_user.organization_id
