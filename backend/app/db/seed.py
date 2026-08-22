"""
Idempotent baseline data seeding — safe to run on every container start
(see docker-entrypoint.sh) and directly in tests. Running it twice never
duplicates rows: everything is looked up by a natural key first.

Seeds, in order:
1. The default Organization (single-tenant deployments use exactly this one).
2. The permission catalog (app/core/permissions.py is the source of truth
   for the *codes*; this module only creates the rows).
3. The five RBAC roles and their permission grants.
4. A bootstrap Admin user — created only if no user exists yet. If
   ADMIN_BOOTSTRAP_PASSWORD isn't set in the environment, a random one is
   generated and printed once (never logged again, never stored in code).
5. The five AI Agent identities, with allowlists sourced directly from
   app.ai.agents.permissions so the seeded DB rows can never drift from the
   code that enforces against them.
6. The detection rule catalog (Sigma YAML + custom Python detections),
   via app.detections.engine.sync_detection_rules — see that module for
   why this is a sync rather than a one-time insert.
7. The curated MITRE ATT&CK catalog (tactics + techniques), then
   relationally links each DetectionRule to the techniques it declares —
   via app.mitre.seed.
8. The built-in threat-hunting query library (app.hunting.seed) — a
   curated set of Sigma-shaped hunt queries, runnable by every
   organization, seeded the same idempotent way as the detection catalog.
"""
from __future__ import annotations

import secrets

import structlog
from sqlalchemy.orm import Session

from app.ai.agents.permissions import AGENT_MAX_EFFECT, AGENT_TOOL_ALLOWLIST
from app.core.config import settings
from app.core.permissions import PERMISSIONS, ROLE_PERMISSIONS
from app.core.security import hash_password
from app.models.agent_identity import AgentIdentity
from app.models.organization import Organization
from app.models.user import Permission, Role, User

log = structlog.get_logger()

DEFAULT_ORG_SLUG = "default"
DEFAULT_ORG_NAME = "Default Organization"


def seed_organization(db: Session) -> Organization:
    org = db.query(Organization).filter(Organization.slug == DEFAULT_ORG_SLUG).one_or_none()
    if org is None:
        org = Organization(name=DEFAULT_ORG_NAME, slug=DEFAULT_ORG_SLUG)
        db.add(org)
        db.commit()
        db.refresh(org)
        log.info("seed_organization_created", slug=org.slug)
    return org


def seed_permissions(db: Session) -> dict[str, Permission]:
    existing = {p.code: p for p in db.query(Permission).all()}
    for code, description in PERMISSIONS.items():
        if code not in existing:
            perm = Permission(code=code, description=description)
            db.add(perm)
            existing[code] = perm
    db.commit()
    return {p.code: p for p in db.query(Permission).all()}


def seed_roles(db: Session, permissions_by_code: dict[str, Permission]) -> dict[str, Role]:
    existing = {r.name: r for r in db.query(Role).all()}
    for role_name, perm_codes in ROLE_PERMISSIONS.items():
        role = existing.get(role_name)
        if role is None:
            role = Role(name=role_name, description=f"{role_name.replace('_', ' ').title()} role")
            db.add(role)
            db.flush()
            existing[role_name] = role
        role.permissions = [permissions_by_code[c] for c in perm_codes]
        db.add(role)
    db.commit()
    log.info("seed_roles_synced", roles=list(ROLE_PERMISSIONS.keys()))
    return {r.name: r for r in db.query(Role).all()}


def seed_bootstrap_admin(db: Session, org: Organization, roles_by_name: dict[str, Role]) -> None:
    if db.query(User).count() > 0:
        return

    password = settings.ADMIN_BOOTSTRAP_PASSWORD
    generated = False
    if not password:
        password = secrets.token_urlsafe(18)
        generated = True

    admin_role = roles_by_name["admin"]
    admin = User(
        email=settings.ADMIN_BOOTSTRAP_EMAIL.lower(),
        full_name="Platform Administrator",
        hashed_password=hash_password(password),
        role_id=admin_role.id,
        organization_id=org.id,
        is_superuser=True,
        must_change_password=True,
    )
    db.add(admin)
    db.commit()

    if generated:
        log.warning(
            "seed_bootstrap_admin_created_with_generated_password",
            email=admin.email,
            password=password,
            note="Shown once. Log in and change it immediately (POST /api/v1/auth/change-password).",
        )
    else:
        log.info("seed_bootstrap_admin_created", email=admin.email)


def seed_agent_identities(db: Session) -> None:
    existing = {a.agent_type: a for a in db.query(AgentIdentity).all()}
    display_names = {
        "triage": "Triage Agent",
        "investigation": "Investigation Agent",
        "threat_hunt": "Threat Hunt Agent",
        "cloud_iam": "Cloud/IAM Agent",
        "response": "Response Agent",
    }
    for agent_type, allowlist in AGENT_TOOL_ALLOWLIST.items():
        agent = existing.get(agent_type.value)
        max_effect = AGENT_MAX_EFFECT[agent_type].value
        if agent is None:
            agent = AgentIdentity(
                agent_type=agent_type.value,
                display_name=display_names.get(agent_type.value, agent_type.value),
                allowed_tools=allowlist,
                max_effect=max_effect,
                enabled=True,
            )
        else:
            agent.allowed_tools = allowlist
            agent.max_effect = max_effect
        db.add(agent)
    db.commit()
    log.info("seed_agent_identities_synced", agents=[a.value for a in AGENT_TOOL_ALLOWLIST.keys()])


def seed_all() -> None:
    from app.db.session import SessionLocal
    from app.detections.engine import sync_detection_rules
    from app.hunting.seed import sync_builtin_hunt_queries
    from app.mitre.seed import link_detection_rules_to_techniques, sync_mitre_catalog

    db: Session = SessionLocal()
    try:
        org = seed_organization(db)
        permissions_by_code = seed_permissions(db)
        roles_by_name = seed_roles(db, permissions_by_code)
        seed_bootstrap_admin(db, org, roles_by_name)
        seed_agent_identities(db)
        sync_detection_rules(db)
        # Phase 6: MITRE catalog must exist before rules can be linked to it.
        sync_mitre_catalog(db)
        link_detection_rules_to_techniques(db)
        # Phase 7: built-in threat-hunting query library.
        sync_builtin_hunt_queries(db)
    finally:
        db.close()


if __name__ == "__main__":
    seed_all()
