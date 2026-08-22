"""
RBAC / authorization boundary tests: vertical privilege escalation
(lower-privileged role hitting a higher-privileged endpoint), horizontal /
IDOR-style access (reaching another tenant's resource by guessing an id),
and confirmation that every denial lands in the audit log.
"""
from app.db.session import SessionLocal
from app.models.audit import AuditLog
from tests.factories import auth_headers, create_organization, create_user


def test_unauthenticated_request_denied(client):
    resp = client.get("/api/v1/incidents")
    assert resp.status_code == 401


def test_viewer_cannot_create_incident_vertical_escalation(client):
    """Viewer role has incidents.read but not incidents.create."""
    org = create_organization()
    user, password = create_user(org, role_name="viewer")
    headers = auth_headers(client, user.email, password)

    resp = client.post(
        "/api/v1/incidents", headers=headers, json={"title": "Should not be allowed", "severity": "LOW"}
    )
    assert resp.status_code == 403


def test_soc_analyst_cannot_manage_users_vertical_escalation(client):
    """admin.users is admin-only; soc_analyst must not reach it even though
    it's a fully legitimate, authenticated user."""
    org = create_organization()
    user, password = create_user(org, role_name="soc_analyst")
    headers = auth_headers(client, user.email, password)

    resp = client.get("/api/v1/admin/users", headers=headers)
    assert resp.status_code == 403

    resp2 = client.post(
        "/api/v1/admin/users",
        headers=headers,
        json={"email": "new@example.com", "full_name": "New Guy", "password": "Sup3r$ecure1!", "role": "admin"},
    )
    assert resp2.status_code == 403


def test_soc_analyst_cannot_approve_response_actions(client):
    """response.approve is SOC Manager/Admin only; soc_analyst has response.request but not .approve."""
    org = create_organization()
    analyst, analyst_pw = create_user(org, role_name="soc_analyst")
    headers = auth_headers(client, analyst.email, analyst_pw)

    create_resp = client.post(
        "/api/v1/response/actions",
        headers=headers,
        json={"action_type": "isolate_host", "target": "WIN-01", "justification": "test"},
    )
    assert create_resp.status_code == 201
    action_id = create_resp.json()["id"]

    approve_resp = client.patch(f"/api/v1/response/actions/{action_id}/approve", headers=headers)
    assert approve_resp.status_code == 403


def test_soc_manager_can_approve_response_actions(client):
    org = create_organization()
    analyst, analyst_pw = create_user(org, role_name="soc_analyst")
    manager, manager_pw = create_user(org, role_name="soc_manager")

    analyst_headers = auth_headers(client, analyst.email, analyst_pw)
    manager_headers = auth_headers(client, manager.email, manager_pw)

    create_resp = client.post(
        "/api/v1/response/actions",
        headers=analyst_headers,
        json={"action_type": "block_ip", "target": "1.2.3.4", "justification": "test"},
    )
    action_id = create_resp.json()["id"]

    approve_resp = client.patch(f"/api/v1/response/actions/{action_id}/approve", headers=manager_headers)
    assert approve_resp.status_code == 200
    assert approve_resp.json()["status"] == "approved"


def test_cross_tenant_incident_access_returns_404_not_403(client):
    """
    IDOR / horizontal-escalation check: a user in org A must not be able to
    fetch an incident that belongs to org B, even by guessing/knowing its
    id. 404 (not 403) is deliberate — see app/core/scope.py — so the
    endpoint doesn't confirm the resource exists at all.
    """
    org_a = create_organization()
    org_b = create_organization()

    user_a, pw_a = create_user(org_a, role_name="soc_analyst")
    user_b, pw_b = create_user(org_b, role_name="soc_analyst")

    headers_b = auth_headers(client, user_b.email, pw_b)
    create_resp = client.post(
        "/api/v1/incidents", headers=headers_b, json={"title": "Org B incident", "severity": "HIGH"}
    )
    assert create_resp.status_code == 201
    incident_id = create_resp.json()["id"]

    headers_a = auth_headers(client, user_a.email, pw_a)
    cross_tenant_resp = client.get(f"/api/v1/incidents/{incident_id}", headers=headers_a)
    assert cross_tenant_resp.status_code == 404

    # ...but the legitimate owner org can see it fine.
    same_org_resp = client.get(f"/api/v1/incidents/{incident_id}", headers=headers_b)
    assert same_org_resp.status_code == 200


def test_cross_tenant_incident_list_never_leaks_other_org_rows(client):
    org_a = create_organization()
    org_b = create_organization()
    user_a, pw_a = create_user(org_a, role_name="soc_analyst")
    user_b, pw_b = create_user(org_b, role_name="soc_analyst")

    headers_a = auth_headers(client, user_a.email, pw_a)
    headers_b = auth_headers(client, user_b.email, pw_b)

    client.post("/api/v1/incidents", headers=headers_a, json={"title": "A-1", "severity": "LOW"})
    client.post("/api/v1/incidents", headers=headers_b, json={"title": "B-1", "severity": "LOW"})
    client.post("/api/v1/incidents", headers=headers_b, json={"title": "B-2", "severity": "LOW"})

    list_a = client.get("/api/v1/incidents", headers=headers_a).json()
    list_b = client.get("/api/v1/incidents", headers=headers_b).json()

    assert {i["title"] for i in list_a} == {"A-1"}
    assert {i["title"] for i in list_b} == {"B-1", "B-2"}


def test_cannot_assign_incident_to_user_in_another_organization(client):
    org_a = create_organization()
    org_b = create_organization()
    manager_a, pw_a = create_user(org_a, role_name="soc_manager")
    outsider_b, _ = create_user(org_b, role_name="soc_analyst")

    headers_a = auth_headers(client, manager_a.email, pw_a)
    create_resp = client.post("/api/v1/incidents", headers=headers_a, json={"title": "A incident", "severity": "HIGH"})
    incident_id = create_resp.json()["id"]

    assign_resp = client.patch(
        f"/api/v1/incidents/{incident_id}/assign", headers=headers_a, json={"assigned_to_id": str(outsider_b.id)}
    )
    assert assign_resp.status_code == 422


def test_permission_denial_is_recorded_in_audit_log(client):
    org = create_organization()
    user, password = create_user(org, role_name="viewer")
    headers = auth_headers(client, user.email, password)

    client.post("/api/v1/incidents", headers=headers, json={"title": "nope", "severity": "LOW"})

    db = SessionLocal()
    try:
        entry = (
            db.query(AuditLog)
            .filter(AuditLog.action == "permission_denied", AuditLog.actor_id == user.id)
            .order_by(AuditLog.timestamp.desc())
            .first()
        )
        assert entry is not None
        assert entry.outcome == "denied"
        assert entry.details.get("required_permission") == "incidents.create"
    finally:
        db.close()


def test_superuser_bypasses_role_permission_list_but_is_still_audited_on_success():
    """
    is_superuser=True (reserved for break-glass/admin bootstrap) bypasses
    the role permission list entirely — has_permission() short-circuits to
    True. This test documents that behavior explicitly rather than leaving
    it as an implicit side effect of User.has_permission().
    """
    from app.models.user import Role, User

    db = SessionLocal()
    try:
        role = db.query(Role).filter(Role.name == "viewer").one()
        fake_user = User(email="x@example.com", full_name="x", hashed_password="x", role_id=role.id, is_superuser=True)
        fake_user.role = role
        assert fake_user.has_permission("admin.users") is True
        assert fake_user.has_permission("literally.anything") is True
    finally:
        db.close()
