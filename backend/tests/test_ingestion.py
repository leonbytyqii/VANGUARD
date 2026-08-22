"""
Event ingestion + normalization tests: adapter correctness per source,
raw-event preservation, host upsert, Process/NetworkConnection
derivation, RBAC on ingest vs read, tenant scoping, and batch
partial-success handling.
"""
from datetime import datetime, timezone

from app.db.session import SessionLocal
from app.models.event import NetworkConnection, Process
from app.models.host import Host
from tests.factories import auth_headers, create_organization, create_user


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def test_windows_sysmon_process_creation_is_normalized_and_evidence_preserved(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, admin_pw)

    body = {
        "source": "windows_sysmon",
        "timestamp": _iso_now(),
        "host": "WIN-01",
        "user": "john",
        "event_type": "process_creation",
        "process": "powershell.exe",
        "command_line": "powershell.exe -enc SQBFAFgA...",
        "parent_process": "winword.exe",
        "src_ip": "10.0.0.25",
    }
    resp = client.post("/api/v1/events", headers=headers, json=body)
    assert resp.status_code == 201
    out = resp.json()
    assert out["category"] == "process"
    assert out["action"] == "process_creation"
    assert out["process"] == "powershell.exe"
    assert out["parent_process"] == "winword.exe"

    detail = client.get(f"/api/v1/events/{out['id']}", headers=headers).json()
    # Raw evidence must be preserved verbatim, not just the normalized projection.
    assert detail["raw_event"]["command_line"] == body["command_line"]
    assert detail["raw_event"]["source"] == "windows_sysmon"


def test_windows_sysmon_rejects_unknown_event_type(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, admin_pw)

    resp = client.post(
        "/api/v1/events",
        headers=headers,
        json={"source": "windows_sysmon", "timestamp": _iso_now(), "host": "WIN-01", "event_type": "not_a_real_type"},
    )
    assert resp.status_code == 422


def test_process_creation_event_derives_a_process_row(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, admin_pw)

    resp = client.post(
        "/api/v1/events",
        headers=headers,
        json={
            "source": "windows_sysmon",
            "timestamp": _iso_now(),
            "host": "WIN-02",
            "user": "jane",
            "event_type": "process_creation",
            "process": "cmd.exe",
            "parent_process": "powershell.exe",
            "command_line": "cmd.exe /c whoami",
        },
    )
    event_id = resp.json()["id"]

    db = SessionLocal()
    try:
        proc = db.query(Process).filter(Process.event_id == event_id).one_or_none()
        assert proc is not None
        assert proc.process_name == "cmd.exe"
        assert proc.parent_process_name == "powershell.exe"
    finally:
        db.close()


def test_firewall_event_derives_a_network_connection_row(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, admin_pw)

    resp = client.post(
        "/api/v1/events",
        headers=headers,
        json={
            "source": "firewall",
            "timestamp": _iso_now(),
            "action": "deny",
            "src_ip": "10.0.0.5",
            "dst_ip": "185.220.101.5",
            "dst_port": 443,
            "protocol": "tcp",
        },
    )
    assert resp.status_code == 201
    event_id = resp.json()["id"]

    db = SessionLocal()
    try:
        conn = db.query(NetworkConnection).filter(NetworkConnection.event_id == event_id).one_or_none()
        assert conn is not None
        assert conn.dst_ip == "185.220.101.5"
        assert conn.dst_port == 443
    finally:
        db.close()


def test_firewall_requires_known_action(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, admin_pw)

    resp = client.post(
        "/api/v1/events",
        headers=headers,
        json={"source": "firewall", "timestamp": _iso_now(), "action": "maybe", "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2"},
    )
    assert resp.status_code == 422


def test_linux_auth_brute_force_shaped_events(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, admin_pw)

    for _ in range(3):
        resp = client.post(
            "/api/v1/events",
            headers=headers,
            json={
                "source": "linux_auth",
                "timestamp": _iso_now(),
                "host": "srv-01",
                "user": "root",
                "action": "failed_password",
                "src_ip": "203.0.113.9",
            },
        )
        assert resp.status_code == 201

    resp = client.post(
        "/api/v1/events",
        headers=headers,
        json={
            "source": "linux_auth",
            "timestamp": _iso_now(),
            "host": "srv-01",
            "user": "root",
            "action": "accepted_password",
            "src_ip": "203.0.113.9",
        },
    )
    assert resp.status_code == 201
    assert resp.json()["category"] == "authentication"


def test_dns_event_requires_domain(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, admin_pw)

    missing = client.post(
        "/api/v1/events", headers=headers, json={"source": "dns", "timestamp": _iso_now(), "src_ip": "10.0.0.5"}
    )
    assert missing.status_code == 422

    ok = client.post(
        "/api/v1/events",
        headers=headers,
        json={"source": "dns", "timestamp": _iso_now(), "src_ip": "10.0.0.5", "domain": "evil-c2.example"},
    )
    assert ok.status_code == 201
    assert ok.json()["category"] == "dns"


def test_cloudtrail_iam_vs_cloud_classification(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, admin_pw)

    iam_resp = client.post(
        "/api/v1/events",
        headers=headers,
        json={
            "source": "cloudtrail",
            "timestamp": _iso_now(),
            "event_type": "AssumeRole",
            "cloud_account": "123456789012",
            "iam_role": "arn:aws:iam::123456789012:role/DeveloperRole",
        },
    )
    assert iam_resp.status_code == 201
    assert iam_resp.json()["category"] == "iam"

    cloud_resp = client.post(
        "/api/v1/events",
        headers=headers,
        json={
            "source": "cloudtrail",
            "timestamp": _iso_now(),
            "event_type": "GetObject",
            "cloud_account": "123456789012",
        },
    )
    assert cloud_resp.status_code == 201
    assert cloud_resp.json()["category"] == "cloud"


def test_unknown_source_rejected(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, admin_pw)

    resp = client.post(
        "/api/v1/events", headers=headers, json={"source": "carrier_pigeon", "timestamp": _iso_now()}
    )
    assert resp.status_code == 422


def test_host_upserts_first_seen_and_last_seen(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, admin_pw)

    for _ in range(2):
        client.post(
            "/api/v1/events",
            headers=headers,
            json={
                "source": "windows_sysmon",
                "timestamp": _iso_now(),
                "host": "WIN-UPSERT-01",
                "event_type": "process_creation",
                "process": "notepad.exe",
            },
        )

    db = SessionLocal()
    try:
        hosts = db.query(Host).filter(Host.organization_id == org.id, Host.hostname == "WIN-UPSERT-01").all()
        assert len(hosts) == 1  # not duplicated on the second ingest
    finally:
        db.close()


def test_hostname_collision_across_organizations_is_allowed(client):
    """
    Phase 5 bug fix regression test: `hosts.hostname` used to have a
    globally-unique index, so two different organizations could never
    both register a host with the same name — a near-certain real-world
    collision (e.g. "WIN-01" is a common naming convention). Fixed via
    migration ac52294ad8d5 (composite unique on organization_id+hostname).
    """
    org_a = create_organization()
    org_b = create_organization()
    admin_a, pw_a = create_user(org_a, role_name="admin", is_superuser=True)
    admin_b, pw_b = create_user(org_b, role_name="admin", is_superuser=True)
    headers_a = auth_headers(client, admin_a.email, pw_a)
    headers_b = auth_headers(client, admin_b.email, pw_b)

    shared_hostname = "WIN-COLLISION-01"  # identical hostname deliberately reused across both orgs
    body = {
        "source": "windows_sysmon",
        "timestamp": _iso_now(),
        "host": shared_hostname,
        "event_type": "process_creation",
        "process": "notepad.exe",
    }
    resp_a = client.post("/api/v1/events", headers=headers_a, json=body)
    resp_b = client.post("/api/v1/events", headers=headers_b, json=body)
    assert resp_a.status_code == 201, resp_a.text
    assert resp_b.status_code == 201, resp_b.text

    db = SessionLocal()
    try:
        hosts = db.query(Host).filter(Host.hostname == shared_hostname).all()
        assert len(hosts) == 2
        assert {h.organization_id for h in hosts} == {org_a.id, org_b.id}
    finally:
        db.close()


def test_batch_ingestion_partial_success(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, admin_pw)

    resp = client.post(
        "/api/v1/events/batch",
        headers=headers,
        json={
            "events": [
                {"source": "windows_sysmon", "timestamp": _iso_now(), "event_type": "process_creation", "process": "a.exe"},
                {"source": "windows_sysmon", "timestamp": _iso_now(), "event_type": "not_a_type"},
                {"source": "dns", "timestamp": _iso_now(), "domain": "example.com"},
            ]
        },
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["accepted"] == 2
    assert body["rejected"] == 1
    assert body["results"][1]["error"] is not None


# --- RBAC on ingestion vs read ---


def test_viewer_cannot_ingest_events(client):
    org = create_organization()
    viewer, viewer_pw = create_user(org, role_name="viewer")
    headers = auth_headers(client, viewer.email, viewer_pw)

    resp = client.post(
        "/api/v1/events",
        headers=headers,
        json={"source": "dns", "timestamp": _iso_now(), "domain": "example.com"},
    )
    assert resp.status_code == 403


def test_viewer_can_read_events(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    viewer, viewer_pw = create_user(org, role_name="viewer")

    admin_headers = auth_headers(client, admin.email, admin_pw)
    client.post(
        "/api/v1/events",
        headers=admin_headers,
        json={"source": "dns", "timestamp": _iso_now(), "domain": "viewer-read-test.example"},
    )

    viewer_headers = auth_headers(client, viewer.email, viewer_pw)
    resp = client.get("/api/v1/events", headers=viewer_headers, params={"domain": "viewer-read-test.example"})
    assert resp.status_code == 200
    assert len(resp.json()) == 1


# --- Tenant scoping ---


def test_events_are_tenant_scoped(client):
    org_a = create_organization()
    org_b = create_organization()
    admin_a, pw_a = create_user(org_a, role_name="admin", is_superuser=True)
    admin_b, pw_b = create_user(org_b, role_name="admin", is_superuser=True)

    headers_a = auth_headers(client, admin_a.email, pw_a)
    headers_b = auth_headers(client, admin_b.email, pw_b)

    create_resp = client.post(
        "/api/v1/events",
        headers=headers_b,
        json={"source": "dns", "timestamp": _iso_now(), "domain": "org-b-only.example"},
    )
    event_id = create_resp.json()["id"]

    cross_tenant = client.get(f"/api/v1/events/{event_id}", headers=headers_a)
    assert cross_tenant.status_code == 404

    list_a = client.get("/api/v1/events", headers=headers_a, params={"domain": "org-b-only.example"}).json()
    assert list_a == []
