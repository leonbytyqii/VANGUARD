"""
Detection engine tests. Per the master spec: every detection must be
proven both ways — "known malicious pattern -> detection triggered" and
"benign pattern -> no false alert" — plus rule-sync idempotency, RBAC on
the read/run endpoints, and tenant scoping of fired detections.
"""
from datetime import datetime, timedelta, timezone

from app.db.session import SessionLocal
from app.detections.engine import sync_detection_rules
from app.detections.registry import DETECTION_REGISTRY
from app.models.detection import Detection, DetectionRule
from tests.factories import auth_headers, create_organization, create_user


def _ts(offset_seconds: int = 0) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)).isoformat()


def _detections_for_rule(rule_id: str) -> list[Detection]:
    db = SessionLocal()
    try:
        rule = db.query(DetectionRule).filter(DetectionRule.rule_id == rule_id).one()
        return db.query(Detection).filter(Detection.rule_id == rule.id).all()
    finally:
        db.close()


def _ingest(client, headers, body):
    resp = client.post("/api/v1/events", headers=headers, json=body)
    assert resp.status_code == 201, resp.text
    return resp.json()


# --- rule sync ---


def test_detection_rule_sync_creates_all_registry_rules_and_is_idempotent():
    db = SessionLocal()
    try:
        rules_by_id = sync_detection_rules(db)
        assert len(rules_by_id) == len(DETECTION_REGISTRY)
        for definition in DETECTION_REGISTRY:
            assert definition.rule_id in rules_by_id

        count_before = db.query(DetectionRule).count()
        sync_detection_rules(db)  # run again — must not duplicate
        count_after = db.query(DetectionRule).count()
        assert count_before == count_after
    finally:
        db.close()


# --- Sigma: suspicious PowerShell encoded command ---


def test_sigma_encoded_powershell_fires_on_malicious_pattern(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, admin_pw)

    _ingest(
        client,
        headers,
        {
            "source": "windows_sysmon",
            "timestamp": _ts(),
            "host": "WIN-ENC-01",
            "user": "alice",
            "event_type": "process_creation",
            "process": "powershell.exe",
            "command_line": "powershell.exe -enc SQBFAFgA==",
        },
    )

    matches = [d for d in _detections_for_rule("sigma_suspicious_powershell_encoded") if d.host_name == "WIN-ENC-01"]
    assert len(matches) == 1
    assert matches[0].risk_score == 75  # level: high


def test_sigma_encoded_powershell_does_not_fire_on_benign_powershell(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, admin_pw)

    _ingest(
        client,
        headers,
        {
            "source": "windows_sysmon",
            "timestamp": _ts(),
            "host": "WIN-BENIGN-01",
            "user": "alice",
            "event_type": "process_creation",
            "process": "powershell.exe",
            "command_line": "powershell.exe -Command Get-Process",
        },
    )

    matches = [d for d in _detections_for_rule("sigma_suspicious_powershell_encoded") if d.host_name == "WIN-BENIGN-01"]
    assert matches == []


# --- Sigma: PowerShell spawned by Office ---


def test_sigma_powershell_from_office_fires(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, admin_pw)

    _ingest(
        client,
        headers,
        {
            "source": "windows_sysmon",
            "timestamp": _ts(),
            "host": "WIN-OFFICE-01",
            "event_type": "process_creation",
            "process": "powershell.exe",
            "parent_process": "winword.exe",
            "command_line": "powershell.exe -w hidden",
        },
    )

    matches = [d for d in _detections_for_rule("sigma_powershell_spawned_by_office") if d.host_name == "WIN-OFFICE-01"]
    assert len(matches) == 1


def test_sigma_powershell_from_office_does_not_fire_for_normal_shell_parent(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, admin_pw)

    _ingest(
        client,
        headers,
        {
            "source": "windows_sysmon",
            "timestamp": _ts(),
            "host": "WIN-NORMAL-01",
            "event_type": "process_creation",
            "process": "powershell.exe",
            "parent_process": "explorer.exe",
            "command_line": "powershell.exe -Command Get-Process",
        },
    )

    matches = [d for d in _detections_for_rule("sigma_powershell_spawned_by_office") if d.host_name == "WIN-NORMAL-01"]
    assert matches == []


# --- Sigma: LSASS credential access ---


def test_sigma_lsass_dump_fires(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, admin_pw)

    _ingest(
        client,
        headers,
        {
            "source": "windows_sysmon",
            "timestamp": _ts(),
            "host": "WIN-LSASS-01",
            "event_type": "process_creation",
            "process": "procdump.exe",
            "command_line": "procdump.exe -ma lsass.exe lsass.dmp",
        },
    )

    matches = [d for d in _detections_for_rule("sigma_credential_access_lsass") if d.host_name == "WIN-LSASS-01"]
    assert len(matches) == 1
    assert matches[0].risk_score == 90  # level: critical


def test_sigma_lsass_dump_does_not_fire_for_unrelated_procdump_target(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, admin_pw)

    _ingest(
        client,
        headers,
        {
            "source": "windows_sysmon",
            "timestamp": _ts(),
            "host": "WIN-LSASS-02",
            "event_type": "process_creation",
            "process": "procdump.exe",
            "command_line": "procdump.exe -ma notepad.exe notepad.dmp",
        },
    )

    matches = [d for d in _detections_for_rule("sigma_credential_access_lsass") if d.host_name == "WIN-LSASS-02"]
    assert matches == []


# --- Sigma: scheduled task persistence ---


def test_sigma_scheduled_task_persistence_fires(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, admin_pw)

    _ingest(
        client,
        headers,
        {
            "source": "windows_sysmon",
            "timestamp": _ts(),
            "host": "WIN-PERSIST-01",
            "event_type": "process_creation",
            "process": "schtasks.exe",
            "command_line": r"schtasks.exe /create /tn Updater /tr C:\evil.exe /sc onlogon",
        },
    )

    matches = [d for d in _detections_for_rule("sigma_persistence_scheduled_task") if d.host_name == "WIN-PERSIST-01"]
    assert len(matches) == 1


def test_sigma_scheduled_task_query_does_not_fire(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, admin_pw)

    _ingest(
        client,
        headers,
        {
            "source": "windows_sysmon",
            "timestamp": _ts(),
            "host": "WIN-PERSIST-02",
            "event_type": "process_creation",
            "process": "schtasks.exe",
            "command_line": "schtasks.exe /query",
        },
    )

    matches = [d for d in _detections_for_rule("sigma_persistence_scheduled_task") if d.host_name == "WIN-PERSIST-02"]
    assert matches == []


# --- Custom: brute force ---


def test_custom_brute_force_fires_after_threshold_failures_then_success(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, admin_pw)
    host = "srv-bf-01"

    for i in range(5):
        _ingest(
            client,
            headers,
            {
                "source": "linux_auth",
                "timestamp": _ts(i),
                "host": host,
                "user": "root",
                "action": "failed_password",
                "src_ip": "198.51.100.9",
            },
        )
    _ingest(
        client,
        headers,
        {
            "source": "linux_auth",
            "timestamp": _ts(10),
            "host": host,
            "user": "root",
            "action": "accepted_password",
            "src_ip": "198.51.100.9",
        },
    )

    matches = [d for d in _detections_for_rule("custom_brute_force_login") if d.host_name == host]
    assert len(matches) == 1
    assert matches[0].evidence_summary["failed_attempt_count"] == 5

    # A subsequent sudo command escalates the same chain to a higher score.
    _ingest(
        client,
        headers,
        {
            "source": "linux_auth",
            "timestamp": _ts(20),
            "host": host,
            "user": "root",
            "action": "sudo_command",
            "src_ip": "198.51.100.9",
        },
    )
    escalated = [
        d
        for d in _detections_for_rule("custom_brute_force_login")
        if d.host_name == host and d.evidence_summary.get("pattern") == "brute_force_then_success_then_privileged_action"
    ]
    assert len(escalated) == 1
    assert escalated[0].risk_score == 95


def test_custom_brute_force_does_not_fire_below_threshold(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, admin_pw)
    host = "srv-bf-02"

    for i in range(2):  # below FAILURE_THRESHOLD
        _ingest(
            client,
            headers,
            {
                "source": "linux_auth",
                "timestamp": _ts(i),
                "host": host,
                "user": "bob",
                "action": "failed_password",
                "src_ip": "198.51.100.10",
            },
        )
    _ingest(
        client,
        headers,
        {
            "source": "linux_auth",
            "timestamp": _ts(5),
            "host": host,
            "user": "bob",
            "action": "accepted_password",
            "src_ip": "198.51.100.10",
        },
    )

    matches = [d for d in _detections_for_rule("custom_brute_force_login") if d.host_name == host]
    assert matches == []


# --- Custom: lateral movement fan-out ---


def test_custom_lateral_movement_fires_on_multi_host_smb_fanout(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, admin_pw)
    src = "10.10.0.50"

    for i, dst in enumerate(["10.10.0.11", "10.10.0.12", "10.10.0.13"]):
        _ingest(
            client,
            headers,
            {
                "source": "firewall",
                "timestamp": _ts(i),
                "action": "allow",
                "src_ip": src,
                "dst_ip": dst,
                "dst_port": 445,
                "protocol": "tcp",
            },
        )

    matches = [d for d in _detections_for_rule("custom_lateral_movement_fanout") if src in str(d.evidence_summary.get("source_ip"))]
    assert len(matches) >= 1
    assert len(matches[-1].evidence_summary["distinct_destination_hosts"]) >= 3


def test_custom_lateral_movement_does_not_fire_on_single_connection(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, admin_pw)

    _ingest(
        client,
        headers,
        {
            "source": "firewall",
            "timestamp": _ts(),
            "action": "allow",
            "src_ip": "10.10.0.99",
            "dst_ip": "10.10.0.14",
            "dst_port": 445,
            "protocol": "tcp",
        },
    )

    matches = [
        d for d in _detections_for_rule("custom_lateral_movement_fanout") if d.evidence_summary.get("source_ip") == "10.10.0.99"
    ]
    assert matches == []


# --- Custom: suspicious outbound connection ---


def test_custom_suspicious_outbound_port_fires(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, admin_pw)

    _ingest(
        client,
        headers,
        {
            "source": "firewall",
            "timestamp": _ts(),
            "action": "allow",
            "src_ip": "10.20.0.5",
            "dst_ip": "203.0.113.77",
            "dst_port": 4444,
            "protocol": "tcp",
        },
    )

    matches = [d for d in _detections_for_rule("custom_suspicious_outbound_port") if d.evidence_summary.get("dst_ip") == "203.0.113.77"]
    assert len(matches) == 1


def test_custom_suspicious_outbound_port_does_not_fire_for_standard_https(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, admin_pw)

    _ingest(
        client,
        headers,
        {
            "source": "firewall",
            "timestamp": _ts(),
            "action": "allow",
            "src_ip": "10.20.0.6",
            "dst_ip": "203.0.113.88",
            "dst_port": 443,
            "protocol": "tcp",
        },
    )

    matches = [d for d in _detections_for_rule("custom_suspicious_outbound_port") if d.evidence_summary.get("dst_ip") == "203.0.113.88"]
    assert matches == []


# --- Custom: DNS DGA entropy ---


def test_custom_dns_dga_fires_on_high_entropy_domain(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, admin_pw)

    _ingest(
        client,
        headers,
        {"source": "dns", "timestamp": _ts(), "src_ip": "10.30.0.5", "domain": "xk3jz9qv7mwplr2t.com"},
    )

    matches = [d for d in _detections_for_rule("custom_dns_anomaly_dga") if d.evidence_summary.get("domain") == "xk3jz9qv7mwplr2t.com"]
    assert len(matches) == 1


def test_custom_dns_dga_does_not_fire_on_normal_domain(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, admin_pw)

    _ingest(
        client,
        headers,
        {"source": "dns", "timestamp": _ts(), "src_ip": "10.30.0.6", "domain": "www.microsoft.com"},
    )

    matches = [d for d in _detections_for_rule("custom_dns_anomaly_dga") if d.evidence_summary.get("domain") == "www.microsoft.com"]
    assert matches == []


# --- Custom: impossible travel proxy ---


def test_custom_impossible_travel_fires_on_multi_ip_login(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, admin_pw)

    _ingest(
        client,
        headers,
        {
            "source": "linux_auth",
            "timestamp": _ts(0),
            "host": "srv-travel-01",
            "user": "carol",
            "action": "accepted_password",
            "src_ip": "203.0.113.1",
        },
    )
    _ingest(
        client,
        headers,
        {
            "source": "linux_auth",
            "timestamp": _ts(120),
            "host": "srv-travel-01",
            "user": "carol",
            "action": "accepted_password",
            "src_ip": "198.18.0.1",
        },
    )

    matches = [d for d in _detections_for_rule("custom_impossible_travel_proxy") if d.user == "carol"]
    assert len(matches) == 1


def test_custom_impossible_travel_does_not_fire_for_same_ip(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, admin_pw)

    for i in range(2):
        _ingest(
            client,
            headers,
            {
                "source": "linux_auth",
                "timestamp": _ts(i * 60),
                "host": "srv-travel-02",
                "user": "dave",
                "action": "accepted_password",
                "src_ip": "203.0.113.2",
            },
        )

    matches = [d for d in _detections_for_rule("custom_impossible_travel_proxy") if d.user == "dave"]
    assert matches == []


# --- Custom: unusual IAM activity ---


def test_custom_unusual_iam_activity_fires_on_policy_change(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, admin_pw)

    _ingest(
        client,
        headers,
        {
            "source": "cloudtrail",
            "timestamp": _ts(),
            "event_type": "PutUserPolicy",
            "cloud_account": "111122223333",
            "user": "eve",
        },
    )

    matches = [d for d in _detections_for_rule("custom_unusual_iam_activity") if d.user == "eve"]
    assert len(matches) == 1


def test_custom_unusual_iam_activity_does_not_fire_on_read_only_call(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, admin_pw)

    _ingest(
        client,
        headers,
        {
            "source": "cloudtrail",
            "timestamp": _ts(),
            "event_type": "GetObject",
            "cloud_account": "111122223333",
            "user": "frank",
        },
    )

    matches = [d for d in _detections_for_rule("custom_unusual_iam_activity") if d.user == "frank"]
    assert matches == []


# --- Custom: suspicious API key usage ---


def test_custom_suspicious_api_key_usage_fires_on_new_source(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, admin_pw)

    _ingest(
        client,
        headers,
        {
            "source": "cloudtrail",
            "timestamp": _ts(0),
            "event_type": "CreateAccessKey",
            "cloud_account": "111122223333",
            "user": "grace",
            "src_ip": "10.40.0.1",
        },
    )
    _ingest(
        client,
        headers,
        {
            "source": "cloudtrail",
            "timestamp": _ts(60),
            "event_type": "ListBuckets",
            "cloud_account": "111122223333",
            "user": "grace",
            "src_ip": "45.33.10.20",
        },
    )

    matches = [d for d in _detections_for_rule("custom_suspicious_api_key_usage") if d.user == "grace"]
    assert len(matches) == 1


def test_custom_suspicious_api_key_usage_does_not_fire_from_same_source(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, admin_pw)

    _ingest(
        client,
        headers,
        {
            "source": "cloudtrail",
            "timestamp": _ts(0),
            "event_type": "CreateAccessKey",
            "cloud_account": "111122223333",
            "user": "heidi",
            "src_ip": "10.40.0.2",
        },
    )
    _ingest(
        client,
        headers,
        {
            "source": "cloudtrail",
            "timestamp": _ts(60),
            "event_type": "ListBuckets",
            "cloud_account": "111122223333",
            "user": "heidi",
            "src_ip": "10.40.0.2",
        },
    )

    matches = [d for d in _detections_for_rule("custom_suspicious_api_key_usage") if d.user == "heidi"]
    assert matches == []


# --- Custom: cloud privilege escalation chain ---


def test_custom_cloud_privilege_escalation_fires_on_assume_role_then_sensitive_action(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, admin_pw)

    _ingest(
        client,
        headers,
        {
            "source": "cloudtrail",
            "timestamp": _ts(0),
            "event_type": "AssumeRole",
            "cloud_account": "111122223333",
            "user": "ivan",
            "iam_role": "arn:aws:iam::111122223333:role/DeveloperRole",
        },
    )
    _ingest(
        client,
        headers,
        {
            "source": "cloudtrail",
            "timestamp": _ts(60),
            "event_type": "PutRolePolicy",
            "cloud_account": "111122223333",
            "user": "ivan",
        },
    )

    matches = [d for d in _detections_for_rule("custom_cloud_privilege_escalation_chain") if d.user == "ivan"]
    assert len(matches) == 1
    assert matches[0].risk_score == 90


def test_custom_cloud_privilege_escalation_does_not_fire_without_assume_role(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, admin_pw)

    _ingest(
        client,
        headers,
        {
            "source": "cloudtrail",
            "timestamp": _ts(),
            "event_type": "PutRolePolicy",
            "cloud_account": "111122223333",
            "user": "judy",
        },
    )

    matches = [d for d in _detections_for_rule("custom_cloud_privilege_escalation_chain") if d.user == "judy"]
    assert matches == []


# --- RBAC ---


def test_viewer_can_read_detection_rules_and_detections(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    viewer, viewer_pw = create_user(org, role_name="viewer")
    admin_headers = auth_headers(client, admin.email, admin_pw)

    _ingest(
        client,
        admin_headers,
        {
            "source": "windows_sysmon",
            "timestamp": _ts(),
            "host": "WIN-RBAC-01",
            "event_type": "process_creation",
            "process": "powershell.exe",
            "command_line": "powershell.exe -enc AAAA",
        },
    )

    viewer_headers = auth_headers(client, viewer.email, viewer_pw)
    rules_resp = client.get("/api/v1/detections/rules", headers=viewer_headers)
    assert rules_resp.status_code == 200
    assert len(rules_resp.json()) == len(DETECTION_REGISTRY)

    detections_resp = client.get("/api/v1/detections", headers=viewer_headers, params={"host": "WIN-RBAC-01"})
    assert detections_resp.status_code == 200
    assert len(detections_resp.json()) == 1


def test_viewer_cannot_trigger_manual_detection_run(client):
    org = create_organization()
    viewer, viewer_pw = create_user(org, role_name="viewer")
    headers = auth_headers(client, viewer.email, viewer_pw)

    resp = client.post("/api/v1/detections/run", headers=headers)
    assert resp.status_code == 403


def test_soc_manager_can_trigger_manual_detection_run(client):
    org = create_organization()
    manager, manager_pw = create_user(org, role_name="soc_manager")
    headers = auth_headers(client, manager.email, manager_pw)

    resp = client.post("/api/v1/detections/run", headers=headers)
    assert resp.status_code == 200
    assert "detections_fired" in resp.json()


# --- Tenant scoping ---


def test_detections_are_tenant_scoped(client):
    org_a = create_organization()
    org_b = create_organization()
    admin_a, pw_a = create_user(org_a, role_name="admin", is_superuser=True)
    admin_b, pw_b = create_user(org_b, role_name="admin", is_superuser=True)

    headers_a = auth_headers(client, admin_a.email, pw_a)
    headers_b = auth_headers(client, admin_b.email, pw_b)

    _ingest(
        client,
        headers_b,
        {
            "source": "windows_sysmon",
            "timestamp": _ts(),
            "host": "WIN-TENANT-01",
            "event_type": "process_creation",
            "process": "powershell.exe",
            "command_line": "powershell.exe -enc AAAA",
        },
    )

    list_a = client.get("/api/v1/detections", headers=headers_a, params={"host": "WIN-TENANT-01"}).json()
    assert list_a == []

    list_b = client.get("/api/v1/detections", headers=headers_b, params={"host": "WIN-TENANT-01"}).json()
    assert len(list_b) == 1
