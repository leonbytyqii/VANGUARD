"""
Alert generation + risk scoring, end to end through the real ingestion
API (events -> detections -> alerts), plus the Alert read/update API's
RBAC and tenant scoping.
"""
from datetime import datetime, timedelta, timezone

from app.db.session import SessionLocal
from app.models.host import Host
from tests.factories import auth_headers, create_organization, create_user

_BASE_TIME = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


def _ts(offset_minutes: float = 0) -> str:
    return (_BASE_TIME + timedelta(minutes=offset_minutes)).isoformat()


def _ingest(client, headers, body):
    resp = client.post("/api/v1/events", headers=headers, json=body)
    assert resp.status_code == 201, resp.text
    return resp.json()


def _encoded_powershell_event(host, offset_minutes=0):
    return {
        "source": "windows_sysmon",
        "timestamp": _ts(offset_minutes),
        "host": host,
        "user": "alice",
        "event_type": "process_creation",
        "process": "powershell.exe",
        "command_line": "powershell.exe -enc SQBFAFgA==",
    }


def _set_host_criticality(org_id, hostname, criticality):
    db = SessionLocal()
    try:
        host = db.query(Host).filter(Host.organization_id == org_id, Host.hostname == hostname).one()
        host.criticality = criticality
        db.add(host)
        db.commit()
    finally:
        db.close()


def _get_alerts(client, headers, **params):
    resp = client.get("/api/v1/alerts", headers=headers, params=params)
    assert resp.status_code == 200, resp.text
    return resp.json()


# --- basic generation ---


def test_alert_created_from_fired_detection(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, admin_pw)

    _ingest(client, headers, _encoded_powershell_event("ALERT-BASIC-01"))

    alerts = _get_alerts(client, headers, host="ALERT-BASIC-01")
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["title"] == "Suspicious PowerShell Encoded Command"
    assert alert["severity"] == "HIGH"
    assert alert["risk_score"] == 75  # base 75 (sigma level=high), standard criticality, no repeat offender
    assert alert["status"] == "new"
    assert alert["source"] == "detection_engine"
    assert alert["detection_id"] is not None
    assert len(alert["related_event_ids"]) == 1
    assert alert["evidence"]["detection_rule_id"] == "sigma_suspicious_powershell_encoded"


# --- dedup / reinforcement ---


def test_alert_reinforces_within_dedup_window_instead_of_duplicating(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, admin_pw)

    _ingest(client, headers, _encoded_powershell_event("ALERT-DEDUP-01", offset_minutes=0))
    _ingest(client, headers, _encoded_powershell_event("ALERT-DEDUP-01", offset_minutes=5))  # well within 30-min window

    alerts = _get_alerts(client, headers, host="ALERT-DEDUP-01")
    assert len(alerts) == 1
    assert len(alerts[0]["related_event_ids"]) == 2
    assert alerts[0]["evidence"]["reinforcement_count"] == 1


def test_alert_creates_new_row_after_dedup_window_expires(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, admin_pw)

    _ingest(client, headers, _encoded_powershell_event("ALERT-NODEDUP-01", offset_minutes=0))
    _ingest(client, headers, _encoded_powershell_event("ALERT-NODEDUP-01", offset_minutes=40))  # past the 30-min window

    alerts = _get_alerts(client, headers, host="ALERT-NODEDUP-01")
    assert len(alerts) == 2


# --- asset criticality ---


def test_alert_risk_score_reflects_asset_criticality(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, admin_pw)

    # Standard-criticality host (default) — no bonus.
    _ingest(client, headers, _encoded_powershell_event("ALERT-CRIT-STD-01"))
    std_alerts = _get_alerts(client, headers, host="ALERT-CRIT-STD-01")
    assert std_alerts[0]["risk_score"] == 75
    assert std_alerts[0]["severity"] == "HIGH"

    # Register the host first (benign event), then mark it critical, then
    # fire the same detection — should score 20 points higher and cross
    # into CRITICAL severity.
    _ingest(
        client,
        headers,
        {
            "source": "windows_sysmon",
            "timestamp": _ts(-10),
            "host": "ALERT-CRIT-HIGH-01",
            "event_type": "process_creation",
            "process": "notepad.exe",
        },
    )
    _set_host_criticality(org.id, "ALERT-CRIT-HIGH-01", "critical")
    _ingest(client, headers, _encoded_powershell_event("ALERT-CRIT-HIGH-01"))

    crit_alerts = _get_alerts(client, headers, host="ALERT-CRIT-HIGH-01")
    matching = [a for a in crit_alerts if a["title"] == "Suspicious PowerShell Encoded Command"]
    assert len(matching) == 1
    assert matching[0]["risk_score"] == 95  # 75 + 20 (critical asset bonus)
    assert matching[0]["severity"] == "CRITICAL"
    assert matching[0]["evidence"]["host_criticality"] == "critical"


# --- repeat offender ---


def test_alert_repeat_offender_bonus_applied_for_second_distinct_rule(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, admin_pw)
    host = "ALERT-REPEAT-01"

    # First distinct rule: suspicious outbound C2 port (base 60).
    _ingest(
        client,
        headers,
        {
            "source": "firewall",
            "timestamp": _ts(0),
            "host": host,
            "action": "allow",
            "src_ip": "10.60.0.5",
            "dst_ip": "203.0.113.44",
            "dst_port": 4444,
            "protocol": "tcp",
        },
    )
    # Second distinct rule, same host, well within the 24h repeat-offender
    # lookback: scheduled-task persistence (base 50).
    _ingest(
        client,
        headers,
        {
            "source": "windows_sysmon",
            "timestamp": _ts(10),
            "host": host,
            "event_type": "process_creation",
            "process": "schtasks.exe",
            "command_line": r"schtasks.exe /create /tn Updater /tr C:\evil.exe /sc onlogon",
        },
    )

    alerts = _get_alerts(client, headers, host=host)
    assert len(alerts) == 2

    persistence_alert = next(a for a in alerts if a["title"] == "Scheduled Task Creation via schtasks.exe")
    assert persistence_alert["evidence"]["repeat_offender"] is True
    assert persistence_alert["risk_score"] == 65  # 50 base + 0 criticality + 15 repeat-offender bonus
    assert persistence_alert["severity"] == "HIGH"

    outbound_alert = next(a for a in alerts if a["title"].startswith("Outbound Connection"))
    assert outbound_alert["evidence"]["repeat_offender"] is False
    assert outbound_alert["risk_score"] == 60


# --- alert update API ---


def test_soc_analyst_can_update_alert_status_and_add_note(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    analyst, analyst_pw = create_user(org, role_name="soc_analyst")
    admin_headers = auth_headers(client, admin.email, admin_pw)

    _ingest(client, admin_headers, _encoded_powershell_event("ALERT-UPDATE-01"))
    alert_id = _get_alerts(client, admin_headers, host="ALERT-UPDATE-01")[0]["id"]

    analyst_headers = auth_headers(client, analyst.email, analyst_pw)
    resp = client.patch(
        f"/api/v1/alerts/{alert_id}",
        headers=analyst_headers,
        json={"status": "triaged", "analyst_note": "Confirmed malicious — escalating."},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "triaged"
    assert len(body["evidence"]["analyst_notes"]) == 1
    assert body["evidence"]["analyst_notes"][0]["note"] == "Confirmed malicious — escalating."
    assert body["evidence"]["analyst_notes"][0]["by"] == analyst.email


def test_alert_update_rejects_invalid_status(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, admin_pw)

    _ingest(client, headers, _encoded_powershell_event("ALERT-BADSTATUS-01"))
    alert_id = _get_alerts(client, headers, host="ALERT-BADSTATUS-01")[0]["id"]

    resp = client.patch(f"/api/v1/alerts/{alert_id}", headers=headers, json={"status": "not_a_real_status"})
    assert resp.status_code == 422


def test_alert_assignment_auto_triages_a_new_alert(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    analyst, _ = create_user(org, role_name="soc_analyst")
    headers = auth_headers(client, admin.email, admin_pw)

    _ingest(client, headers, _encoded_powershell_event("ALERT-ASSIGN-01"))
    alert_id = _get_alerts(client, headers, host="ALERT-ASSIGN-01")[0]["id"]

    resp = client.patch(f"/api/v1/alerts/{alert_id}", headers=headers, json={"assigned_to_id": str(analyst.id)})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["assigned_to_id"] == str(analyst.id)
    assert body["status"] == "triaged"


# --- RBAC ---


def test_viewer_can_read_but_not_update_alerts(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    viewer, viewer_pw = create_user(org, role_name="viewer")
    admin_headers = auth_headers(client, admin.email, admin_pw)

    _ingest(client, admin_headers, _encoded_powershell_event("ALERT-RBAC-01"))

    viewer_headers = auth_headers(client, viewer.email, viewer_pw)
    read_resp = client.get("/api/v1/alerts", headers=viewer_headers, params={"host": "ALERT-RBAC-01"})
    assert read_resp.status_code == 200
    alert_id = read_resp.json()[0]["id"]

    update_resp = client.patch(f"/api/v1/alerts/{alert_id}", headers=viewer_headers, json={"status": "triaged"})
    assert update_resp.status_code == 403


# --- tenant scoping ---


def test_alerts_are_tenant_scoped(client):
    org_a = create_organization()
    org_b = create_organization()
    admin_a, pw_a = create_user(org_a, role_name="admin", is_superuser=True)
    admin_b, pw_b = create_user(org_b, role_name="admin", is_superuser=True)
    headers_a = auth_headers(client, admin_a.email, pw_a)
    headers_b = auth_headers(client, admin_b.email, pw_b)

    _ingest(client, headers_b, _encoded_powershell_event("ALERT-TENANT-01"))

    assert _get_alerts(client, headers_a, host="ALERT-TENANT-01") == []
    alerts_b = _get_alerts(client, headers_b, host="ALERT-TENANT-01")
    assert len(alerts_b) == 1

    cross_tenant = client.get(f"/api/v1/alerts/{alerts_b[0]['id']}", headers=headers_a)
    assert cross_tenant.status_code == 404
