import uuid
from datetime import datetime, timezone

from app.models import Alert, Detection, DetectionRule, Host, Organization, Role, User


def test_can_create_role_and_user(db_session):
    org = Organization(name="Test Org", slug=f"test-org-{uuid.uuid4().hex[:8]}")
    db_session.add(org)
    db_session.flush()

    role = Role(name="soc_analyst_test", description="test role")
    db_session.add(role)
    db_session.flush()

    user = User(
        email=f"analyst-{uuid.uuid4()}@example.com",
        full_name="Test Analyst",
        hashed_password="not-a-real-hash",
        role_id=role.id,
        organization_id=org.id,
    )
    db_session.add(user)
    db_session.flush()

    assert user.id is not None
    assert user.role.name == "soc_analyst_test"


def test_can_create_detection_and_alert(db_session):
    host = Host(hostname=f"WIN-{uuid.uuid4().hex[:8]}", os_family="windows")
    db_session.add(host)
    db_session.flush()

    rule = DetectionRule(
        rule_id=f"test.rule.{uuid.uuid4().hex[:8]}",
        title="Suspicious PowerShell",
        engine="custom_python",
        mitre_technique_ids=["T1059.001"],
    )
    db_session.add(rule)
    db_session.flush()

    detection = Detection(
        rule_id=rule.id,
        host_name=host.hostname,
        user="john",
        fired_at=datetime.now(timezone.utc),
        risk_score=75,
    )
    db_session.add(detection)
    db_session.flush()

    alert = Alert(
        title="Suspicious PowerShell execution",
        severity="HIGH",
        risk_score=75,
        source="windows_sysmon",
        detection_id=detection.id,
        host_name=host.hostname,
        user="john",
        alert_timestamp=datetime.now(timezone.utc),
    )
    db_session.add(alert)
    db_session.flush()

    assert alert.id is not None
    assert alert.detection_id == detection.id
