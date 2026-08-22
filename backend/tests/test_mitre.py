"""
MITRE ATT&CK catalog: data-integrity invariants (no DB), sync
idempotency, relational detection-rule linking, alert tagging, and the
read-only coverage API.
"""
from datetime import datetime, timezone

from app.db.session import SessionLocal
from app.detections.registry import DETECTION_REGISTRY
from app.mitre.data import TACTICS, TECHNIQUES
from app.mitre.seed import link_detection_rules_to_techniques, sync_mitre_catalog
from app.models.detection import DetectionRule
from app.models.mitre import MitreTactic, MitreTechnique
from tests.factories import auth_headers, create_organization, create_user


# --- data-integrity invariants (pure, no DB) ---


def test_every_detection_registry_technique_id_is_in_the_seeded_catalog():
    """
    The invariant app/mitre/data.py's module docstring promises: a new
    detection referencing an unseeded MITRE technique should fail this
    test loudly, rather than silently producing an alert with a dangling
    MITRE tag at runtime.
    """
    seeded_ids = {t["technique_id"] for t in TECHNIQUES}
    referenced_ids: set[str] = set()
    for definition in DETECTION_REGISTRY:
        referenced_ids.update(definition.mitre_technique_ids)

    missing = referenced_ids - seeded_ids
    assert missing == set(), f"Detections reference MITRE technique IDs not in app/mitre/data.py: {missing}"


def test_every_subtechnique_parent_is_itself_seeded():
    seeded_ids = {t["technique_id"] for t in TECHNIQUES}
    for t in TECHNIQUES:
        parent = t.get("parent_technique_id")
        if parent:
            assert parent in seeded_ids, f"{t['technique_id']}'s parent {parent} is not itself seeded"


def test_every_technique_tactic_id_is_a_seeded_tactic():
    seeded_tactic_ids = {t["tactic_id"] for t in TACTICS}
    for t in TECHNIQUES:
        assert t["tactic_id"] in seeded_tactic_ids


def test_fourteen_tactics_with_distinct_matrix_order():
    assert len(TACTICS) == 14
    orders = [t["matrix_order"] for t in TACTICS]
    assert len(set(orders)) == 14  # all distinct
    assert sorted(orders) == list(range(1, 15))


# --- sync behavior (DB) ---


def test_mitre_sync_is_idempotent():
    db = SessionLocal()
    try:
        sync_mitre_catalog(db)
        tactic_count_1 = db.query(MitreTactic).count()
        technique_count_1 = db.query(MitreTechnique).count()

        sync_mitre_catalog(db)  # run again — must not duplicate
        assert db.query(MitreTactic).count() == tactic_count_1
        assert db.query(MitreTechnique).count() == technique_count_1
        assert tactic_count_1 == len(TACTICS)
        assert technique_count_1 == len(TECHNIQUES)
    finally:
        db.close()


def test_subtechnique_parent_linkage_resolved():
    db = SessionLocal()
    try:
        sync_mitre_catalog(db)
        sub = db.query(MitreTechnique).filter(MitreTechnique.technique_id == "T1059.001").one()
        parent = db.query(MitreTechnique).filter(MitreTechnique.technique_id == "T1059").one()
        assert sub.parent_technique_id == parent.id
        assert sub.is_subtechnique is True
        assert parent.is_subtechnique is False
    finally:
        db.close()


def test_detection_rules_are_relationally_linked_to_their_techniques():
    db = SessionLocal()
    try:
        sync_mitre_catalog(db)
        link_detection_rules_to_techniques(db)

        rule = db.query(DetectionRule).filter(DetectionRule.rule_id == "custom_cloud_privilege_escalation_chain").one()
        linked_ids = {t.technique_id for t in rule.mitre_techniques}
        assert linked_ids == set(rule.mitre_technique_ids)
        assert "T1548" in linked_ids
        assert "T1550.001" in linked_ids
        assert "T1078.004" in linked_ids
    finally:
        db.close()


# --- API ---


def test_viewer_can_list_tactics_with_technique_counts(client):
    org = create_organization()
    viewer, viewer_pw = create_user(org, role_name="viewer")
    headers = auth_headers(client, viewer.email, viewer_pw)

    resp = client.get("/api/v1/mitre/tactics", headers=headers)
    assert resp.status_code == 200
    tactics = resp.json()
    assert len(tactics) == 14
    assert tactics[0]["tactic_id"] == "TA0043"  # Reconnaissance, matrix_order=1, first
    execution = next(t for t in tactics if t["tactic_id"] == "TA0002")
    assert execution["technique_count"] > 0
    assert execution["covered_technique_count"] > 0  # T1059.001 etc. are covered


def test_list_techniques_filtered_by_tactic(client):
    org = create_organization()
    viewer, viewer_pw = create_user(org, role_name="viewer")
    headers = auth_headers(client, viewer.email, viewer_pw)

    resp = client.get("/api/v1/mitre/techniques", headers=headers, params={"tactic_id": "TA0002"})
    assert resp.status_code == 200
    technique_ids = {t["technique_id"] for t in resp.json()}
    assert "T1059.001" in technique_ids
    assert "T1003.001" not in technique_ids  # that's Credential Access (TA0006), not Execution


def test_list_techniques_covered_only_filter(client):
    org = create_organization()
    viewer, viewer_pw = create_user(org, role_name="viewer")
    headers = auth_headers(client, viewer.email, viewer_pw)

    resp = client.get("/api/v1/mitre/techniques", headers=headers, params={"covered_only": True})
    assert resp.status_code == 200
    technique_ids = {t["technique_id"] for t in resp.json()}
    assert "T1059.001" in technique_ids  # covered by sigma_suspicious_powershell_encoded
    assert "T1531" not in technique_ids  # Account Access Removal — no detection covers it


def test_list_techniques_search_by_name(client):
    org = create_organization()
    viewer, viewer_pw = create_user(org, role_name="viewer")
    headers = auth_headers(client, viewer.email, viewer_pw)

    resp = client.get("/api/v1/mitre/techniques", headers=headers, params={"q": "powershell"})
    assert resp.status_code == 200
    names = [t["name"] for t in resp.json()]
    assert any("PowerShell" in n for n in names)


def test_technique_coverage_lists_linked_detection_rules(client):
    org = create_organization()
    viewer, viewer_pw = create_user(org, role_name="viewer")
    headers = auth_headers(client, viewer.email, viewer_pw)

    resp = client.get("/api/v1/mitre/techniques/T1059.001/coverage", headers=headers)
    assert resp.status_code == 200
    rule_ids = {r["rule_id"] for r in resp.json()}
    assert "sigma_suspicious_powershell_encoded" in rule_ids


def test_technique_coverage_404_for_unknown_technique(client):
    org = create_organization()
    viewer, viewer_pw = create_user(org, role_name="viewer")
    headers = auth_headers(client, viewer.email, viewer_pw)

    resp = client.get("/api/v1/mitre/techniques/T9999.999/coverage", headers=headers)
    assert resp.status_code == 404


def test_matrix_shape_and_coverage_percentage(client):
    org = create_organization()
    viewer, viewer_pw = create_user(org, role_name="viewer")
    headers = auth_headers(client, viewer.email, viewer_pw)

    resp = client.get("/api/v1/mitre/matrix", headers=headers)
    assert resp.status_code == 200
    body = resp.json()

    assert len(body["tactics"]) == 14
    assert [c["matrix_order"] for c in body["tactics"]] == sorted(c["matrix_order"] for c in body["tactics"])
    assert body["total_techniques"] == len(TECHNIQUES)

    all_covered_referenced = set()
    for definition in DETECTION_REGISTRY:
        all_covered_referenced.update(definition.mitre_technique_ids)
    assert body["covered_techniques"] == len(all_covered_referenced)
    assert body["coverage_pct"] == round(len(all_covered_referenced) / len(TECHNIQUES) * 100, 1)

    execution_column = next(c for c in body["tactics"] if c["tactic_id"] == "TA0002")
    powershell_cell = next(t for t in execution_column["techniques"] if t["technique_id"] == "T1059.001")
    assert powershell_cell["is_subtechnique"] is True
    assert powershell_cell["parent_technique_id"] == "T1059"
    assert powershell_cell["covered"] is True
    assert "sigma_suspicious_powershell_encoded" in powershell_cell["detection_rule_ids"]


# --- alert tagging integration ---


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def test_alert_carries_relational_mitre_tags(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, admin_pw)

    resp = client.post(
        "/api/v1/events",
        headers=headers,
        json={
            "source": "windows_sysmon",
            "timestamp": _iso_now(),
            "host": "MITRE-TAG-01",
            "event_type": "process_creation",
            "process": "powershell.exe",
            "command_line": "powershell.exe -enc AAAA",
        },
    )
    assert resp.status_code == 201

    alerts = client.get("/api/v1/alerts", headers=headers, params={"host": "MITRE-TAG-01"}).json()
    assert len(alerts) == 1
    tags = set(alerts[0]["mitre_technique_ids"])
    assert "T1059.001" in tags
    assert "T1027" in tags
