"""
Threat-hunting engine (Phase 7): built-in query data-integrity, the safe
selection/condition matcher reused from the Sigma engine, run_hunt's
scan/match/persist behavior and bounds, idempotent builtin sync, and the
read/write/execute-gated coverage/CRUD API.
"""
from datetime import datetime, timedelta, timezone

import pytest

from app.db.session import SessionLocal
from app.hunting.builtin_queries import BUILTIN_HUNT_QUERIES
from app.hunting.engine import HuntQueryError, run_hunt, validate_query_definition
from app.hunting.seed import sync_builtin_hunt_queries
from app.mitre.data import TECHNIQUES
from app.models.hunting import HuntQuery
from tests.factories import auth_headers, create_organization, create_user

_SEEDED_TECHNIQUE_IDS = {t["technique_id"] for t in TECHNIQUES}


# --- data-integrity invariants (pure, no DB) ---


def test_every_builtin_hunt_mitre_id_is_in_the_seeded_catalog():
    """
    Same discipline Phase 6 enforces for DETECTION_REGISTRY: a builtin
    hunt referencing an unseeded MITRE technique should fail loudly here,
    not silently produce a dangling tag.
    """
    for hunt in BUILTIN_HUNT_QUERIES:
        for technique_id in hunt["mitre_technique_ids"]:
            assert technique_id in _SEEDED_TECHNIQUE_IDS, f"{hunt['name']!r} references unseeded technique {technique_id}"


def test_every_builtin_hunt_query_definition_validates():
    for hunt in BUILTIN_HUNT_QUERIES:
        validate_query_definition(hunt["query_definition"])  # raises on failure


def test_builtin_hunt_names_are_unique():
    names = [h["name"] for h in BUILTIN_HUNT_QUERIES]
    assert len(names) == len(set(names))


# --- validate_query_definition ---


def test_validate_rejects_missing_condition():
    with pytest.raises(HuntQueryError):
        validate_query_definition({"selection": {"Image|endswith": "\\cmd.exe"}})


def test_validate_rejects_no_selections():
    with pytest.raises(HuntQueryError):
        validate_query_definition({"condition": "selection"})


def test_validate_rejects_non_mapping_selection():
    with pytest.raises(HuntQueryError):
        validate_query_definition({"selection": "not a dict", "condition": "selection"})


def test_validate_rejects_unsafe_condition_syntax():
    """
    The condition string is walked by the same safe AST evaluator the
    Sigma engine uses (no eval()) — anything beyond selection names
    combined with and/or/not/() must be rejected, e.g. an attempted
    function call or attribute access.
    """
    with pytest.raises(HuntQueryError):
        validate_query_definition({"selection": {"Image": "cmd.exe"}, "condition": "selection.upper()"})


def test_validate_rejects_condition_referencing_unknown_selection():
    with pytest.raises(HuntQueryError):
        validate_query_definition({"selection_a": {"Image": "cmd.exe"}, "condition": "selection_b"})


# --- sync behavior (DB) ---


def test_builtin_hunt_sync_is_idempotent():
    db = SessionLocal()
    try:
        sync_builtin_hunt_queries(db)
        count_1 = db.query(HuntQuery).filter(HuntQuery.is_builtin.is_(True)).count()
        sync_builtin_hunt_queries(db)
        count_2 = db.query(HuntQuery).filter(HuntQuery.is_builtin.is_(True)).count()
        assert count_1 == count_2 == len(BUILTIN_HUNT_QUERIES)
    finally:
        db.close()


def test_builtin_hunt_queries_have_null_organization_id():
    db = SessionLocal()
    try:
        sync_builtin_hunt_queries(db)
        rows = db.query(HuntQuery).filter(HuntQuery.is_builtin.is_(True)).all()
        assert rows
        assert all(r.organization_id is None for r in rows)
    finally:
        db.close()


# --- run_hunt engine behavior (DB) ---


def _iso_now() -> datetime:
    return datetime.now(timezone.utc)


def test_run_hunt_rejects_inverted_time_range():
    db = SessionLocal()
    try:
        org = create_organization()
        now = _iso_now()
        with pytest.raises(HuntQueryError):
            run_hunt(
                db,
                organization_id=org.id,
                query_definition={"selection": {"Image": "cmd.exe"}, "condition": "selection"},
                time_range_start=now,
                time_range_end=now - timedelta(hours=1),
            )
    finally:
        db.close()


def test_run_hunt_rejects_time_range_exceeding_max_days():
    db = SessionLocal()
    try:
        org = create_organization()
        now = _iso_now()
        with pytest.raises(HuntQueryError):
            run_hunt(
                db,
                organization_id=org.id,
                query_definition={"selection": {"Image": "cmd.exe"}, "condition": "selection"},
                time_range_start=now - timedelta(days=90),
                time_range_end=now,
            )
    finally:
        db.close()


def test_run_hunt_matches_and_excludes_correctly(client):
    """
    Ingests one event that should match a broad PowerShell hunt and one
    that shouldn't, then confirms run_hunt's matched_event_ids reflects
    exactly that — the evidence-citation guarantee: a hunt must point at
    real, re-checkable Event rows, never assert a match without one.
    """
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, admin_pw)

    now = _iso_now()
    malicious = client.post(
        "/api/v1/events",
        headers=headers,
        json={
            "source": "windows_sysmon",
            "timestamp": now.isoformat(),
            "host": "HUNT-TEST-01",
            "event_type": "process_creation",
            "process": "powershell.exe",
            "command_line": "powershell.exe -w hidden -nop -c whoami",
        },
    )
    assert malicious.status_code == 201

    benign = client.post(
        "/api/v1/events",
        headers=headers,
        json={
            "source": "windows_sysmon",
            "timestamp": now.isoformat(),
            "host": "HUNT-TEST-01",
            "event_type": "process_creation",
            "process": "powershell.exe",
            "command_line": "powershell.exe Get-Process",
        },
    )
    assert benign.status_code == 201

    db = SessionLocal()
    try:
        hunt = next(h for h in BUILTIN_HUNT_QUERIES if h["name"] == "Broad PowerShell Obfuscation/Bypass Indicators")
        execution = run_hunt(
            db,
            organization_id=admin.organization_id,
            query_definition=hunt["query_definition"],
            time_range_start=now - timedelta(minutes=5),
            time_range_end=now + timedelta(minutes=5),
        )
        assert execution.status == "completed"
        assert execution.matched_event_count == 1
        assert execution.scanned_event_count == 2
        assert not execution.truncated_scan
        assert not execution.truncated_results
    finally:
        db.close()


def test_run_hunt_truncates_scan_when_over_the_cap(client, monkeypatch):
    """Direct unit test of the truncation bookkeeping via a monkeypatched, tiny cap — avoids needing 20k+ real rows."""
    import app.hunting.engine as engine_module

    monkeypatch.setattr(engine_module, "MAX_EVENTS_SCANNED", 1)

    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, admin_pw)
    now = _iso_now()

    for _ in range(3):
        resp = client.post(
            "/api/v1/events",
            headers=headers,
            json={
                "source": "windows_sysmon",
                "timestamp": now.isoformat(),
                "host": "HUNT-TRUNC-01",
                "event_type": "process_creation",
                "process": "notepad.exe",
            },
        )
        assert resp.status_code == 201

    db = SessionLocal()
    try:
        execution = engine_module.run_hunt(
            db,
            organization_id=admin.organization_id,
            query_definition={"selection": {"Image": "notepad.exe"}, "condition": "selection"},
            time_range_start=now - timedelta(minutes=5),
            time_range_end=now + timedelta(minutes=5),
        )
        assert execution.truncated_scan is True
        assert execution.scanned_event_count == 1
    finally:
        db.close()


# --- API ---


def test_viewer_can_list_builtin_hunt_queries_but_cannot_write_or_execute(client):
    org = create_organization()
    viewer, viewer_pw = create_user(org, role_name="viewer")
    headers = auth_headers(client, viewer.email, viewer_pw)

    resp = client.get("/api/v1/hunting/queries", headers=headers)
    assert resp.status_code == 200
    names = {q["name"] for q in resp.json()}
    assert "Broad PowerShell Obfuscation/Bypass Indicators" in names
    assert all(q["is_builtin"] for q in resp.json())  # viewer's org has no custom queries yet

    create_resp = client.post(
        "/api/v1/hunting/queries",
        headers=headers,
        json={"name": "x", "query_definition": {"selection": {"Image": "x"}, "condition": "selection"}},
    )
    assert create_resp.status_code == 403

    run_resp = client.post(
        "/api/v1/hunting/run",
        headers=headers,
        json={
            "query_definition": {"selection": {"Image": "x"}, "condition": "selection"},
            "time_range_start": _iso_now().isoformat(),
            "time_range_end": (_iso_now() + timedelta(minutes=1)).isoformat(),
        },
    )
    assert run_resp.status_code == 403


def test_soc_analyst_can_create_run_and_review_a_custom_query(client):
    org = create_organization()
    # events.ingest isn't granted to soc_analyst (it's a service/ingestion-
    # credential permission, see app/core/permissions.py) — ingest with an
    # admin account, then do every hunting-specific check as the analyst.
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    admin_headers = auth_headers(client, admin.email, admin_pw)
    analyst, analyst_pw = create_user(org, role_name="soc_analyst")
    headers = auth_headers(client, analyst.email, analyst_pw)

    now = _iso_now()
    ingest = client.post(
        "/api/v1/events",
        headers=admin_headers,
        json={
            "source": "windows_sysmon",
            "timestamp": now.isoformat(),
            "host": "HUNT-API-01",
            "event_type": "process_creation",
            "process": "rundll32.exe",
            "command_line": "rundll32.exe evil.dll,Entry",
        },
    )
    assert ingest.status_code == 201

    create_resp = client.post(
        "/api/v1/hunting/queries",
        headers=headers,
        json={
            "name": "Custom LOLBin Hunt",
            "description": "test",
            "query_definition": {"selection": {"Image|endswith": "\\rundll32.exe"}, "condition": "selection"},
            "default_lookback_hours": 1,
        },
    )
    assert create_resp.status_code == 201, create_resp.text
    hunt_query_id = create_resp.json()["id"]
    assert create_resp.json()["is_builtin"] is False

    run_resp = client.post(
        f"/api/v1/hunting/queries/{hunt_query_id}/run",
        headers=headers,
        json={
            "time_range_start": (now - timedelta(minutes=5)).isoformat(),
            "time_range_end": (now + timedelta(minutes=5)).isoformat(),
        },
    )
    assert run_resp.status_code == 201, run_resp.text
    execution = run_resp.json()
    assert execution["status"] == "completed"
    assert execution["matched_event_count"] == 1

    events_resp = client.get(f"/api/v1/hunting/executions/{execution['id']}/events", headers=headers)
    assert events_resp.status_code == 200
    assert events_resp.json()[0]["process"] == "rundll32.exe"

    list_resp = client.get("/api/v1/hunting/executions", headers=headers, params={"hunt_query_id": hunt_query_id})
    assert list_resp.status_code == 200
    assert len(list_resp.json()) == 1


def test_soc_analyst_cannot_edit_or_delete_a_builtin_query(client):
    org = create_organization()
    analyst, analyst_pw = create_user(org, role_name="soc_analyst")
    headers = auth_headers(client, analyst.email, analyst_pw)

    builtin = client.get(
        "/api/v1/hunting/queries", headers=headers, params={"q": "LOLBin"}
    ).json()[0]

    patch_resp = client.patch(f"/api/v1/hunting/queries/{builtin['id']}", headers=headers, json={"name": "hijacked"})
    assert patch_resp.status_code == 403

    delete_resp = client.delete(f"/api/v1/hunting/queries/{builtin['id']}", headers=headers)
    assert delete_resp.status_code == 403


def test_custom_query_is_not_visible_or_editable_by_another_org():
    """IDOR check: an org's custom hunt query must 404 for a different org, matching the alerts/incidents pattern."""
    org_a = create_organization()
    org_b = create_organization()
    analyst_a, pw_a = create_user(org_a, role_name="soc_analyst")

    db = SessionLocal()
    try:
        custom = HuntQuery(
            organization_id=org_a.id,
            name="Org A Private Hunt",
            is_builtin=False,
            query_definition={"selection": {"Image": "x"}, "condition": "selection"},
        )
        db.add(custom)
        db.commit()
        db.refresh(custom)
        custom_id = custom.id
    finally:
        db.close()

    from fastapi.testclient import TestClient

    from app.main import app

    client = TestClient(app)
    analyst_b, pw_b = create_user(org_b, role_name="soc_analyst")
    headers_b = auth_headers(client, analyst_b.email, pw_b)

    get_resp = client.get(f"/api/v1/hunting/queries/{custom_id}", headers=headers_b)
    assert get_resp.status_code == 404

    patch_resp = client.patch(f"/api/v1/hunting/queries/{custom_id}", headers=headers_b, json={"name": "stolen"})
    assert patch_resp.status_code == 404


def test_ioc_search_matches_events_containing_the_indicator(client):
    org = create_organization()
    admin, admin_pw = create_user(org, role_name="admin", is_superuser=True)
    admin_headers = auth_headers(client, admin.email, admin_pw)
    analyst, analyst_pw = create_user(org, role_name="soc_analyst")
    headers = auth_headers(client, analyst.email, analyst_pw)

    now = _iso_now()
    ingest = client.post(
        "/api/v1/events",
        headers=admin_headers,
        json={
            "source": "firewall",
            "timestamp": now.isoformat(),
            "host": "HUNT-IOC-01",
            "action": "allow",
            "src_ip": "10.0.0.5",
            "dst_ip": "203.0.113.66",
            "dst_port": 443,
        },
    )
    assert ingest.status_code == 201

    resp = client.post(
        "/api/v1/hunting/ioc-search",
        headers=headers,
        json={
            "ioc_type": "ip",
            "value": "203.0.113.66",
            "time_range_start": (now - timedelta(minutes=5)).isoformat(),
            "time_range_end": (now + timedelta(minutes=5)).isoformat(),
        },
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["matched_event_count"] == 1


def test_ad_hoc_run_rejects_malformed_query_definition_with_422(client):
    org = create_organization()
    analyst, analyst_pw = create_user(org, role_name="soc_analyst")
    headers = auth_headers(client, analyst.email, analyst_pw)
    now = _iso_now()

    resp = client.post(
        "/api/v1/hunting/run",
        headers=headers,
        json={
            "query_definition": {"condition": "selection"},  # no selections declared
            "time_range_start": now.isoformat(),
            "time_range_end": (now + timedelta(minutes=1)).isoformat(),
        },
    )
    assert resp.status_code == 422
