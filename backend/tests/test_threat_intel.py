"""
Threat intelligence enrichment (Phase 10): the provider abstraction and
its non-raising contract, the offline sample feed's honesty about what it
does and doesn't know, verdict aggregation, cache TTL behaviour, IOC
extraction from cited evidence, incident<->IOC attachment, the real
enrich_ioc agent tool, and RBAC / tenant isolation on /api/v1/threat-intel.
"""
import ipaddress
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.ai.agents.permissions import invoke_agent_tool
from app.db.session import SessionLocal
from app.models.alert import Alert
from app.models.enums import ActionEffect, AgentType, IOCType
from app.models.threat_intel import IOC, ThreatIntelligence
from app.ai.tools.registry import TOOL_REGISTRY
from app.threat_intel.extraction import extract_from_event
from app.threat_intel.providers.base import ProviderResult, ThreatIntelProvider
from app.threat_intel.providers.local import LocalFeedProvider
from app.threat_intel.registry import MIN_CONFIDENCE, aggregate, get_providers
from app.threat_intel.sample_feed import SAMPLE_INDICATORS
from tests.factories import auth_headers, create_organization, create_user


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


@pytest.fixture()
def analyst_ctx(client):
    org = create_organization()
    user, pw = create_user(org, role_name="soc_analyst")
    return org, user, auth_headers(client, user.email, pw)


def _make_alert(org_id, *, related_event_ids=None, host_name="TI-HOST-01") -> Alert:
    db = SessionLocal()
    try:
        alert = Alert(
            organization_id=org_id,
            title="Threat-intel test alert",
            description="",
            severity="HIGH",
            risk_score=80,
            status="new",
            source="manual_test",
            host_name=host_name,
            user="alice",
            related_event_ids=related_event_ids or [],
            alert_timestamp=datetime.now(timezone.utc),
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        return alert
    finally:
        db.close()


# --------------------------------------------------------------------------
# Sample feed integrity — no real infrastructure may be named
# --------------------------------------------------------------------------


def test_every_sample_ip_is_in_a_reserved_documentation_range():
    """
    The bundled feed must never label a real operator's host as malicious.
    RFC 5737 reserves these three ranges for documentation precisely so a
    committed file like this one can exist.
    """
    documentation = [
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
    ]
    for value in SAMPLE_INDICATORS:
        try:
            addr = ipaddress.ip_address(value)
        except ValueError:
            continue
        assert any(addr in net for net in documentation), f"{value} is not a reserved documentation address"


def test_every_sample_domain_uses_a_reserved_tld():
    for value in SAMPLE_INDICATORS:
        if "." not in value or value.startswith("http"):
            continue
        try:
            ipaddress.ip_address(value)
            continue  # it's an IP, covered by the test above
        except ValueError:
            pass
        if len(value) in (32, 40, 64) and all(c in "0123456789abcdef" for c in value):
            continue  # a hash, not a domain
        assert value.endswith((".invalid", ".test")), f"{value} does not use an RFC 2606 reserved TLD"


def test_every_sample_verdict_is_a_known_reputation():
    for value, (reputation, confidence, _tags, _desc) in SAMPLE_INDICATORS.items():
        assert reputation in {"malicious", "suspicious", "clean", "unknown"}, value
        assert 0.0 <= confidence <= 1.0, value


# --------------------------------------------------------------------------
# LocalFeedProvider
# --------------------------------------------------------------------------


def test_local_provider_scores_a_known_indicator():
    result = LocalFeedProvider().lookup(IOCType.IP.value, "203.0.113.7")
    assert result.reputation == "malicious"
    assert result.confidence >= 0.9
    assert result.raw["synthetic"] is True
    assert result.lookup_failed is False


def test_local_provider_returns_unknown_not_clean_for_an_indicator_it_has_never_seen():
    """
    The central honesty property of the offline provider: no data is
    reported as no data. Manufacturing a verdict here would be the same
    class of failure as the AI fabricating evidence.
    """
    result = LocalFeedProvider().lookup(IOCType.DOMAIN.value, "something-nobody-has-scored.invalid")
    assert result.reputation == "unknown"
    assert result.confidence == 0.0


def test_local_provider_calls_private_addresses_clean_but_says_why():
    result = LocalFeedProvider().lookup(IOCType.IP.value, "10.1.2.3")
    assert result.reputation == "clean"
    # The caveat must travel with the verdict — "clean" here is a claim
    # about routability, not about the host being safe.
    assert "routability" in result.raw["caveat"]


def test_provider_failure_is_unknown_never_clean():
    failed = ProviderResult.failure("some_provider", "connection refused")
    assert failed.reputation == "unknown"
    assert failed.confidence == 0.0
    assert failed.lookup_failed is True


def test_local_provider_is_always_in_the_chain():
    assert any(isinstance(p, LocalFeedProvider) for p in get_providers())


def test_providers_declare_supported_types_and_are_skipped_otherwise():
    provider = LocalFeedProvider()
    assert provider.supports(IOCType.IP.value)
    assert not provider.supports("not_a_type")


def test_a_raising_provider_would_violate_the_contract():
    """Documents the contract rather than asserting on an implementation."""

    class BadProvider(ThreatIntelProvider):
        name = "bad"
        supported_types = (IOCType.IP.value,)

        def lookup(self, ioc_type, value):
            raise RuntimeError("network down")

    with pytest.raises(RuntimeError):
        BadProvider().lookup(IOCType.IP.value, "203.0.113.7")
    # ...which is exactly why every shipped provider wraps its own I/O and
    # returns ProviderResult.failure instead.


# --------------------------------------------------------------------------
# Aggregation
# --------------------------------------------------------------------------


def _r(reputation, confidence, *, failed=False):
    return ProviderResult(provider="p", reputation=reputation, confidence=confidence, lookup_failed=failed)


def test_aggregate_returns_unknown_when_nothing_confident_voted():
    assert aggregate([]) == ("unknown", 0)
    assert aggregate([_r("malicious", 0.1)]) == ("unknown", 0)


def test_aggregate_ignores_failed_lookups():
    assert aggregate([_r("malicious", 0.99, failed=True)]) == ("unknown", 0)


def test_worst_confident_verdict_wins_over_a_clean_majority():
    """
    Deliberately not a majority vote: one confirmed C2 match outweighs
    three feeds with nothing to say. False negatives cost more in triage.
    """
    reputation, score = aggregate([_r("clean", 0.9), _r("clean", 0.9), _r("malicious", 0.8)])
    assert reputation == "malicious"
    assert score == 80


def test_low_confidence_opinions_do_not_vote():
    reputation, _ = aggregate([_r("malicious", MIN_CONFIDENCE - 0.01), _r("clean", 0.9)])
    assert reputation == "clean"


def test_clean_scores_zero():
    assert aggregate([_r("clean", 1.0)]) == ("clean", 0)


# --------------------------------------------------------------------------
# Extraction
# --------------------------------------------------------------------------


def test_extraction_skips_non_routable_addresses(client, analyst_ctx):
    from app.models.event import Event

    event = Event(
        organization_id=None,
        event_timestamp=datetime.now(timezone.utc),
        source="synthetic_lab",
        category="network",
        src_ip="10.0.0.5",
        dst_ip="203.0.113.7",
        domain="c2-panel.invalid",
        ingested_at=datetime.now(timezone.utc),
        raw_event={},
    )
    found = {(i.ioc_type, i.value) for i in extract_from_event(event)}
    assert ("ip", "203.0.113.7") in found
    assert ("domain", "c2-panel.invalid") in found
    assert ("ip", "10.0.0.5") not in found, "an internal address is not an indicator a feed can score"


def test_extraction_records_the_field_an_indicator_came_from():
    from app.models.event import Event

    event = Event(
        organization_id=None,
        event_timestamp=datetime.now(timezone.utc),
        source="dns",
        category="dns",
        domain="malware-delivery.invalid",
        ingested_at=datetime.now(timezone.utc),
        raw_event={},
    )
    [ioc] = extract_from_event(event)
    assert ioc.source_field == "domain"


def test_extraction_rejects_a_malformed_hash():
    from app.models.event import Event

    event = Event(
        organization_id=None,
        event_timestamp=datetime.now(timezone.utc),
        source="windows_sysmon",
        category="process",
        file_hash="not-a-hash",
        ingested_at=datetime.now(timezone.utc),
        raw_event={},
    )
    assert extract_from_event(event) == []


# --------------------------------------------------------------------------
# API: lookup, caching, CRUD
# --------------------------------------------------------------------------


def test_lookup_creates_enriches_and_then_serves_from_cache(client, analyst_ctx):
    _, _, headers = analyst_ctx
    body = {"ioc_type": "ip", "value": "203.0.113.7"}

    first = client.post("/api/v1/threat-intel/lookup", headers=headers, json=body)
    assert first.status_code == 200, first.text
    assert first.json()["from_cache"] is False
    ioc = first.json()["ioc"]
    assert ioc["reputation"] == "malicious"
    assert ioc["threat_score"] >= 90
    assert ioc["last_enriched_at"] is not None
    assert len(ioc["enrichments"]) >= 1

    second = client.post("/api/v1/threat-intel/lookup", headers=headers, json=body)
    assert second.status_code == 200
    assert second.json()["from_cache"] is True, "a fresh verdict must not re-hit the provider"
    assert second.json()["ioc"]["id"] == ioc["id"], "the same indicator, not a duplicate row"


def test_value_is_normalized_so_case_does_not_create_duplicates(client, analyst_ctx):
    _, _, headers = analyst_ctx
    a = client.post(
        "/api/v1/threat-intel/lookup", headers=headers, json={"ioc_type": "domain", "value": "C2-Panel.INVALID"}
    ).json()
    b = client.post(
        "/api/v1/threat-intel/lookup", headers=headers, json={"ioc_type": "domain", "value": "c2-panel.invalid"}
    ).json()
    assert a["ioc"]["id"] == b["ioc"]["id"]
    assert a["ioc"]["value"] == "c2-panel.invalid"


def test_expired_enrichment_is_re_queried(client, analyst_ctx):
    _, _, headers = analyst_ctx
    created = client.post(
        "/api/v1/threat-intel/lookup", headers=headers, json={"ioc_type": "ip", "value": "198.51.100.23"}
    ).json()

    db = SessionLocal()
    try:
        rows = (
            db.query(ThreatIntelligence)
            .filter(ThreatIntelligence.ioc_id == uuid.UUID(created["ioc"]["id"]))
            .all()
        )
        for row in rows:
            row.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
            db.add(row)
        db.commit()
    finally:
        db.close()

    again = client.post(
        "/api/v1/threat-intel/lookup", headers=headers, json={"ioc_type": "ip", "value": "198.51.100.23"}
    )
    assert again.json()["from_cache"] is False, "an expired verdict is not reused"


def test_unknown_indicator_is_recorded_as_unknown(client, analyst_ctx):
    _, _, headers = analyst_ctx
    resp = client.post(
        "/api/v1/threat-intel/lookup",
        headers=headers,
        json={"ioc_type": "domain", "value": "never-heard-of-this.invalid"},
    )
    assert resp.status_code == 200
    assert resp.json()["ioc"]["reputation"] == "unknown"
    assert resp.json()["ioc"]["threat_score"] == 0


def test_create_list_filter_and_retire_an_ioc(client, analyst_ctx):
    _, _, headers = analyst_ctx
    created = client.post(
        "/api/v1/threat-intel/iocs",
        headers=headers,
        json={"ioc_type": "ip", "value": "203.0.113.13", "tags": ["manual"], "notes": "Seen in a phishing header."},
    )
    assert created.status_code == 201, created.text
    ioc = created.json()
    assert ioc["reputation"] == "malicious"
    assert "manual" in ioc["tags"]

    listed = client.get("/api/v1/threat-intel/iocs", headers=headers, params={"reputation": "malicious"}).json()
    assert ioc["id"] in [i["id"] for i in listed]

    high = client.get("/api/v1/threat-intel/iocs", headers=headers, params={"min_score": 90}).json()
    assert all(i["threat_score"] >= 90 for i in high)

    retired = client.patch(f"/api/v1/threat-intel/iocs/{ioc['id']}", headers=headers, json={"is_active": False})
    assert retired.status_code == 200
    assert retired.json()["is_active"] is False

    active = client.get("/api/v1/threat-intel/iocs", headers=headers).json()
    assert ioc["id"] not in [i["id"] for i in active], "retired indicators are hidden by default"
    # ...but still retrievable, because incidents may cite them.
    assert client.get(f"/api/v1/threat-intel/iocs/{ioc['id']}", headers=headers).status_code == 200


def test_unknown_ioc_type_is_rejected_by_the_schema(client, analyst_ctx):
    _, _, headers = analyst_ctx
    resp = client.post(
        "/api/v1/threat-intel/lookup", headers=headers, json={"ioc_type": "telepathy", "value": "x"}
    )
    assert resp.status_code == 422


def test_caller_cannot_set_reputation_or_threat_score(client, analyst_ctx):
    """Derived fields are absent from the request schema, so they're ignored."""
    _, _, headers = analyst_ctx
    resp = client.post(
        "/api/v1/threat-intel/iocs",
        headers=headers,
        json={
            "ioc_type": "domain",
            "value": "harmless-but-claimed-bad.invalid",
            "reputation": "malicious",
            "threat_score": 100,
        },
    )
    assert resp.status_code == 201
    assert resp.json()["reputation"] == "unknown"
    assert resp.json()["threat_score"] == 0


# --------------------------------------------------------------------------
# Alert enrichment
# --------------------------------------------------------------------------


def _ingest_c2_event(client, headers, host="TI-C2-01"):
    body = {
        "source": "firewall",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "host": host,
        "action": "allow",
        "src_ip": "10.0.0.50",
        "dst_ip": "203.0.113.7",
        "dst_port": 4444,
        "protocol": "tcp",
    }
    resp = client.post("/api/v1/events", headers=headers, json=body)
    assert resp.status_code == 201, resp.text
    return resp.json()


def test_alert_enrichment_extracts_and_scores_indicators_from_cited_evidence(client):
    org = create_organization()
    admin, pw = create_user(org, role_name="admin", is_superuser=True)
    headers = auth_headers(client, admin.email, pw)

    _ingest_c2_event(client, headers)
    alerts = client.get("/api/v1/alerts", headers=headers, params={"host": "TI-C2-01"}).json()
    assert alerts, "the suspicious-outbound detection should have fired"
    alert = alerts[0]

    resp = client.post(f"/api/v1/threat-intel/alerts/{alert['id']}/enrich", headers=headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["extracted"] >= 1
    assert body["malicious"] >= 1
    values = {i["value"] for i in body["iocs"]}
    assert "203.0.113.7" in values
    assert "10.0.0.50" not in values, "internal addresses are not extracted as indicators"

    # The IOC records which alert surfaced it.
    c2 = next(i for i in body["iocs"] if i["value"] == "203.0.113.7")
    assert alert["id"] in c2["related_alert_ids"]


def test_enriching_an_alert_with_no_cited_events_is_a_no_op(client, analyst_ctx):
    org, _, headers = analyst_ctx
    alert = _make_alert(org.id, related_event_ids=[])
    resp = client.post(f"/api/v1/threat-intel/alerts/{alert.id}/enrich", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["extracted"] == 0


def test_cannot_enrich_another_tenants_alert(client, analyst_ctx):
    _, _, headers = analyst_ctx
    other_org = create_organization()
    foreign = _make_alert(other_org.id)
    resp = client.post(f"/api/v1/threat-intel/alerts/{foreign.id}/enrich", headers=headers)
    assert resp.status_code == 404


# --------------------------------------------------------------------------
# Incident <-> IOC
# --------------------------------------------------------------------------


def test_attach_and_detach_an_ioc_from_a_case(client, analyst_ctx):
    _, _, headers = analyst_ctx
    incident = client.post(
        "/api/v1/incidents", headers=headers, json={"title": "IOC case", "severity": "HIGH"}
    ).json()
    ioc = client.post(
        "/api/v1/threat-intel/iocs", headers=headers, json={"ioc_type": "ip", "value": "203.0.113.7"}
    ).json()

    attached = client.post(
        f"/api/v1/incidents/{incident['id']}/iocs", headers=headers, json={"ioc_id": ioc["id"]}
    )
    assert attached.status_code == 201, attached.text
    assert [i["id"] for i in attached.json()] == [ioc["id"]]

    timeline = client.get(
        f"/api/v1/incidents/{incident['id']}/timeline", headers=headers, params={"kind": "ioc_added"}
    ).json()
    assert len(timeline) == 1
    assert timeline[0]["details"]["reputation"] == "malicious"

    detached = client.delete(f"/api/v1/incidents/{incident['id']}/iocs/{ioc['id']}", headers=headers)
    assert detached.status_code == 204
    assert client.get(f"/api/v1/incidents/{incident['id']}/iocs", headers=headers).json() == []


def test_attaching_the_same_ioc_twice_is_idempotent(client, analyst_ctx):
    _, _, headers = analyst_ctx
    incident = client.post(
        "/api/v1/incidents", headers=headers, json={"title": "Dup case", "severity": "LOW"}
    ).json()
    ioc = client.post(
        "/api/v1/threat-intel/iocs", headers=headers, json={"ioc_type": "ip", "value": "203.0.113.66"}
    ).json()

    client.post(f"/api/v1/incidents/{incident['id']}/iocs", headers=headers, json={"ioc_id": ioc["id"]})
    second = client.post(
        f"/api/v1/incidents/{incident['id']}/iocs", headers=headers, json={"ioc_id": ioc["id"]}
    )
    assert second.status_code == 201
    assert len(second.json()) == 1


def test_cannot_attach_another_tenants_ioc_to_your_case(client, analyst_ctx):
    _, _, headers = analyst_ctx
    other_org = create_organization()
    other_user, other_pw = create_user(other_org, role_name="soc_analyst")
    other_headers = auth_headers(client, other_user.email, other_pw)
    foreign_ioc = client.post(
        "/api/v1/threat-intel/iocs", headers=other_headers, json={"ioc_type": "ip", "value": "198.51.100.99"}
    ).json()

    incident = client.post(
        "/api/v1/incidents", headers=headers, json={"title": "Mine", "severity": "LOW"}
    ).json()
    resp = client.post(
        f"/api/v1/incidents/{incident['id']}/iocs", headers=headers, json={"ioc_id": foreign_ioc["id"]}
    )
    assert resp.status_code == 404


# --------------------------------------------------------------------------
# The enrich_ioc agent tool
# --------------------------------------------------------------------------


def test_enrich_ioc_tool_is_read_only_and_returns_a_real_row():
    assert TOOL_REGISTRY["enrich_ioc"].effect is ActionEffect.READ_ONLY

    org = create_organization()
    db = SessionLocal()
    try:
        result = invoke_agent_tool(
            db,
            agent_type=AgentType.INVESTIGATION,
            tool_name="enrich_ioc",
            organization_id=org.id,
            ioc_type="ip",
            value="203.0.113.7",
        )
        assert result["reputation"] == "malicious"
        assert result["threat_score"] >= 90
        # The claim resolves to an actual database row, same as any other
        # evidence source the agent can cite.
        assert db.query(IOC).filter(IOC.id == uuid.UUID(result["ioc_id"])).one_or_none() is not None
    finally:
        db.close()


def test_enrich_ioc_tool_returns_an_error_dict_rather_than_raising():
    org = create_organization()
    db = SessionLocal()
    try:
        result = invoke_agent_tool(
            db,
            agent_type=AgentType.INVESTIGATION,
            tool_name="enrich_ioc",
            organization_id=org.id,
            ioc_type="not_a_type",
            value="x",
        )
    finally:
        db.close()
    assert result["reputation"] == "unknown"
    assert "error" in result


def test_enrich_ioc_tool_is_tenant_scoped():
    org_a = create_organization()
    org_b = create_organization()
    db = SessionLocal()
    try:
        invoke_agent_tool(
            db, agent_type=AgentType.INVESTIGATION, tool_name="enrich_ioc",
            organization_id=org_a.id, ioc_type="ip", value="203.0.113.7",
        )
        in_b = db.query(IOC).filter(IOC.organization_id == org_b.id, IOC.value == "203.0.113.7").count()
    finally:
        db.close()
    assert in_b == 0


# --------------------------------------------------------------------------
# RBAC + tenant isolation
# --------------------------------------------------------------------------


def test_viewer_can_look_up_but_cannot_manage(client):
    org = create_organization()
    viewer, pw = create_user(org, role_name="viewer")
    headers = auth_headers(client, viewer.email, pw)

    assert client.get("/api/v1/threat-intel/iocs", headers=headers).status_code == 200
    assert client.post(
        "/api/v1/threat-intel/lookup", headers=headers, json={"ioc_type": "ip", "value": "203.0.113.7"}
    ).status_code == 200
    assert client.post(
        "/api/v1/threat-intel/iocs", headers=headers, json={"ioc_type": "ip", "value": "203.0.113.13"}
    ).status_code == 403


def test_force_refresh_requires_manage_because_it_spends_a_shared_quota(client):
    org = create_organization()
    viewer, pw = create_user(org, role_name="viewer")
    viewer_headers = auth_headers(client, viewer.email, pw)
    analyst, apw = create_user(org, role_name="soc_analyst")
    analyst_headers = auth_headers(client, analyst.email, apw)

    body = {"ioc_type": "ip", "value": "192.0.2.44", "force_refresh": True}
    denied = client.post("/api/v1/threat-intel/lookup", headers=viewer_headers, json=body)
    assert denied.status_code == 403
    assert "threat_intel.manage" in denied.json()["detail"]

    allowed = client.post("/api/v1/threat-intel/lookup", headers=analyst_headers, json=body)
    assert allowed.status_code == 200
    assert allowed.json()["from_cache"] is False


def test_unauthenticated_access_is_rejected(client):
    assert client.get("/api/v1/threat-intel/iocs").status_code == 401
    assert client.post("/api/v1/threat-intel/lookup", json={"ioc_type": "ip", "value": "1.1.1.1"}).status_code == 401


def test_iocs_are_tenant_isolated(client, analyst_ctx):
    _, _, headers = analyst_ctx
    other_org = create_organization()
    other_user, other_pw = create_user(other_org, role_name="soc_analyst")
    other_headers = auth_headers(client, other_user.email, other_pw)

    foreign = client.post(
        "/api/v1/threat-intel/iocs", headers=other_headers, json={"ioc_type": "domain", "value": "exfil-drop.invalid"}
    ).json()

    assert client.get(f"/api/v1/threat-intel/iocs/{foreign['id']}", headers=headers).status_code == 404
    assert client.patch(
        f"/api/v1/threat-intel/iocs/{foreign['id']}", headers=headers, json={"notes": "hijacked"}
    ).status_code == 404
    assert client.post(
        f"/api/v1/threat-intel/iocs/{foreign['id']}/refresh", headers=headers
    ).status_code == 404

    mine = [i["id"] for i in client.get("/api/v1/threat-intel/iocs", headers=headers).json()]
    assert foreign["id"] not in mine


def test_the_same_indicator_in_two_tenants_is_two_independent_rows(client, analyst_ctx):
    _, _, headers = analyst_ctx
    other_org = create_organization()
    other_user, other_pw = create_user(other_org, role_name="soc_analyst")
    other_headers = auth_headers(client, other_user.email, other_pw)

    a = client.post(
        "/api/v1/threat-intel/lookup", headers=headers, json={"ioc_type": "ip", "value": "203.0.113.7"}
    ).json()["ioc"]
    b = client.post(
        "/api/v1/threat-intel/lookup", headers=other_headers, json={"ioc_type": "ip", "value": "203.0.113.7"}
    ).json()["ioc"]

    assert a["id"] != b["id"], "one org observing an indicator says nothing about another"
    assert a["reputation"] == b["reputation"] == "malicious"


def test_enrichment_is_audited(client, analyst_ctx):
    _, _, headers = analyst_ctx
    created = client.post(
        "/api/v1/threat-intel/lookup", headers=headers, json={"ioc_type": "ip", "value": "203.0.113.13"}
    ).json()

    from app.models.audit import AuditLog

    db = SessionLocal()
    try:
        actions = {
            row.action for row in db.query(AuditLog).filter(AuditLog.resource_id == created["ioc"]["id"]).all()
        }
    finally:
        db.close()
    assert "ioc_enriched" in actions
