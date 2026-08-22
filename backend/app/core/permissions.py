"""
Source of truth for the platform's permission catalog and default RBAC
role grants. app/db/seed.py creates the DB rows from this; enforcement at
request time always re-reads the DB (via User.has_permission), never this
module directly, so revoking a permission from a role in the admin UI
takes effect immediately without a redeploy.

Permission codes follow `resource.action`. The base list matches the set
specified for SOC-AI Phase 2; a few narrow additions
(incidents.update, events.ingest, admin.agents, detections.read,
detections.run, mitre.read, threat_hunting.read, threat_hunting.write,
ai.read) were needed for the platform to actually function end-to-end
and are called out below. `threat_hunting.execute` and `ai.investigate`
were already part of the original Phase 2 base list, ahead of Phase 7/8
actually implementing what they gate.
"""

PERMISSIONS: dict[str, str] = {
    "alerts.read": "View alerts",
    "alerts.update": "Update alert status/assignment/notes",
    "incidents.read": "View incidents",
    "incidents.create": "Create incidents",
    "incidents.update": "Update incident fields (summary, severity, status)",  # addition: needed for lifecycle mgmt
    "incidents.assign": "Assign incidents to analysts",
    "events.read": "Search and view normalized events",
    "events.ingest": "Submit events via the ingestion API",  # addition: service/ingestion-credential permission
    "detections.read": "View detection rules and fired detections",  # addition (Phase 4)
    "detections.run": "Manually trigger a full detection sweep",  # addition (Phase 4)
    "mitre.read": "View the MITRE ATT&CK catalog and detection coverage matrix",  # addition (Phase 6)
    "threat_hunting.read": "View the hunt query library and past hunt execution results",  # addition (Phase 7)
    "threat_hunting.write": "Create, edit, and delete custom threat-hunting queries",  # addition (Phase 7)
    "threat_hunting.execute": "Run threat-hunting queries",
    "threat_intel.lookup": "Query IOC threat-intelligence enrichment",
    "threat_intel.manage": "Add, edit, retire, and force-refresh threat-intelligence indicators",  # addition (Phase 10)
    "ai.read": "View AI investigation results and their full agent-step trace",  # addition (Phase 8)
    "ai.investigate": "Trigger an AI agent investigation",
    "blueprints.execute": "Run a SOC Blueprint-guided investigation",
    "playbooks.execute": "Trigger a deterministic SOAR playbook",
    "response.request": "Request a privileged response action",
    "response.approve": "Approve, reject, or execute a privileged response action",
    "iam.read": "View cloud IAM identities and attack paths",
    "cloud.read": "View cloud/CloudTrail-style events",
    "admin.users": "Manage users",
    "admin.roles": "View roles and their permission grants",
    "admin.agents": "Manage AI agent identities and their tool allowlists",  # addition: agent governance
    "audit.read": "View the audit log",
}

ROLE_PERMISSIONS: dict[str, list[str]] = {
    "viewer": [
        "alerts.read",
        "incidents.read",
        "events.read",
        "detections.read",
        "mitre.read",
        "threat_hunting.read",
        "ai.read",
        "iam.read",
        "cloud.read",
        "threat_intel.lookup",
    ],
    "threat_hunter": [
        "alerts.read",
        "incidents.read",
        "events.read",
        "detections.read",
        "mitre.read",
        "threat_hunting.read",
        "threat_hunting.write",
        "ai.read",
        "iam.read",
        "cloud.read",
        "threat_intel.lookup",
        "threat_hunting.execute",
        "ai.investigate",
    ],
    "soc_analyst": [
        "alerts.read",
        "alerts.update",
        "incidents.read",
        "incidents.create",
        "incidents.update",
        "events.read",
        "detections.read",
        "mitre.read",
        "threat_hunting.read",
        "threat_hunting.write",
        "ai.read",
        "iam.read",
        "cloud.read",
        "threat_intel.lookup",
        "threat_intel.manage",
        "threat_hunting.execute",
        "ai.investigate",
        "blueprints.execute",
        "response.request",
    ],
    "soc_manager": [
        "alerts.read",
        "alerts.update",
        "incidents.read",
        "incidents.create",
        "incidents.update",
        "incidents.assign",
        "events.read",
        "detections.read",
        "detections.run",
        "mitre.read",
        "threat_hunting.read",
        "threat_hunting.write",
        "ai.read",
        "iam.read",
        "cloud.read",
        "threat_intel.lookup",
        "threat_intel.manage",
        "threat_hunting.execute",
        "ai.investigate",
        "blueprints.execute",
        "playbooks.execute",
        "response.request",
        "response.approve",
        "audit.read",
    ],
    "admin": list(PERMISSIONS.keys()),
}
