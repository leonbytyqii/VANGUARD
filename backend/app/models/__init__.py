"""
Import every ORM model here so Alembic's autogenerate (via app/db/base.py)
sees the full schema, and so application code can do `from app.models import X`.
"""
from app.models.agent_identity import AgentIdentity  # noqa: F401
from app.models.ai import AgentEvidence, AgentStep, AIInvestigation  # noqa: F401
from app.models.alert import Alert, alert_mitre_techniques  # noqa: F401
from app.models.audit import AuditLog  # noqa: F401
from app.models.auth import RefreshToken  # noqa: F401
from app.models.automation import Playbook, PlaybookRun, ResponseAction, SOCBlueprint  # noqa: F401
from app.models.cloud import CloudEvent, CloudIdentity, IAMAttackPath  # noqa: F401
from app.models.detection import Detection, DetectionRule  # noqa: F401
from app.models.event import Event, NetworkConnection, Process  # noqa: F401
from app.models.host import Host  # noqa: F401
from app.models.hunting import HuntExecution, HuntQuery  # noqa: F401
from app.models.incident import (  # noqa: F401
    Incident,
    IncidentEvent,
    IncidentNote,
    IncidentTask,
    incident_alerts,
    incident_mitre_techniques,
)
from app.models.mitre import MitreTactic, MitreTechnique, detection_rule_mitre_techniques  # noqa: F401
from app.models.organization import Organization  # noqa: F401
from app.models.threat_intel import IOC, ThreatIntelligence  # noqa: F401
from app.models.user import Permission, Role, User, role_permissions  # noqa: F401

__all__ = [
    "Organization",
    "Permission", "Role", "User", "role_permissions",
    "RefreshToken",
    "AgentIdentity",
    "Host",
    "Event", "NetworkConnection", "Process",
    "MitreTactic", "MitreTechnique", "detection_rule_mitre_techniques",
    "Detection", "DetectionRule",
    "Alert", "alert_mitre_techniques",
    "Incident", "IncidentEvent", "IncidentNote", "IncidentTask",
    "incident_alerts", "incident_mitre_techniques",
    "IOC", "ThreatIntelligence",
    "HuntQuery", "HuntExecution",
    "AgentEvidence", "AgentStep", "AIInvestigation",
    "Playbook", "PlaybookRun", "ResponseAction", "SOCBlueprint",
    "CloudEvent", "CloudIdentity", "IAMAttackPath",
    "AuditLog",
]
