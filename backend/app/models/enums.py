"""
Shared enums used across models, schemas, and detection/AI logic.
Stored as plain strings in Postgres (native_enum=False) so new values can be
added via a simple migration rather than an ALTER TYPE.
"""
import enum


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    SOC_MANAGER = "soc_manager"
    SOC_ANALYST = "soc_analyst"
    THREAT_HUNTER = "threat_hunter"
    VIEWER = "viewer"


class Severity(str, enum.Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertStatus(str, enum.Enum):
    NEW = "new"
    TRIAGED = "triaged"
    INVESTIGATING = "investigating"
    ESCALATED = "escalated"
    FALSE_POSITIVE = "false_positive"
    CLOSED = "closed"


class IncidentStatus(str, enum.Enum):
    NEW = "new"
    TRIAGED = "triaged"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    ERADICATED = "eradicated"
    RECOVERED = "recovered"
    CLOSED = "closed"


class HostCriticality(str, enum.Enum):
    """
    Reference values for Host.criticality — kept as a plain string column
    (not a DB enum) so an admin can tune asset criticality without a
    migration, per TenantScopedMixin's general "data change, not schema
    change" philosophy. Consumed by app/services/risk_scoring.py.
    """
    LOW = "low"
    STANDARD = "standard"
    IMPORTANT = "important"
    CRITICAL = "critical"


class EventCategory(str, enum.Enum):
    PROCESS = "process"
    AUTHENTICATION = "authentication"
    NETWORK = "network"
    DNS = "dns"
    FILE = "file"
    CLOUD = "cloud"
    IAM = "iam"
    FIREWALL = "firewall"
    REGISTRY = "registry"
    OTHER = "other"


class EventSource(str, enum.Enum):
    WINDOWS_SYSMON = "windows_sysmon"
    LINUX_AUTH = "linux_auth"
    DNS = "dns"
    FIREWALL = "firewall"
    CLOUDTRAIL = "cloudtrail"
    SYNTHETIC_LAB = "synthetic_lab"
    OTHER = "other"


class DetectionEngine(str, enum.Enum):
    SIGMA = "sigma"
    CUSTOM_PYTHON = "custom_python"
    BEHAVIORAL_CORRELATION = "behavioral_correlation"


class IOCType(str, enum.Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"


class AgentType(str, enum.Enum):
    TRIAGE = "triage"
    INVESTIGATION = "investigation"
    THREAT_HUNT = "threat_hunt"
    CLOUD_IAM = "cloud_iam"
    RESPONSE = "response"


class InvestigationStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    AWAITING_APPROVAL = "awaiting_approval"


class ActionEffect(str, enum.Enum):
    READ_ONLY = "read_only"
    PROPOSE_ONLY = "propose_only"
    PRIVILEGED_ACTION = "privileged_action"


class ApprovalStatus(str, enum.Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED = "executed"
    FAILED = "failed"


class IncidentClosureClassification(str, enum.Enum):
    """
    Why an incident was closed. Required by
    app/services/incidents.py::transition_incident_status whenever the
    target status is `closed` — a case file that doesn't record *what it
    turned out to be* is not a closed case, it's an abandoned one, and
    the detection engine's false-positive rate is only measurable if
    this is mandatory rather than optional.
    """
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    BENIGN_TRUE_POSITIVE = "benign_true_positive"  # real activity, but authorized (e.g. a sanctioned pentest)
    DUPLICATE = "duplicate"


class IncidentTimelineKind(str, enum.Enum):
    """
    The vocabulary of `incident_events.kind`. Every entry is written by
    app/services/incident_timeline.py from inside a service function —
    there is deliberately no API route that lets a caller author one
    directly, so the case file cannot be back-dated or forged.
    """
    CREATED = "created"
    STATUS_CHANGE = "status_change"
    ASSIGNMENT = "assignment"
    NOTE = "note"
    TASK = "task"
    ALERT_LINKED = "alert_linked"
    ALERT_UNLINKED = "alert_unlinked"
    EVIDENCE = "evidence"
    RESPONSE_ACTION = "response_action"
    AI_INVESTIGATION = "ai_investigation"
    IOC_ADDED = "ioc_added"


class IncidentTaskCategory(str, enum.Enum):
    """
    NIST SP 800-61r2 incident-handling phases, used to group the IR
    checklist seeded onto a new incident
    (app/incidents/task_templates.py). "Preparation" is intentionally
    absent: it is an org-level, pre-incident activity, not a task you
    perform on one specific case.
    """
    DETECTION_ANALYSIS = "detection_analysis"
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    POST_INCIDENT = "post_incident"


class IOCReputation(str, enum.Enum):
    """
    An indicator's aggregate verdict across every provider that has scored
    it. `UNKNOWN` is a real, common answer — an indicator nobody has an
    opinion on is not the same as a clean one, and collapsing the two
    would turn "we have no data" into "we checked and it's fine".
    """
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    CLEAN = "clean"
    UNKNOWN = "unknown"
