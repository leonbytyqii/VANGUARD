from app.models.enums import EventCategory
from app.schemas.event import EventIngestRequest
from app.services.ingestion.adapters.base import AdapterValidationError, NormalizedFields, SourceAdapter

# Event-name substrings that mark an event as identity/access-management
# activity rather than a general resource operation — this is what routes
# an event to category=iam (and, from Phase 11 on, into IAM attack-path
# reconstruction) versus category=cloud.
_IAM_EVENT_MARKERS = (
    "role",
    "user",
    "policy",
    "accesskey",
    "credential",
    "group",
    "mfa",
    "login",
    "assumerole",
    "federat",
)


class CloudTrailAdapter(SourceAdapter):
    """
    AWS CloudTrail-style API activity events. `event_type` carries the
    CloudTrail eventName (e.g. 'AssumeRole', 'PutUserPolicy',
    'CreateAccessKey', 'GetObject'). Identity-management-shaped event
    names are classified category=iam; everything else is category=cloud.
    This split is what lets Phase 11's IAM attack-path reconstruction
    query "just the identity chain" without scanning every S3/EC2 call.

    Phase 3 populates the generic `events` table only. Phase 11 adds a
    richer, cloud-specific `cloud_events` row (actor/assumed-role chain,
    request/response elements) alongside it for attack-path graphs — kept
    separate deliberately so this adapter doesn't have to guess at
    IAM-attack-path semantics before that feature exists.
    """

    source_name = "cloudtrail"

    def normalize(self, payload: EventIngestRequest) -> NormalizedFields:
        event_name = (payload.event_type or "").strip()
        if not event_name:
            raise AdapterValidationError("cloudtrail events require 'event_type' (the CloudTrail eventName).")
        if not payload.cloud_account:
            raise AdapterValidationError("cloudtrail events require 'cloud_account'.")

        lowered = event_name.lower()
        category = EventCategory.IAM if any(marker in lowered for marker in _IAM_EVENT_MARKERS) else EventCategory.CLOUD

        return NormalizedFields(category=category.value, action=event_name)
