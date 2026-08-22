from app.models.enums import EventCategory
from app.schemas.event import EventIngestRequest
from app.services.ingestion.adapters.base import NormalizedFields, SourceAdapter


class GenericAdapter(SourceAdapter):
    """
    Passthrough adapter for already-normalized-shaped input — used by the
    attack simulation lab (Phase 14) and for manual/API testing where the
    caller already knows the target category. Infers `category` from
    which fields are populated when not given explicitly, rather than
    requiring a source-specific vocabulary.
    """

    source_name = "synthetic_lab"

    def normalize(self, payload: EventIngestRequest) -> NormalizedFields:
        category = self._infer_category(payload)
        action = payload.action or payload.event_type or "event"
        return NormalizedFields(category=category.value, action=action)

    @staticmethod
    def _infer_category(payload: EventIngestRequest) -> EventCategory:
        if payload.process:
            return EventCategory.PROCESS
        if payload.domain:
            return EventCategory.DNS
        if payload.cloud_account or payload.iam_role:
            return EventCategory.CLOUD
        if payload.dst_ip and payload.dst_port:
            return EventCategory.NETWORK
        if payload.user and (payload.action or "").lower() in {"failed_password", "accepted_password", "login", "logout"}:
            return EventCategory.AUTHENTICATION
        return EventCategory.OTHER
