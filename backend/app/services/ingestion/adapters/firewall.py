from app.models.enums import EventCategory
from app.schemas.event import EventIngestRequest
from app.services.ingestion.adapters.base import AdapterValidationError, NormalizedFields, SourceAdapter

_KNOWN_ACTIONS = {"allow", "deny", "drop", "reset"}


class FirewallAdapter(SourceAdapter):
    """
    Network/firewall connection logs. Feeds NetworkConnection rows (see
    app/services/ingestion/service.py) used by the process-network-join
    view in Phase 7/8 and Phase 4's suspicious-outbound-connection
    detections.
    """

    source_name = "firewall"

    def normalize(self, payload: EventIngestRequest) -> NormalizedFields:
        action = (payload.action or "").strip().lower()
        if action not in _KNOWN_ACTIONS:
            raise AdapterValidationError(
                f"firewall events require 'action' to be one of: {', '.join(sorted(_KNOWN_ACTIONS))}."
            )
        if not (payload.src_ip and payload.dst_ip):
            raise AdapterValidationError("firewall events require both 'src_ip' and 'dst_ip'.")

        return NormalizedFields(category=EventCategory.FIREWALL.value, action=action)
