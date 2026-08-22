from app.models.enums import EventCategory
from app.schemas.event import EventIngestRequest
from app.services.ingestion.adapters.base import AdapterValidationError, NormalizedFields, SourceAdapter


class DNSAdapter(SourceAdapter):
    """
    DNS query/response logs. `domain` is the queried name; Phase 4's DNS
    anomaly detections (DGA-shaped domains, newly-observed domains, high
    query volume to one domain) and Phase 10's IOC enrichment both key off
    this field.
    """

    source_name = "dns"

    def normalize(self, payload: EventIngestRequest) -> NormalizedFields:
        if not payload.domain:
            raise AdapterValidationError("dns events require 'domain' (the queried name).")
        return NormalizedFields(category=EventCategory.DNS.value, action=payload.action or "dns_query")
