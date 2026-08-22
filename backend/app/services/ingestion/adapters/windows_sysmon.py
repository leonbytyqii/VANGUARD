from app.models.enums import EventCategory
from app.schemas.event import EventIngestRequest
from app.services.ingestion.adapters.base import AdapterValidationError, NormalizedFields, SourceAdapter

_EVENT_TYPE_CATEGORY = {
    "process_creation": EventCategory.PROCESS,
    "network_connection": EventCategory.NETWORK,
    "file_create": EventCategory.FILE,
    "file_delete": EventCategory.FILE,
    "registry_event": EventCategory.REGISTRY,
    "registry_add": EventCategory.REGISTRY,
    "registry_set": EventCategory.REGISTRY,
}


class WindowsSysmonAdapter(SourceAdapter):
    """
    Windows endpoint telemetry (Sysmon-shaped). The most detection-rich
    source in the platform — process lineage (process/parent_process +
    GUIDs) and command lines are what the behavioral detections in Phase 4
    (encoded PowerShell, suspicious process spawning) and the process-tree
    tool in Phase 7/8 are built on.
    """

    source_name = "windows_sysmon"

    def normalize(self, payload: EventIngestRequest) -> NormalizedFields:
        event_type = (payload.event_type or "").strip().lower()
        if not event_type:
            raise AdapterValidationError("windows_sysmon events require 'event_type' (e.g. 'process_creation').")

        category = _EVENT_TYPE_CATEGORY.get(event_type)
        if category is None:
            raise AdapterValidationError(
                f"Unrecognized windows_sysmon event_type '{event_type}'. "
                f"Known types: {', '.join(sorted(_EVENT_TYPE_CATEGORY))}."
            )

        if category == EventCategory.PROCESS and not payload.process:
            raise AdapterValidationError("process_creation events require 'process'.")
        if category == EventCategory.NETWORK and not (payload.dst_ip or payload.domain):
            raise AdapterValidationError("network_connection events require 'dst_ip' or 'domain'.")

        return NormalizedFields(category=category.value, action=event_type)
