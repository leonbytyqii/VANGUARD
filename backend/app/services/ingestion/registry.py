"""
Adapter registry. Adding a new log source is: write one SourceAdapter
subclass in app/services/ingestion/adapters/, register it here, done —
nothing in the ingestion service, the API route, or the detection engine
needs to change.
"""
from app.services.ingestion.adapters.base import SourceAdapter
from app.services.ingestion.adapters.cloudtrail import CloudTrailAdapter
from app.services.ingestion.adapters.dns import DNSAdapter
from app.services.ingestion.adapters.firewall import FirewallAdapter
from app.services.ingestion.adapters.generic import GenericAdapter
from app.services.ingestion.adapters.linux_auth import LinuxAuthAdapter
from app.services.ingestion.adapters.windows_sysmon import WindowsSysmonAdapter

ADAPTER_REGISTRY: dict[str, SourceAdapter] = {
    a.source_name: a
    for a in [
        WindowsSysmonAdapter(),
        LinuxAuthAdapter(),
        DNSAdapter(),
        FirewallAdapter(),
        CloudTrailAdapter(),
        GenericAdapter(),
    ]
}


def get_adapter(source: str) -> SourceAdapter | None:
    return ADAPTER_REGISTRY.get(source)
