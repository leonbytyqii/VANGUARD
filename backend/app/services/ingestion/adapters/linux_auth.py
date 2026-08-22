from app.models.enums import EventCategory
from app.schemas.event import EventIngestRequest
from app.services.ingestion.adapters.base import AdapterValidationError, NormalizedFields, SourceAdapter

_KNOWN_ACTIONS = {
    "failed_password",
    "accepted_password",
    "failed_publickey",
    "accepted_publickey",
    "sudo_command",
    "new_session",
    "session_closed",
    "user_added",
    "user_deleted",
    "account_locked",
}


class LinuxAuthAdapter(SourceAdapter):
    """
    Linux authentication logs (auth.log / journald-shaped). Always
    category=authentication; `action` carries the specific event
    (failed_password, accepted_password, sudo_command, ...) that Phase 4's
    brute-force correlation rule (N failed_password + 1 accepted_password
    + new privileged session) keys on.
    """

    source_name = "linux_auth"

    def normalize(self, payload: EventIngestRequest) -> NormalizedFields:
        action = (payload.action or payload.event_type or "").strip().lower()
        if not action:
            raise AdapterValidationError("linux_auth events require 'action' (e.g. 'failed_password').")
        if action not in _KNOWN_ACTIONS:
            raise AdapterValidationError(
                f"Unrecognized linux_auth action '{action}'. Known actions: {', '.join(sorted(_KNOWN_ACTIONS))}."
            )
        if not payload.user:
            raise AdapterValidationError("linux_auth events require 'user'.")

        return NormalizedFields(category=EventCategory.AUTHENTICATION.value, action=action)
