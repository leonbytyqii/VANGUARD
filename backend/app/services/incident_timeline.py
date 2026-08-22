"""
The incident case file's append-only writer.

This lives in its own module, rather than inside
`app.services.incidents`, for one structural reason: the response-action
state machine (`app.services.response_actions`) has to write approval and
execution entries onto an incident's timeline, while
`app.services.incidents` has to be able to *read* response actions. Giving
the timeline its own dependency-free module means neither of those has to
import the other.

**There is deliberately no API route that writes an `IncidentEvent`.**
Every entry is produced here, from inside the service function that
performed the underlying change, with a server-generated timestamp. A
caller cannot author a timeline entry, cannot back-date one, and cannot
attribute one to another actor — which is what makes the timeline usable
as an incident-response record rather than just a comment thread. The
same reasoning is why `app/api/v1/incidents.py` exposes
`GET /incidents/{id}/timeline` and no corresponding POST/PATCH/DELETE.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.models.enums import IncidentTimelineKind
from app.models.incident import IncidentEvent


def record_timeline_event(
    db: Session,
    *,
    incident_id: uuid.UUID,
    kind: IncidentTimelineKind,
    actor: str | None,
    details: dict[str, Any] | None = None,
    commit: bool = True,
) -> IncidentEvent:
    """
    Append one entry to an incident's timeline.

    `actor` is a label, not a foreign key: a timeline entry can be
    attributed to a human (their email), to an AI agent
    ("ai_agent:response"), or to the platform itself (None, for entries
    that are a consequence of a rule rather than of somebody's action).
    Tying it to `users.id` would make the first two unrepresentable.

    `commit=False` lets a caller batch several entries into the single
    transaction that also performs the change they describe, so a
    half-written case file is not a state the database can be left in.
    """
    entry = IncidentEvent(
        incident_id=incident_id,
        event_timestamp=datetime.now(timezone.utc),
        kind=kind.value,
        actor=actor,
        details=details or {},
    )
    db.add(entry)
    if commit:
        db.commit()
    else:
        db.flush()
    return entry
