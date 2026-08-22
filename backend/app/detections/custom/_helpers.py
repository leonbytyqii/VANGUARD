"""Small shared query helpers for the custom/behavioral detections."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.models.event import Event


def events_in_window(
    db: Session,
    *,
    organization_id: uuid.UUID,
    category: str | None,
    before: datetime,
    minutes: int,
    host_name: str | None = None,
    user: str | None = None,
    exclude_event_id: uuid.UUID | None = None,
):
    """
    Events for this org in (before - minutes, before], optionally scoped
    to a category/host/user. Used by every correlation detection below to
    look back over a bounded window rather than the whole event table.
    """
    q = db.query(Event).filter(
        Event.organization_id == organization_id,
        Event.event_timestamp <= before,
        Event.event_timestamp > before - timedelta(minutes=minutes),
    )
    if category:
        q = q.filter(Event.category == category)
    if host_name:
        q = q.filter(Event.host_name_raw == host_name)
    if user:
        q = q.filter(Event.user == user)
    if exclude_event_id:
        q = q.filter(Event.id != exclude_event_id)
    return q.order_by(Event.event_timestamp.asc()).all()
