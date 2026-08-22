"""
Idempotent upsert of BUILTIN_HUNT_QUERIES into `hunt_queries`, mirroring
the pattern app/detections/engine.py::sync_detection_rules uses for
DETECTION_REGISTRY: the DB always reflects exactly what's defined in code,
with the builtin's `name` (scoped to `organization_id IS NULL,
is_builtin=True`) as the natural key — a name collision with an org's own
custom query is not a conflict, since custom queries are scoped to that
org's non-null `organization_id`.
"""
from __future__ import annotations

import structlog
from sqlalchemy.orm import Session

from app.hunting.builtin_queries import BUILTIN_HUNT_QUERIES
from app.models.hunting import HuntQuery

log = structlog.get_logger()


def sync_builtin_hunt_queries(db: Session) -> dict[str, HuntQuery]:
    existing = {
        q.name: q
        for q in db.query(HuntQuery).filter(HuntQuery.organization_id.is_(None), HuntQuery.is_builtin.is_(True)).all()
    }

    for definition in BUILTIN_HUNT_QUERIES:
        row = existing.get(definition["name"])
        if row is None:
            row = HuntQuery(name=definition["name"], organization_id=None, is_builtin=True)
            db.add(row)

        row.description = definition["description"]
        row.query_definition = definition["query_definition"]
        row.default_lookback_hours = definition.get("default_lookback_hours", 24)
        row.mitre_technique_ids = list(definition.get("mitre_technique_ids", []))
        existing[definition["name"]] = row

    db.commit()
    log.info("hunt_queries_synced", query_count=len(BUILTIN_HUNT_QUERIES))
    return {
        q.name: q
        for q in db.query(HuntQuery).filter(HuntQuery.organization_id.is_(None), HuntQuery.is_builtin.is_(True)).all()
    }
