"""
Self-written, dependency-light Sigma rule engine (see loader.py for why
this doesn't use pySigma's backend-conversion API). Exposes:

- `load_sigma_rules(directory)` — parse *.yml files into `SigmaRule`.
- `SigmaDetection` — adapts a parsed `SigmaRule` to the shared
  `DetectionDefinition` protocol so the registry/engine can dispatch to
  it exactly like a custom Python detection.
"""
from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from app.detections.base import DetectionMatch
from app.detections.sigma_engine.loader import load_sigma_rules  # noqa: F401 — re-exported package-level entry point
from app.detections.sigma_engine.matcher import match_event
from app.detections.sigma_engine.models import SigmaRule
from app.models.event import Event

__all__ = ["load_sigma_rules", "SigmaDetection"]

# Sigma logsource.category -> the Event.category values that can ever
# satisfy that rule. Keeps the per-event dispatch table (engine.py) from
# invoking a rule against event categories it could never match anyway.
LOGSOURCE_CATEGORY_MAP: dict[str, set[str]] = {
    "process_creation": {"process"},
    "network_connection": {"network", "firewall"},
    "dns_query": {"dns"},
    "file_event": {"file"},
    "registry_event": {"registry"},
    "authentication": {"authentication"},
}

_LEVEL_TO_RISK = {"low": 25, "medium": 50, "high": 75, "critical": 90}


class SigmaDetection:
    """Adapts a parsed SigmaRule to the DetectionDefinition protocol."""

    engine = "sigma"

    def __init__(self, rule: SigmaRule):
        self._rule = rule
        self.rule_id = rule.rule_id
        self.title = rule.title
        self.description = rule.description
        self.level = rule.level
        self.base_risk_score = _LEVEL_TO_RISK.get(rule.level, 50)
        self.mitre_technique_ids = rule.mitre_technique_ids
        self.source_path = rule.source_path
        self.logsource = rule.logsource
        logsource_category = rule.logsource.get("category")
        self.relevant_categories = LOGSOURCE_CATEGORY_MAP.get(logsource_category, {"process"})

    def run(self, db: Session, *, organization_id: uuid.UUID, triggering_event: Event) -> list[DetectionMatch]:
        if not match_event(self._rule, triggering_event):
            return []
        return [
            DetectionMatch(
                matched_event_ids=[triggering_event.id],
                fired_at=triggering_event.event_timestamp,
                host_name=triggering_event.host_name_raw,
                user=triggering_event.user,
                evidence_summary={
                    "engine": "sigma",
                    "rule_id": self.rule_id,
                    "matched_event": {
                        "id": str(triggering_event.id),
                        "process": triggering_event.process,
                        "parent_process": triggering_event.parent_process,
                        "command_line": triggering_event.command_line,
                        "user": triggering_event.user,
                        "host": triggering_event.host_name_raw,
                        "timestamp": triggering_event.event_timestamp.isoformat(),
                    },
                },
            )
        ]
