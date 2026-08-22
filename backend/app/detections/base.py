"""
Uniform detection interface. Both Sigma-driven rules (single-event pattern
matching, translated from a YAML file at load time) and custom Python
detections (multi-event correlation / behavioral heuristics that don't fit
Sigma's model, e.g. "N failed logins + 1 success + new privileged
session") implement the same `DetectionDefinition` contract, so
`app/detections/engine.py` can dispatch to either without caring which.

Every detection's `run()` returns zero or more `DetectionMatch` objects.
A match must always cite the concrete `Event` row(s) that produced it
(`matched_event_ids`) — this is the same evidence-integrity rule that
governs the AI agents (docs/SECURITY.md, docs/ARCHITECTURE.md §6): a
detection is not allowed to assert something happened without a pointer
back to the raw evidence a human (or the AI investigation layer, later)
can independently re-examine.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol

from sqlalchemy.orm import Session

from app.models.event import Event


@dataclass
class DetectionMatch:
    """One firing of a detection against a specific set of evidence."""

    matched_event_ids: list[uuid.UUID]
    fired_at: datetime
    host_name: str | None = None
    user: str | None = None
    # Structured, evidence-grounded explanation of *why* this fired —
    # rendered as-is in the UI and consumable later by the AI Investigation
    # Agent as pre-collected evidence rather than something it has to
    # re-derive from scratch. Never free text asserting an unverified claim.
    evidence_summary: dict = field(default_factory=dict)
    # Optional per-match override of the rule's base_risk_score, for
    # detections whose severity depends on match specifics (e.g. brute
    # force is worse when the eventual success is on a privileged account).
    risk_score_override: int | None = None


class DetectionDefinition(Protocol):
    """
    Contract shared by Sigma-backed rules (app/detections/sigma_engine) and
    custom Python detections (app/detections/custom). `app.detections.registry`
    collects instances of both into one DETECTION_REGISTRY list.
    """

    rule_id: str
    title: str
    description: str
    engine: str  # DetectionEngine value: "sigma" | "custom_python" | "behavioral_correlation"
    level: str  # "low" | "medium" | "high" | "critical", mirrors Sigma's `level` field
    base_risk_score: int
    mitre_technique_ids: list[str]
    # Only events whose `category` is in this set are ever passed to this
    # detection — the engine's per-event dispatch table is keyed off this,
    # so a detection that only cares about "authentication" events never
    # even gets invoked for a DNS event. Custom correlation detections that
    # need to look back across a window still declare which category
    # *triggers* a re-evaluation.
    relevant_categories: set[str]

    def run(
        self,
        db: Session,
        *,
        organization_id: uuid.UUID,
        triggering_event: Event,
    ) -> list[DetectionMatch]:
        """
        Evaluate this detection in the context of one newly-ingested event
        that matched `relevant_categories`. Implementations that need
        historical context (e.g. brute force) query the DB themselves,
        scoped to `organization_id` and typically a bounded time window
        ending at `triggering_event.event_timestamp`.
        """
        ...
