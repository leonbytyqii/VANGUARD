"""
The AI layer's structured output contract (docs/ARCHITECTURE.md §4.4).
The AI never returns free text to the frontend or persists one — every
investigation's `result` is one of these two schemas, validated before
it is ever trusted.

`requires_approval` on `RecommendedContainmentAction` is typed
`Literal[True]` rather than `bool` — not merely validated as present.
This is a deliberately stronger guarantee than the architecture doc's
literal wording ("missing requires_approval" is rejected): a schema field
that can only ever be `True` makes "the AI proposes an action that skips
approval" a type error, not just a validation-time check that a bug could
weaken later. Nothing here executes anything regardless — the field only
ever reaches app.ai.tools.registry::_request_response_approval, which
files a *pending* ResponseAction; see app/services/response_actions.py's
state machine for the actual human-approval gate.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class ObservedEvidenceItem(BaseModel):
    """
    `source_event_id`/`source_table` are what app.ai.orchestrator's
    validator checks against the evidence this investigation actually
    retrieved via real tool calls (app/ai/agents/permissions.py) — a
    citation that doesn't resolve to a real, actually-seen row is
    grounds for rejecting the whole result. `source_event_id` is None
    for claims grounded in a non-Event source (an alert, host, or IOC
    lookup) — `source_table` still names where that came from.
    """
    claim: str
    source_tool: str
    source_event_id: str | None = None
    source_table: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)


class Hypothesis(BaseModel):
    statement: str
    likelihood: Literal["low", "medium", "high"]
    based_on: list[str] = Field(default_factory=list)  # indices/ids into observed_evidence


class MitreAttackTag(BaseModel):
    technique_id: str
    tactic: str


class AffectedAsset(BaseModel):
    type: Literal["host", "user", "cloud_identity", "ip"]
    id: str


class RecommendedContainmentAction(BaseModel):
    action: str  # validated against PRIVILEGED_ACTION_CATALOG in the orchestrator, not here (schema has no DB access)
    target: str
    reasoning: str
    requires_approval: Literal[True] = True


class AIInvestigationResult(BaseModel):
    severity: Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    risk_score: int = Field(ge=0, le=100)
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str
    observed_evidence: list[ObservedEvidenceItem] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    mitre_attack: list[MitreAttackTag] = Field(default_factory=list)
    affected_assets: list[AffectedAsset] = Field(default_factory=list)
    recommended_investigation: list[str] = Field(default_factory=list)
    recommended_containment: list[RecommendedContainmentAction] = Field(default_factory=list)
    false_positive_indicators: list[str] = Field(default_factory=list)


class TriageDecision(BaseModel):
    """
    The Triage Agent's much smaller output — "is this worth a full
    investigation?" (docs/ARCHITECTURE.md §4.2). Deliberately not a
    partial `AIInvestigationResult`: triage can conclude without ever
    calling the tools a full investigation would, and a short-circuited
    investigation should be visibly different in shape, not a
    result with most fields empty.
    """
    proceed: bool
    initial_severity: Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str
