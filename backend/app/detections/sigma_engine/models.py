"""
In-memory representation of a parsed Sigma rule. Deliberately a thin,
purpose-built model — not a full Sigma spec implementation (see the
sigma_engine package docstring in loader.py for why).
"""
from __future__ import annotations

from dataclasses import dataclass, field


class SigmaRuleError(ValueError):
    """Raised for a structurally invalid Sigma YAML file."""


@dataclass
class SigmaRule:
    rule_id: str
    title: str
    description: str
    level: str
    status: str
    logsource: dict
    detection: dict  # raw {"selection_name": {...}, ..., "condition": "..."}
    mitre_technique_ids: list[str] = field(default_factory=list)
    source_path: str | None = None
