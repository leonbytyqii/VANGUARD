"""
Lightweight Sigma YAML loader.

Deliberate design decision: this does NOT depend on pySigma's parsing /
backend-conversion machinery. pySigma is built to *compile* Sigma rules
into query languages for specific SIEM backends (Elasticsearch DSL,
Splunk SPL, ...); VANGUARD has no such backend yet — events live in
Postgres and are matched in-process against Python objects. Pulling in
pySigma's full pipeline/backend abstraction here would mean fighting an
API designed for a problem we don't have. Instead this package parses the
handful of Sigma constructs VANGUARD's rules actually use (field
selections with |contains/|startswith/|endswith/|re modifiers, list-OR,
dict-AND, and and/or/not/() in `condition`) with plain PyYAML plus a
small safe boolean-expression evaluator (matcher.py). This is an
explicit, documented scope reduction versus the full Sigma spec (no
aggregations like `count() > N`, no `1 of them` / `all of them` shortcuts,
no near/timeframe correlation) — those cases are exactly why the custom
Python detections in app/detections/custom exist instead of being forced
into Sigma YAML.
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

from app.detections.sigma_engine.models import SigmaRule, SigmaRuleError

_ATTACK_TAG_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)

REQUIRED_FIELDS = ("title", "id", "logsource", "detection")


def _extract_mitre_ids(tags: list[str]) -> list[str]:
    ids: list[str] = []
    for tag in tags or []:
        m = _ATTACK_TAG_RE.match(str(tag).strip())
        if m:
            ids.append(m.group(1).upper())
    return ids


def parse_sigma_rule(raw: dict, *, source_path: str | None = None) -> SigmaRule:
    missing = [f for f in REQUIRED_FIELDS if f not in raw]
    if missing:
        raise SigmaRuleError(f"Sigma rule {source_path or '<inline>'} missing required field(s): {missing}")

    detection = raw["detection"]
    if not isinstance(detection, dict) or "condition" not in detection:
        raise SigmaRuleError(f"Sigma rule {source_path or raw.get('id')} has no 'detection.condition'")

    return SigmaRule(
        rule_id=str(raw["id"]),
        title=str(raw["title"]),
        description=str(raw.get("description", "")),
        level=str(raw.get("level", "medium")).lower(),
        status=str(raw.get("status", "stable")),
        logsource=dict(raw.get("logsource") or {}),
        detection=detection,
        mitre_technique_ids=_extract_mitre_ids(raw.get("tags", [])),
        source_path=source_path,
    )


def load_sigma_rules(directory: str | Path) -> list[SigmaRule]:
    """
    Load every *.yml / *.yaml file in `directory` as a Sigma rule. A
    malformed file raises SigmaRuleError with the offending path rather
    than being silently skipped — a detection engine that can silently
    fail to load a rule is a worse failure mode than a loud startup error.
    """
    directory = Path(directory)
    rules: list[SigmaRule] = []
    if not directory.exists():
        return rules

    for path in sorted(directory.glob("*.yml")) + sorted(directory.glob("*.yaml")):
        with path.open("r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
        if not isinstance(raw, dict):
            raise SigmaRuleError(f"Sigma rule {path} did not parse to a mapping")
        rules.append(parse_sigma_rule(raw, source_path=str(path)))
    return rules
