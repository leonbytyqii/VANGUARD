"""
Evaluates a parsed SigmaRule against a single normalized `Event`. The
underlying selection/condition evaluator (`evaluate_detection_dict`) is
also reused directly by the Phase 7 threat-hunting engine
(app/hunting/engine.py) to evaluate ad hoc, request-supplied
selection/condition dicts — see that function's docstring.

Two independent pieces:
1. Field mapping — translates Sigma's conventional Sysmon-flavoured field
   names (Image, ParentImage, CommandLine, ...) to SOC-AI's normalized
   `Event` column names (process, parent_process, command_line, ...), so
   rule authors can write rules using the vocabulary the wider Sigma
   ecosystem already uses, while the engine matches against our schema.
2. A small, safe boolean-condition evaluator for `detection.condition`
   (e.g. "selection and not filter"). It parses the string with `ast` and
   only permits BoolOp/UnaryOp(Not)/Name/Expression nodes — anything else
   (calls, attribute access, comparisons, literals used as code, ...)
   raises SigmaConditionError. This is not `eval()`: no arbitrary
   expression, not even a hardcoded one, is ever executed — the AST is
   walked and reduced by hand against a dict of {selection_name: bool}.
"""
from __future__ import annotations

import ast
import re

from app.detections.sigma_engine.models import SigmaRule, SigmaRuleError
from app.models.event import Event

# Sigma field name -> Event attribute name.
FIELD_MAP: dict[str, str] = {
    "Image": "process",
    "OriginalFileName": "process",
    "ParentImage": "parent_process",
    "CommandLine": "command_line",
    "ParentCommandLine": "command_line",
    "User": "user",
    "TargetUser": "user",
    "DestinationIp": "dst_ip",
    "DestinationPort": "dst_port",
    "SourceIp": "src_ip",
    "SourcePort": "src_port",
    "QueryName": "domain",
    "Hashes": "file_hash",
    "Sha256": "file_hash",
    "Md5": "file_hash",
    "Computer": "host_name_raw",
    "EventType": "event_type",
}

_MODIFIERS = ("contains", "startswith", "endswith", "re")


class SigmaConditionError(ValueError):
    pass


def _split_field_modifier(raw_field: str) -> tuple[str, str | None]:
    if "|" in raw_field:
        field_name, modifier = raw_field.split("|", 1)
        if modifier not in _MODIFIERS:
            raise SigmaRuleError(f"Unsupported Sigma field modifier '|{modifier}' on field '{raw_field}'")
        return field_name, modifier
    return raw_field, None


def _get_event_value(event: Event, sigma_field: str) -> str | int | None:
    attr = FIELD_MAP.get(sigma_field, sigma_field)
    return getattr(event, attr, None)


def _value_matches(event_value, expected, modifier: str | None) -> bool:
    if event_value is None:
        return False
    event_str = str(event_value)
    expected_str = str(expected)

    if modifier is None:
        return event_str.lower() == expected_str.lower()
    if modifier == "contains":
        return expected_str.lower() in event_str.lower()
    if modifier == "startswith":
        return event_str.lower().startswith(expected_str.lower())
    if modifier == "endswith":
        # Sigma rules are written against real-world Image/ParentImage
        # fields, which are full Windows paths (e.g.
        # 'C:\Windows\System32\powershell.exe'), so public rules
        # conventionally write 'Image|endswith: \powershell.exe' with a
        # leading path separator. SOC-AI's normalized Event.process field
        # deliberately stores just the executable name (see
        # app/schemas/event.py), not a full path — so a leading '\' or
        # '/' on the expected pattern is stripped before comparing,
        # letting rules be written in the conventional Sigma style while
        # still matching our simplified schema.
        return event_str.lower().endswith(expected_str.lower().lstrip("\\/"))
    if modifier == "re":
        return re.search(expected_str, event_str, re.IGNORECASE) is not None
    raise SigmaRuleError(f"Unsupported modifier '{modifier}'")  # pragma: no cover — guarded upstream


def _evaluate_selection(event: Event, selection: dict) -> bool:
    """Dict-AND semantics: every field in the selection must match."""
    for raw_field, expected in selection.items():
        field_name, modifier = _split_field_modifier(raw_field)
        event_value = _get_event_value(event, field_name)

        if isinstance(expected, list):
            # List-OR semantics: any one value in the list matching is enough.
            if not any(_value_matches(event_value, v, modifier) for v in expected):
                return False
        else:
            if not _value_matches(event_value, expected, modifier):
                return False
    return True


_ALLOWED_CONDITION_NODES = (
    ast.Expression,
    ast.BoolOp,
    ast.And,
    ast.Or,
    ast.UnaryOp,
    ast.Not,
    ast.Name,
    ast.Load,
)


def _validate_condition_ast(node: ast.AST) -> None:
    if not isinstance(node, _ALLOWED_CONDITION_NODES):
        raise SigmaConditionError(
            f"Disallowed syntax in Sigma condition: {type(node).__name__}. "
            "Only selection names combined with and/or/not/() are supported."
        )
    for child in ast.iter_child_nodes(node):
        _validate_condition_ast(child)


def _eval_condition_ast(node: ast.AST, selection_results: dict[str, bool]) -> bool:
    if isinstance(node, ast.Expression):
        return _eval_condition_ast(node.body, selection_results)
    if isinstance(node, ast.Name):
        if node.id not in selection_results:
            raise SigmaConditionError(f"Condition references unknown selection '{node.id}'")
        return selection_results[node.id]
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return not _eval_condition_ast(node.operand, selection_results)
    if isinstance(node, ast.BoolOp):
        values = [_eval_condition_ast(v, selection_results) for v in node.values]
        return all(values) if isinstance(node.op, ast.And) else any(values)
    raise SigmaConditionError(f"Unsupported condition node: {type(node).__name__}")  # pragma: no cover


def evaluate_condition(condition: str, selection_results: dict[str, bool]) -> bool:
    try:
        tree = ast.parse(condition, mode="eval")
    except SyntaxError as exc:
        raise SigmaConditionError(f"Invalid Sigma condition syntax: {condition!r}") from exc
    _validate_condition_ast(tree)
    return _eval_condition_ast(tree, selection_results)


def evaluate_detection_dict(event: Event, detection: dict, *, source_label: str = "detection") -> bool:
    """
    Core of `match_event()`, extracted so it can be reused against a raw
    Sigma-shaped `detection` dict directly — named selections plus a
    `condition` string — without requiring a loaded `SigmaRule`.

    This is what the threat-hunting engine (Phase 7,
    app/hunting/engine.py) runs a `HuntQuery.query_definition` through:
    the exact same field-mapping, modifier, and safe-AST condition logic
    that governs auto-firing Sigma detections, applied on demand against
    a bounded historical time range instead of a single triggering event.
    Reusing this function rather than writing a second matcher means a
    hunt query and a Sigma detection rule share one evidence-safe
    evaluation path and one set of tested edge cases.
    """
    condition = detection["condition"]

    selection_results: dict[str, bool] = {}
    for name, selection in detection.items():
        if name == "condition":
            continue
        if not isinstance(selection, dict):
            raise SigmaRuleError(f"{source_label}: selection '{name}' must be a mapping")
        selection_results[name] = _evaluate_selection(event, selection)

    return evaluate_condition(condition, selection_results)


def match_event(rule: SigmaRule, event: Event) -> bool:
    """True if `event` satisfies `rule`'s detection.condition."""
    return evaluate_detection_dict(event, rule.detection, source_label=f"Sigma rule {rule.rule_id}")
