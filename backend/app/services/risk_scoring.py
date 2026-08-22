"""
Alert risk-scoring formula. Deliberately a small set of pure functions
with no DB access — every weight is a named module-level constant with a
one-line justification, so "why did this alert score 78?" always has a
traceable, arithmetic answer rather than a black box. app/services/alerting.py
gathers the DB context (host criticality, repeat-offender count) and
calls these; keeping them separate is what makes them trivially unit
testable without a database.

score = clamp(0, 100, round(
    base_risk_score                      # from the firing Detection/DetectionRule (Phase 4);
                                          # already reflects Sigma `level` or a custom
                                          # detection's documented severity
  + ASSET_CRITICALITY_BONUS[host.criticality]
  + (REPEAT_OFFENDER_BONUS if repeat_offender else 0)
))

Deliberately NOT included yet (documented, not hidden):
- MITRE tactic/technique weighting — Phase 6 seeds the real ATT&CK
  catalog; weighting by tactic before that data exists would mean
  hardcoding a technique->tactic map here that's about to be replaced.
- Historical false-positive rate per rule — would need a feedback loop
  from analyst-closed alerts (status=false_positive) back into scoring,
  which is a reasonable Phase 9+ enhancement once there's enough closed-
  alert history to make the adjustment meaningful rather than noisy.
"""
from __future__ import annotations

from app.models.enums import Severity

# Asset criticality: how much worse is it if THIS host, specifically, is
# involved? A brute-force hit on a disposable dev VM and the same pattern
# on the domain controller are not the same risk, even with an identical
# base detection score.
ASSET_CRITICALITY_BONUS: dict[str, int] = {
    "low": -5,
    "standard": 0,
    "important": 10,
    "critical": 20,
}
DEFAULT_ASSET_CRITICALITY_BONUS = 0  # unknown host (not yet seen/registered) — treat as standard

# Repeat-offender: a second, *distinct* detection rule firing against the
# same host/user within the lookback window is a materially stronger
# signal than either firing alone — it suggests an ongoing chain of
# activity rather than one isolated (possibly false-positive) blip. This
# is intentionally keyed on *distinct rule* count, not repeat firings of
# the *same* rule — same-rule repeats are handled by alert dedup/
# reinforcement (app/services/alerting.py), not by inflating the score.
REPEAT_OFFENDER_BONUS = 15
REPEAT_OFFENDER_LOOKBACK_HOURS = 24
REPEAT_OFFENDER_DISTINCT_RULE_THRESHOLD = 1  # >=1 other distinct rule already alerted on this asset

# Severity thresholds. Chosen so a Sigma `critical` rule (base 90, see
# app/detections/sigma_engine/__init__.py::_LEVEL_TO_RISK) lands as
# Severity.CRITICAL on a standard-criticality asset with no other
# aggravating factors (90 + 0 + 0 = 90 >= 85), and a `low`-equivalent
# base score on a low-criticality asset with no repeat offenses lands as
# INFO/LOW rather than being inflated by rounding.
_SEVERITY_THRESHOLDS: list[tuple[int, Severity]] = [
    (85, Severity.CRITICAL),
    (65, Severity.HIGH),
    (40, Severity.MEDIUM),
    (20, Severity.LOW),
    (0, Severity.INFO),
]


def compute_alert_risk_score(*, base_risk_score: int, host_criticality: str | None, repeat_offender: bool) -> int:
    """
    Pure function: given the inputs, always returns the same score.
    Clamped to [0, 100] — the valid range for `Alert.risk_score` and for
    `risk_score_to_severity` below.
    """
    criticality_bonus = ASSET_CRITICALITY_BONUS.get(
        (host_criticality or "standard").lower(), DEFAULT_ASSET_CRITICALITY_BONUS
    )
    repeat_bonus = REPEAT_OFFENDER_BONUS if repeat_offender else 0

    raw = base_risk_score + criticality_bonus + repeat_bonus
    return max(0, min(100, round(raw)))


def risk_score_to_severity(score: int) -> str:
    """Deterministic mapping from a 0-100 score to a Severity value."""
    for threshold, severity in _SEVERITY_THRESHOLDS:
        if score >= threshold:
            return severity.value
    return Severity.INFO.value  # pragma: no cover — unreachable, threshold list ends at 0
