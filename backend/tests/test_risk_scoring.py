"""
Pure unit tests for the risk-scoring formula — no DB, no client, just
arithmetic. Exhaustive on purpose: every named constant in
app/services/risk_scoring.py should have a test that would fail if the
constant's value silently changed.
"""
import pytest

from app.services.risk_scoring import (
    ASSET_CRITICALITY_BONUS,
    REPEAT_OFFENDER_BONUS,
    compute_alert_risk_score,
    risk_score_to_severity,
)


def test_base_score_unchanged_for_standard_criticality_no_repeat():
    assert compute_alert_risk_score(base_risk_score=50, host_criticality="standard", repeat_offender=False) == 50


@pytest.mark.parametrize("criticality,expected_bonus", list(ASSET_CRITICALITY_BONUS.items()))
def test_asset_criticality_bonus_applied(criticality, expected_bonus):
    score = compute_alert_risk_score(base_risk_score=50, host_criticality=criticality, repeat_offender=False)
    assert score == 50 + expected_bonus


def test_unknown_host_criticality_defaults_to_no_bonus():
    score = compute_alert_risk_score(base_risk_score=50, host_criticality="made_up_value", repeat_offender=False)
    assert score == 50


def test_none_host_criticality_treated_as_standard():
    score = compute_alert_risk_score(base_risk_score=50, host_criticality=None, repeat_offender=False)
    assert score == 50


def test_repeat_offender_adds_bonus():
    score = compute_alert_risk_score(base_risk_score=50, host_criticality="standard", repeat_offender=True)
    assert score == 50 + REPEAT_OFFENDER_BONUS


def test_criticality_and_repeat_offender_bonuses_stack():
    score = compute_alert_risk_score(base_risk_score=50, host_criticality="important", repeat_offender=True)
    assert score == 50 + ASSET_CRITICALITY_BONUS["important"] + REPEAT_OFFENDER_BONUS


def test_score_clamped_to_100():
    score = compute_alert_risk_score(base_risk_score=95, host_criticality="critical", repeat_offender=True)
    assert score == 100


def test_score_clamped_to_0():
    score = compute_alert_risk_score(base_risk_score=0, host_criticality="low", repeat_offender=False)
    assert score == 0


@pytest.mark.parametrize(
    "score,expected_severity",
    [
        (0, "INFO"),
        (19, "INFO"),
        (20, "LOW"),
        (39, "LOW"),
        (40, "MEDIUM"),
        (64, "MEDIUM"),
        (65, "HIGH"),
        (84, "HIGH"),
        (85, "CRITICAL"),
        (100, "CRITICAL"),
    ],
)
def test_risk_score_to_severity_thresholds(score, expected_severity):
    assert risk_score_to_severity(score) == expected_severity


def test_sigma_critical_level_lands_as_critical_severity_on_standard_asset():
    # Sigma `level: critical` -> base_risk_score 90 (app/detections/sigma_engine/__init__.py).
    score = compute_alert_risk_score(base_risk_score=90, host_criticality="standard", repeat_offender=False)
    assert risk_score_to_severity(score) == "CRITICAL"


def test_sigma_medium_level_on_low_criticality_asset_does_not_inflate_to_high():
    # Sigma `level: medium` -> base_risk_score 50; a low-criticality asset
    # should not creep this up into HIGH territory.
    score = compute_alert_risk_score(base_risk_score=50, host_criticality="low", repeat_offender=False)
    assert risk_score_to_severity(score) == "MEDIUM"
