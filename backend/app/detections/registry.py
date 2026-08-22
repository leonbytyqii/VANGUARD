"""
Combines Sigma-backed rules (loaded from detections/sigma/*.yml at import
time) and the hand-written custom/behavioral detections into one
DETECTION_REGISTRY — the single list app/detections/engine.py dispatches
against. Adding a new detection is: drop a Sigma YAML file in
detections/sigma/, or add one class to app/detections/custom/ and list it
below. Nothing else changes.
"""
from __future__ import annotations

from pathlib import Path

from app.detections.base import DetectionDefinition
from app.detections.custom.brute_force import BruteForceDetection
from app.detections.custom.cloud_privilege_escalation import CloudPrivilegeEscalationDetection
from app.detections.custom.dns_anomaly import DNSAnomalyDGADetection
from app.detections.custom.impossible_travel import ImpossibleTravelDetection
from app.detections.custom.lateral_movement import LateralMovementDetection
from app.detections.custom.suspicious_api_key_usage import SuspiciousAPIKeyUsageDetection
from app.detections.custom.suspicious_outbound_connection import SuspiciousOutboundConnectionDetection
from app.detections.custom.unusual_iam_activity import UnusualIAMActivityDetection
from app.detections.sigma_engine import SigmaDetection
from app.detections.sigma_engine.loader import load_sigma_rules

# backend/app/detections/registry.py -> repo_root/detections/sigma
SIGMA_RULES_DIR = Path(__file__).resolve().parents[3] / "detections" / "sigma"

CUSTOM_DETECTIONS: list[DetectionDefinition] = [
    BruteForceDetection(),
    LateralMovementDetection(),
    SuspiciousOutboundConnectionDetection(),
    DNSAnomalyDGADetection(),
    ImpossibleTravelDetection(),
    UnusualIAMActivityDetection(),
    SuspiciousAPIKeyUsageDetection(),
    CloudPrivilegeEscalationDetection(),
]


def _load_sigma_detections() -> list[DetectionDefinition]:
    return [SigmaDetection(rule) for rule in load_sigma_rules(SIGMA_RULES_DIR)]


def build_detection_registry() -> list[DetectionDefinition]:
    """
    Rebuilt as a function (not just a module-level constant) so tests can
    point SIGMA_RULES_DIR at a fixture directory if needed, and so a
    detections-reload endpoint could re-read Sigma files from disk without
    restarting the process, later.
    """
    return _load_sigma_detections() + list(CUSTOM_DETECTIONS)


DETECTION_REGISTRY: list[DetectionDefinition] = build_detection_registry()
