"""
Shannon-entropy-based DGA (Domain Generation Algorithm) heuristic.
Explicitly documented as a simplification: real DGA detection uses
trained classifiers over n-gram frequency and TLD/registration
reputation; entropy-thresholding is a well-known, easy-to-explain
approximation that catches the obvious cases (e.g.
'kq3jx9z1vw8p.com') while missing dictionary-based DGAs and flagging
some legitimate but randomly-named CDN/tracking subdomains — a tradeoff
worth stating plainly in an interview rather than overselling accuracy.
"""
from __future__ import annotations

import math
import uuid
from collections import Counter

from sqlalchemy.orm import Session

from app.detections.base import DetectionMatch
from app.models.event import Event

ENTROPY_THRESHOLD = 3.6
MIN_LABEL_LENGTH = 12


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


class DNSAnomalyDGADetection:
    rule_id = "custom_dns_anomaly_dga"
    title = "Possible DGA Domain (High-Entropy DNS Query)"
    description = (
        f"The queried domain's primary label has length >= {MIN_LABEL_LENGTH} "
        f"and Shannon entropy >= {ENTROPY_THRESHOLD}, consistent with an "
        "algorithmically-generated domain used for C2 rendezvous. "
        "Heuristic simplification — see module docstring for known "
        "false-positive/false-negative tradeoffs."
    )
    engine = "custom_python"
    level = "medium"
    base_risk_score = 55
    mitre_technique_ids = ["T1568.002", "T1071.004"]
    relevant_categories = {"dns"}

    def run(self, db: Session, *, organization_id: uuid.UUID, triggering_event: Event) -> list[DetectionMatch]:
        domain = (triggering_event.domain or "").strip().lower()
        if not domain:
            return []

        label = domain.split(".")[0]
        if len(label) < MIN_LABEL_LENGTH:
            return []

        entropy = shannon_entropy(label)
        if entropy < ENTROPY_THRESHOLD:
            return []

        return [
            DetectionMatch(
                matched_event_ids=[triggering_event.id],
                fired_at=triggering_event.event_timestamp,
                host_name=triggering_event.host_name_raw,
                user=triggering_event.user,
                evidence_summary={
                    "pattern": "high_entropy_dns_label",
                    "domain": domain,
                    "label": label,
                    "entropy": round(entropy, 3),
                    "threshold": ENTROPY_THRESHOLD,
                },
            )
        ]
