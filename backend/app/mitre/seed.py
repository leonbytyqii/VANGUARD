"""
Idempotent sync of app/mitre/data.py's curated ATT&CK catalog into the DB,
plus relational linking of DetectionRule <-> MitreTechnique. Same
natural-key-lookup pattern as app/db/seed.py's permission/role/agent sync
and app/detections/engine.py::sync_detection_rules — running this twice
never duplicates rows, and it's safe to call on every app start.
"""
from __future__ import annotations

import structlog
from sqlalchemy.orm import Session

from app.mitre.data import TACTICS, TECHNIQUES
from app.models.detection import DetectionRule
from app.models.mitre import MitreTactic, MitreTechnique

log = structlog.get_logger()


def sync_mitre_catalog(db: Session) -> dict[str, MitreTechnique]:
    """
    Upserts every tactic then every technique (parents before
    sub-techniques — TECHNIQUES in app/mitre/data.py is already ordered
    that way, but this also does a second pass to resolve
    parent_technique_id regardless of declaration order, so the data file
    isn't load-bearing on ordering). Returns {technique_id: MitreTechnique}.
    """
    tactics_by_id = {t.tactic_id: t for t in db.query(MitreTactic).all()}
    for row in TACTICS:
        tactic = tactics_by_id.get(row["tactic_id"])
        if tactic is None:
            tactic = MitreTactic(tactic_id=row["tactic_id"])
            db.add(tactic)
        tactic.name = row["name"]
        tactic.description = row["description"]
        tactic.matrix_order = row["matrix_order"]
        tactics_by_id[row["tactic_id"]] = tactic
    db.flush()

    techniques_by_id = {t.technique_id: t for t in db.query(MitreTechnique).all()}
    for row in TECHNIQUES:
        technique = techniques_by_id.get(row["technique_id"])
        if technique is None:
            technique = MitreTechnique(technique_id=row["technique_id"])
            db.add(technique)
        technique.name = row["name"]
        technique.description = row["description"]
        technique.tactic_id = tactics_by_id[row["tactic_id"]].id
        techniques_by_id[row["technique_id"]] = technique
    db.flush()

    # Second pass: resolve parent_technique_id now that every technique
    # row is guaranteed to exist, regardless of declaration order in
    # TECHNIQUES.
    for row in TECHNIQUES:
        parent_str_id = row.get("parent_technique_id")
        if not parent_str_id:
            continue
        technique = techniques_by_id[row["technique_id"]]
        parent = techniques_by_id.get(parent_str_id)
        if parent is None:
            log.warning("mitre_technique_unknown_parent", technique_id=row["technique_id"], parent_id=parent_str_id)
            continue
        technique.parent_technique_id = parent.id

    db.commit()
    log.info("mitre_catalog_synced", tactics=len(TACTICS), techniques=len(TECHNIQUES))
    return {t.technique_id: t for t in db.query(MitreTechnique).all()}


def link_detection_rules_to_techniques(db: Session) -> None:
    """
    Populates DetectionRule.mitre_techniques (the relational M2M) from
    DetectionRule.mitre_technique_ids (the JSON list every detection
    already declares — app/detections/base.py). Must run after both
    sync_detection_rules (app/detections/engine.py) and
    sync_mitre_catalog above have populated their respective tables.

    A technique ID referenced by a detection but not present in the
    seeded MITRE catalog is logged and skipped rather than raising — a
    detection author adding a new MITRE tag shouldn't break app startup;
    it just means that one tag won't be relationally linked until the
    catalog in app/mitre/data.py is updated to include it.
    """
    techniques_by_id = {t.technique_id: t for t in db.query(MitreTechnique).all()}
    rules = db.query(DetectionRule).all()

    unresolved: set[str] = set()
    for rule in rules:
        resolved = []
        for technique_id in rule.mitre_technique_ids:
            technique = techniques_by_id.get(technique_id)
            if technique is None:
                unresolved.add(technique_id)
                continue
            resolved.append(technique)
        rule.mitre_techniques = resolved
        db.add(rule)

    db.commit()
    if unresolved:
        log.warning("mitre_technique_ids_not_in_catalog", technique_ids=sorted(unresolved))
    log.info("detection_rule_mitre_links_synced", rule_count=len(rules))
