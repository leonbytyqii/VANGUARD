"""
Read-only MITRE ATT&CK catalog + detection-coverage endpoints. Everything
here is org-independent reference data (the catalog and detection rules
are both shared across tenants — see app/models/mitre.py and
app/models/detection.py's docstrings), so nothing in this router is
tenant-scoped, unlike most of the rest of the API.
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.deps import require_permission
from app.db.session import get_db
from app.models.mitre import MitreTactic, MitreTechnique
from app.models.user import User
from app.schemas.mitre import (
    DetectionRuleCoverageOut,
    MatrixTacticColumn,
    MatrixTechniqueCell,
    MitreMatrixResponse,
    MitreTacticOut,
    MitreTechniqueOut,
)

router = APIRouter(prefix="/mitre", tags=["mitre"])


@router.get("/tactics", response_model=list[MitreTacticOut])
def list_tactics(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("mitre.read")),
):
    tactics = db.query(MitreTactic).order_by(MitreTactic.matrix_order.asc()).all()
    out = []
    for tactic in tactics:
        technique_count = len(tactic.techniques)
        covered_count = sum(1 for t in tactic.techniques if t.detection_rules)
        item = MitreTacticOut.model_validate(tactic)
        item.technique_count = technique_count
        item.covered_technique_count = covered_count
        out.append(item)
    return out


@router.get("/techniques", response_model=list[MitreTechniqueOut])
def list_techniques(
    tactic_id: str | None = Query(None, description="Filter by MitreTactic.tactic_id, e.g. TA0002"),
    covered_only: bool | None = Query(None, description="If true, only techniques with >=1 linked detection rule"),
    q: str | None = Query(None, description="Case-insensitive substring match on technique name or ID"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("mitre.read")),
):
    query = db.query(MitreTechnique)
    if tactic_id:
        tactic = db.query(MitreTactic).filter(MitreTactic.tactic_id == tactic_id).one_or_none()
        if tactic is None:
            raise HTTPException(status_code=404, detail="Unknown tactic_id")
        query = query.filter(MitreTechnique.tactic_id == tactic.id)
    if q:
        like = f"%{q.lower()}%"
        query = query.filter(
            (MitreTechnique.name.ilike(like)) | (MitreTechnique.technique_id.ilike(like))
        )

    techniques = query.order_by(MitreTechnique.technique_id.asc()).all()
    if covered_only is not None:
        techniques = [t for t in techniques if bool(t.detection_rules) == covered_only]

    out = []
    for t in techniques:
        item = MitreTechniqueOut.model_validate(t)
        item.is_subtechnique = t.is_subtechnique
        item.detection_rule_count = len(t.detection_rules)
        out.append(item)
    return out


@router.get("/techniques/{technique_id}/coverage", response_model=list[DetectionRuleCoverageOut])
def get_technique_coverage(
    technique_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("mitre.read")),
):
    """Which detection rules (if any) cover a given ATT&CK technique ID, e.g. T1059.001."""
    technique = db.query(MitreTechnique).filter(MitreTechnique.technique_id == technique_id).one_or_none()
    if technique is None:
        raise HTTPException(status_code=404, detail="Unknown technique_id")
    return [
        DetectionRuleCoverageOut(rule_id=r.rule_id, title=r.title, engine=r.engine, enabled=r.enabled)
        for r in technique.detection_rules
    ]


@router.get("/matrix", response_model=MitreMatrixResponse)
def get_matrix(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("mitre.read")),
):
    """
    The full ATT&CK-matrix-shaped view: tactics (in ATT&CK's own order)
    each holding their techniques, annotated with which detection rules
    (if any) cover them. This is the data contract for the dashboard
    matrix view (Phase 12 wires it into the frontend — see
    docs/DETECTION_ENGINE.md and the app/mitre placeholder page).
    """
    tactics = db.query(MitreTactic).order_by(MitreTactic.matrix_order.asc()).all()

    total_techniques = 0
    covered_techniques = 0
    columns: list[MatrixTacticColumn] = []
    for tactic in tactics:
        cells: list[MatrixTechniqueCell] = []
        for t in sorted(tactic.techniques, key=lambda x: x.technique_id):
            covered = bool(t.detection_rules)
            total_techniques += 1
            covered_techniques += 1 if covered else 0
            cells.append(
                MatrixTechniqueCell(
                    technique_id=t.technique_id,
                    name=t.name,
                    is_subtechnique=t.is_subtechnique,
                    parent_technique_id=t.parent.technique_id if t.parent else None,
                    detection_rule_ids=[r.rule_id for r in t.detection_rules],
                    covered=covered,
                )
            )
        columns.append(
            MatrixTacticColumn(tactic_id=tactic.tactic_id, name=tactic.name, matrix_order=tactic.matrix_order, techniques=cells)
        )

    coverage_pct = round((covered_techniques / total_techniques) * 100, 1) if total_techniques else 0.0
    return MitreMatrixResponse(
        tactics=columns, total_techniques=total_techniques, covered_techniques=covered_techniques, coverage_pct=coverage_pct
    )
