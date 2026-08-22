import uuid

from pydantic import BaseModel


class MitreTechniqueOut(BaseModel):
    id: uuid.UUID
    technique_id: str
    name: str
    description: str
    tactic_id: uuid.UUID | None
    parent_technique_id: uuid.UUID | None
    is_subtechnique: bool
    detection_rule_count: int = 0

    model_config = {"from_attributes": True}


class MitreTacticOut(BaseModel):
    id: uuid.UUID
    tactic_id: str
    name: str
    description: str
    matrix_order: int
    technique_count: int = 0
    covered_technique_count: int = 0

    model_config = {"from_attributes": True}


class MatrixTechniqueCell(BaseModel):
    technique_id: str
    name: str
    is_subtechnique: bool
    parent_technique_id: str | None
    detection_rule_ids: list[str]  # DetectionRule.rule_id strings, e.g. "sigma_suspicious_powershell_encoded"
    covered: bool


class MatrixTacticColumn(BaseModel):
    tactic_id: str
    name: str
    matrix_order: int
    techniques: list[MatrixTechniqueCell]


class MitreMatrixResponse(BaseModel):
    tactics: list[MatrixTacticColumn]
    total_techniques: int
    covered_techniques: int
    coverage_pct: float


class DetectionRuleCoverageOut(BaseModel):
    rule_id: str
    title: str
    engine: str
    enabled: bool
