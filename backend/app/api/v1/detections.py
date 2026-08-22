import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.deps import require_permission
from app.core.scope import scoped_query
from app.db.session import get_db
from app.detections.engine import run_all_detections, sync_detection_rules
from app.models.detection import Detection, DetectionRule
from app.models.user import User
from app.schemas.detection import DetectionOut, DetectionRuleOut, DetectionRunResponse
from app.services.alerting import generate_alerts_for_detections

router = APIRouter(prefix="/detections", tags=["detections"])


@router.get("/rules", response_model=list[DetectionRuleOut])
def list_detection_rules(
    engine: str | None = None,
    enabled: bool | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("detections.read")),
):
    # DetectionRule is the shared, org-independent rule catalog (not
    # tenant data) — every organization sees the same set of loaded
    # rules, same as every deployment runs the same Sigma/custom
    # detection code.
    q = db.query(DetectionRule)
    if engine:
        q = q.filter(DetectionRule.engine == engine)
    if enabled is not None:
        q = q.filter(DetectionRule.enabled == enabled)
    rules = q.order_by(DetectionRule.title.asc()).all()
    return [DetectionRuleOut.model_validate(r) for r in rules]


@router.get("", response_model=list[DetectionOut])
def list_detections(
    rule_id: uuid.UUID | None = None,
    host: str | None = None,
    user: str | None = None,
    min_risk_score: int | None = Query(None, ge=0, le=100),
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("detections.read")),
):
    q = scoped_query(db, Detection, current_user)
    if rule_id:
        q = q.filter(Detection.rule_id == rule_id)
    if host:
        q = q.filter(Detection.host_name == host)
    if user:
        q = q.filter(Detection.user == user)
    if min_risk_score is not None:
        q = q.filter(Detection.risk_score >= min_risk_score)
    if start_time:
        q = q.filter(Detection.fired_at >= start_time)
    if end_time:
        q = q.filter(Detection.fired_at <= end_time)

    detections = q.order_by(Detection.fired_at.desc()).offset(offset).limit(limit).all()
    return [DetectionOut.model_validate(d) for d in detections]


@router.get("/{detection_id}", response_model=DetectionOut)
def get_detection(
    detection_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("detections.read")),
):
    detection = scoped_query(db, Detection, current_user).filter(Detection.id == detection_id).one_or_none()
    if detection is None:
        raise HTTPException(status_code=404, detail="Detection not found")
    return DetectionOut.model_validate(detection)


@router.post("/run", response_model=DetectionRunResponse)
def trigger_detection_run(
    since: datetime | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("detections.run")),
):
    """
    Manual full-sweep trigger (soc_manager/admin only). Re-evaluates
    events in [since, now] against every loaded detection — useful after
    enabling a new/edited rule, or replaying attack-simulation-lab
    telemetry that was ingested before a relevant rule existed. Every
    newly-fired detection also generates/reinforces an Alert, same as the
    ingestion-time path (app/services/alerting.py's dedup logic keeps a
    re-run from spamming duplicate alerts for patterns already alerted on).
    """
    sync_detection_rules(db)
    fired = run_all_detections(db, organization_id=current_user.organization_id, since=since)
    if fired:
        generate_alerts_for_detections(db, organization_id=current_user.organization_id, detections=fired)
    return DetectionRunResponse(detections_fired=len(fired), detection_ids=[d.id for d in fired])
