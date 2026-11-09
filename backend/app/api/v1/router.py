from fastapi import APIRouter

from app.api.v1 import (
    admin,
    ai,
    alerts,
    auth,
    cloud,
    dashboard,
    detections,
    events,
    health,
    hunting,
    incidents,
    lab,
    mitre,
    response,
    threat_intel,
)

api_router = APIRouter()
api_router.include_router(health.router, tags=["meta"])
api_router.include_router(auth.router)
api_router.include_router(admin.router)
api_router.include_router(response.router)
api_router.include_router(incidents.router)
api_router.include_router(events.router)
api_router.include_router(detections.router)
api_router.include_router(alerts.router)
api_router.include_router(mitre.router)
api_router.include_router(hunting.router)
api_router.include_router(ai.router)
api_router.include_router(threat_intel.router)
api_router.include_router(cloud.router)
api_router.include_router(dashboard.router)
api_router.include_router(lab.router)

# Every router the platform exposes is registered above. New ones are added
# here as each phase lands — see docs/ARCHITECTURE.md for the phase plan.
