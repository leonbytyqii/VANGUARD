"""
Shared slowapi Limiter instance. Lives in its own module (not app.main) so
route modules like app.api.v1.auth can import and apply `@limiter.limit(...)`
to specific endpoints without a circular import on the FastAPI app object.
"""
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.core.config import settings

limiter = Limiter(key_func=get_remote_address, default_limits=[settings.RATE_LIMIT_DEFAULT])
