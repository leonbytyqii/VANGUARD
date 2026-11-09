"""
Single import point used by Alembic's env.py to discover all models via
Base.metadata. Keep this import (not the individual model modules) as the
target_metadata source of truth.
"""
import app.models  # noqa: F401  (populates Base.metadata as a side effect)
from app.db.base_class import Base  # noqa: F401
