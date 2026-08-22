#!/bin/sh
set -e

echo "Waiting for database..."
until python -c "
import sys, time, psycopg2, os
from app.core.config import settings
try:
    psycopg2.connect(settings.DATABASE_URL.replace('postgresql+psycopg2', 'postgresql'))
except Exception as e:
    sys.exit(1)
"; do
  sleep 1
done

echo "Running migrations..."
alembic upgrade head

echo "Seeding baseline data (roles/permissions/MITRE ATT&CK)..."
python -m app.db.seed || true

echo "Starting API server..."
exec uvicorn app.main:app --host 0.0.0.0 --port 8000
