#!/bin/sh
# Creates the socai_test database used by backend/tests (local/dev only).
set -e
PGPASSWORD="${POSTGRES_PASSWORD:-socai}" psql -h "${POSTGRES_HOST:-localhost}" -U "${POSTGRES_USER:-socai}" -d postgres \
  -c "SELECT 1 FROM pg_database WHERE datname = 'socai_test'" | grep -q 1 || \
PGPASSWORD="${POSTGRES_PASSWORD:-socai}" psql -h "${POSTGRES_HOST:-localhost}" -U "${POSTGRES_USER:-socai}" -d postgres \
  -c "CREATE DATABASE socai_test OWNER ${POSTGRES_USER:-socai};"
