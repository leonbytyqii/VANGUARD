# Changelog

All notable changes to VANGUARD are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [0.1.0] — 2026-11-09

### Added — Backend

**Phase 1 — Core ingestion and schema**
- FastAPI application with Alembic migrations, structlog, and production hardening checks
- PostgreSQL 16 schema: organizations, users, roles, permissions, events, hosts, processes, network connections
- Six ingestion adapters: Windows Sysmon, Linux auth, DNS, Firewall, CloudTrail, Synthetic Lab
- Automatic Host record creation/update on first event from a new hostname
- Process and NetworkConnection projection rows derived from enriched event fields

**Phase 2 — Authentication and RBAC**
- JWT access tokens + HttpOnly refresh cookie with token rotation and reuse detection
- Five RBAC roles: `admin`, `soc_manager`, `soc_analyst`, `threat_hunter`, `viewer`
- Per-endpoint permission enforcement via FastAPI dependency injection
- Account lockout after configurable failed login attempts
- Password strength validation (minimum length, common-password blocklist)
- Rate limiting on auth endpoints (slowapi, per source IP)

**Phase 3 — Tenant isolation**
- `organization_id` column on every tenant-scoped model
- `scoped_query` helper enforces tenant boundaries at query construction time
- 404-not-403 response for cross-tenant resource access (IDOR enumeration prevention)

**Phase 4 — Detection engine**
- Sigma YAML interpreter with safe field-matching (no `eval`)
- Four Sigma rules: suspicious PowerShell, PowerShell spawned by Office, LSASS credential access, persistence via scheduled task
- Eight custom Python behavioral detections: brute-force login, impossible travel, lateral movement, cloud privilege escalation, DNS anomaly, suspicious outbound connection, unusual IAM activity, suspicious API key usage
- Category-dispatch table: detections only evaluated against relevant event categories
- Synchronous detection execution inline with ingestion (Celery seam documented for future async scaling)

**Phase 5 — Alert generation and risk scoring**
- Alert deduplication and reinforcement (same rule, same asset, within 30-minute window)
- Pure-function risk scoring: `base_risk_score + asset_criticality_bonus + repeat_offender_bonus`, bounded [0, 100]
- Five severity thresholds: INFO / LOW / MEDIUM / HIGH / CRITICAL

**Phase 6 — MITRE ATT&CK integration**
- ATT&CK Enterprise catalog: 14 tactics, 49 techniques seeded from bundled data
- Relational M2M tagging between detection rules and techniques, and between alerts and techniques
- ATT&CK coverage API: detected / partially-covered / uncovered breakdown

**Phase 7 — Threat hunting**
- Builtin hunt query library (8 queries)
- Hunt execution engine with tenant-scoped event search
- Results persisted for analyst review

**Phase 8 — AI agent orchestration**
- Three-phase investigation: Triage → Investigation → handoffs (ThreatHunt + Response)
- 14 AI tools: all `read_only` or `propose_only`, zero privileged actions
- Four-layer permission enforcement per tool call: identity enabled, tool registered, allowlist, effect ceiling
- Evidence validation gate: every cited event ID must have been retrieved via a real tool call in the same session and must resolve to a real DB row
- Prompt injection guard in every agent system prompt
- Investigation replay: partial traces persisted as `AgentStep` rows even on failure

**Phase 9 — Response and SOAR foundation**
- Response action state machine: proposed → pending → approved/rejected → executed/failed
- Mandatory human approval before any privileged action
- `PRIVILEGED_ACTION_CATALOG` defines the universe of possible action types — none callable by any agent
- SOC Blueprint playbook templates matched to detection rules

**Phase 10 — Threat intelligence**
- IOC normalization, deduplication, and freshness tracking
- Provider abstraction: mock (offline, deterministic) and live (VirusTotal, AbuseIPDB, OTX)
- `enrich_ioc` AI tool backed by real provider calls, cache-aware, never force-refreshes from agent loop

**Phase 11 — Cloud/IAM analysis**
- CloudTrail-shaped event projection: `cloud_events` and `cloud_identities` rows
- Attack path reconstruction via observed AssumeRole chains
- Three Cloud/IAM agent tools: `get_cloud_identity`, `get_role_assumptions`, `search_cloud_events`

**Phase 12 — Incident response**
- NIST SP 800-61r2 incident lifecycle: new → triaged → investigating → contained → eradicated → recovered → closed
- Mandatory closure classification: `true_positive`, `false_positive`, `benign_true_positive`, `duplicate`
- Immutable incident timeline (service-written only, no direct API for client-authored entries)
- Task templates auto-seeded per NIST phase on incident creation

**Phase 13 — Dashboard and audit**
- SOC overview API: EPS, open alerts, open incidents, MTTR/MTTC/MTTClose, top hosts/users/rules, alert timeseries
- Immutable audit log API with pagination and filtering

**Phase 14 — Attack simulation lab**
- Eight deterministic attack scenarios replayed through the real ingestion pipeline
- Scenario assertions in `test_lab.py` — a scenario that stops firing is a test failure

**Phase 15 — Production hardening**
- Startup checks: refuse to start in production with placeholder JWT secret, debug enabled, wildcard CORS, or `change_me` DB URL
- Security headers on every response: `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Content-Security-Policy`, `Permissions-Policy`, `Strict-Transport-Security` (production only)
- Interactive API docs disabled in production

### Added — Frontend

- Fifteen Next.js routes: Dashboard, Alerts, Alert Detail, AI Investigations, Investigation Detail, Incidents, Incident Detail, Threat Hunting, Cloud/IAM, MITRE ATT&CK, Threat Intelligence, Lab, Audit, Automation/Playbooks, Admin
- Real API integration via typed fetch client; no hardcoded statistics
- Single-flight token refresh — prevents refresh-token-reuse-detection false positives under concurrent requests
- Dark SOC color scheme: graphite/near-black foundation with restrained accent palette
- Component library: `StatTile`, `Panel`, `Table`, `EmptyState`, `ErrorState`, `Loading`, `Select`, `PageHeader`
- Alert-volume timeseries bar chart (Recharts)

### Added — Infrastructure

- Docker Compose: PostgreSQL 16, Redis 7, backend, frontend, Celery worker (behind `jobs` profile)
- Backend Dockerfile with non-root `appuser` runtime
- Alembic: 12 sequential migration files, zero drift on `alembic check`
- `scripts/create_test_db.sh` for local test database setup

### Added — Repository (v0.1.0 release engineering)

- GitHub Actions CI: backend (ruff lint, pytest, alembic check) + frontend (tsc, build)
- `LICENSE` (MIT)
- `CONTRIBUTING.md`
- Root `SECURITY.md`
- `CHANGELOG.md`
- GitHub issue templates: Bug Report, Feature Request, Detection Rule
- GitHub pull request template

---

[0.1.0]: https://github.com/leonbytyqii/VANGUARD/releases/tag/v0.1.0
