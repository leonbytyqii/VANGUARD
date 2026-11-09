# Contributing to VANGUARD

Thank you for your interest in contributing.

VANGUARD is a security operations platform. Contributions that strengthen engineering quality, detection coverage, AI reliability, tenant isolation, or test coverage are especially welcome.

---

## Getting started

**Prerequisites:** Python 3.11, Node.js 20, PostgreSQL 16, Docker (optional but recommended).

```bash
git clone https://github.com/leonbytyqii/VANGUARD.git
cd VANGUARD
cp .env.example .env
# Edit .env — set POSTGRES_PASSWORD and generate JWT_SECRET_KEY
docker compose up --build
```

For backend development without Docker:

```bash
cd backend
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
# Set DATABASE_URL to your local postgres, e.g.:
# export DATABASE_URL=postgresql+psycopg2://socai:socai@localhost:5432/socai
alembic upgrade head
uvicorn app.main:app --reload
```

For frontend development:

```bash
cd frontend
npm ci
npm run dev
```

---

## Running the test suite

```bash
# Local postgres must be running. See scripts/create_test_db.sh to create socai_test.
cd backend
pytest --tb=short -q
alembic check
```

```bash
cd frontend
npx tsc --noEmit
npm run build
```

All tests must pass and `alembic check` must report zero drift before opening a pull request. The CI workflow validates this automatically.

---

## Code standards

- **Python:** `ruff check .` must pass with zero errors. No `type: ignore` without a comment explaining why.
- **TypeScript:** `tsc --noEmit` must pass. No `any` without a comment.
- **SQL / migrations:** Use Alembic. Never hand-edit applied migrations. Every schema change needs a new migration.
- **Tests:** Every new backend route, service function, or detection must have tests. Test tenant isolation explicitly — a test that only checks the happy path without verifying cross-tenant rejection is incomplete.
- **Comments:** Explain WHY, not WHAT. Document non-obvious security decisions, invariants, and workarounds.

---

## Security architecture — mandatory constraints

Before contributing to the AI, detection, or response subsystems, read `docs/SECURITY.md` and `docs/ARCHITECTURE.md`. The constraints below are non-negotiable:

1. **AI agents must never possess privileged execution.** No new tool in `TOOL_REGISTRY` may carry `ActionEffect.PRIVILEGED_ACTION`. Privileged actions belong only in `PRIVILEGED_ACTION_CATALOG` and require human approval.
2. **Every AI conclusion must cite retrieved evidence.** The evidence validation gate in `app/ai/orchestrator.py` must remain intact.
3. **Tenant isolation is enforced server-side.** All queries for tenant-scoped resources must use `scoped_query` or an explicit `organization_id` filter. Never trust a client-supplied organization ID without validating against the authenticated user's organization.
4. **Prompt injection must not grant permissions.** Agent system prompts include the injection guard from `orchestrator.py`. Do not remove or weaken it.
5. **Simulated responses must never be represented as real execution.** The lab generates synthetic telemetry; it does not execute anything on the host.

Pull requests that weaken these properties will not be merged regardless of other merit.

---

## Pull request process

1. Fork the repository and create a feature branch from `main`.
2. Make your changes in small, testable commits.
3. Ensure the full test suite passes and ruff/tsc report clean.
4. Update `CHANGELOG.md` under an `[Unreleased]` section.
5. If you're adding a detection rule, include positive and negative test cases.
6. Open a pull request against `main` with a clear description of what changed and why.

For security vulnerabilities, use the private disclosure process described in `SECURITY.md` — do not open a public issue.
