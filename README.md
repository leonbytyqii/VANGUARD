# SOC-AI

**An agentic AI Security Operations Center platform** — SIEM ingestion and
detection, SOAR-style incident and approval workflows, and a multi-agent AI
investigation layer that gathers evidence through controlled tools, reasons
over it, and produces auditable, evidence-grounded conclusions rather than
free-text guesses. Full design rationale: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

> The AI never acts directly on the world. Every conclusion is grounded in
> retrieved evidence with a traceable source; every action with real-world
> effect requires explicit human approval. See §4 and §6 of the architecture
> doc for how that is enforced structurally, not just by prompt instruction.

**Status: all 15 phases complete.** 422 automated tests passing, `ruff check`
clean, `alembic check` reporting zero drift, and a Next.js frontend that
builds cleanly across 15 routes.

---

## What it does

| Capability | Detail |
|---|---|
| **Ingestion & normalization** | `POST /api/v1/events` with six pluggable source adapters (Windows/Sysmon, Linux auth, DNS, firewall, CloudTrail, lab). The raw payload is always preserved alongside the normalized projection. |
| **Detection engine** | A self-written, dependency-light Sigma YAML interpreter (4 rules) plus 8 custom Python correlation/behavioral detections, sharing one dispatch interface and running synchronously on ingest. |
| **Risk scoring & alerting** | A documented, fully arithmetic formula — base score + asset criticality + repeat-offender bonus — with dedup so a re-firing rule doesn't flood the queue. |
| **MITRE ATT&CK** | Curated Enterprise catalog (14 tactics, 49 techniques), relational tagging on rules/alerts/incidents, and a coverage matrix. |
| **Threat hunting** | On-demand bounded search over historical telemetry through the same safe, no-`eval()` matcher the Sigma engine uses. Every run records explicit truncation state. |
| **Agentic AI analyst** | Multi-agent orchestrator (Triage → Investigation → Threat Hunt / Response) over a provider-agnostic LLM interface, with an offline-safe deterministic provider as the default. |
| **Incident response** | NIST SP 800-61r2 lifecycle state machine, append-only case timeline, response checklist, IR metrics, AI-investigation promotion. |
| **Threat intelligence** | Provider-chain IOC enrichment with caching, aggregation, and an offline synthetic feed. |
| **Cloud / IAM** | CloudTrail projection, derived identities, and reconstructed identity attack-path graphs. |
| **SOC dashboard** | Fifteen real Next.js routes over the whole platform. |
| **Attack simulation lab** | Eight scenarios replayed through the real ingestion path — an end-to-end test of the detection stack you can watch happen. |

---

## Five design decisions worth reading

These are more interesting than the feature list.

**1. Privileged actions are structurally unreachable, not prompt-discouraged.**
`isolate_host`, `disable_account`, `block_ip`, `revoke_cloud_credentials` are
not in the AI tool registry at all — there is nothing to dispatch to. No
agent's effect ceiling permits `privileged_action`, and no registry tool is
classified as one. A prompt-injected agent can, at most, ask for a tool that
does not exist.

**2. The AI cannot cite evidence that does not exist.**
Every claim must name a `source_tool` and, where applicable, a
`source_event_id` that was both actually retrieved this session *and*
resolves to a real row in the caller's tenant. A result that fails is
rejected, persisted as a visible `conclude_rejected` step, and retried once.
The same check runs again when an investigation is promoted to an incident,
because a stored result is just data by then.

**3. "No data" and "zero" are never rendered the same way.**
An un-scored indicator is `unknown`, never `clean`. An un-reached IR
milestone is `null`, never `0` — "0s mean time to contain" reads as flawless
performance when it means nothing was contained. A bounded hunt says it was
bounded. This runs from the database through the API schema to the pixel.

**4. Integrity comes from absent code paths, not permission checks.**
The audit log and the incident timeline have no write route at all — not a
protected one, none. Their integrity does not depend on an authorization
check a later refactor could relax.

**5. Every limitation is stated, not omitted.**
Response execution is simulated. Attack paths show what was *observed*, not
what IAM policy makes *possible*. The offline threat feed genuinely does not
know about most indicators. [`docs/HARDENING.md`](docs/HARDENING.md) §8 lists
every remaining gap.

---

## Quick start

### Option A — Docker Compose

```bash
cp .env.example .env
# generate a real secret:
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
# set JWT_SECRET_KEY and POSTGRES_PASSWORD in .env, then:
docker compose up --build
```

- Frontend: http://localhost:3000
- Backend API: http://localhost:8000 (docs at `/api/docs` outside production)

### Option B — Local development

```bash
# Backend
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
alembic upgrade head
python -m app.db.seed          # prints the bootstrap admin password once
uvicorn app.main:app --reload

# Frontend (separate terminal)
cd frontend
npm install
npm run dev
```

Sign in with the bootstrap admin credential `seed.py` printed, then open
**Simulation Lab** and run a scenario — it populates the platform with
telemetry, detections, alerts and cloud identities in one click.

---

## Running the checks

```bash
cd backend
./../scripts/create_test_db.sh   # one-time: creates the socai_test database
pytest -q                        # 422 tests
ruff check .                     # clean
alembic check                    # no drift

cd ../frontend
npx tsc --noEmit                 # clean
npm run build                    # 15 routes
```

### Test coverage by area

| File | Tests | Covers |
|---|---|---|
| `test_auth.py`, `test_rbac.py`, `test_rate_limiting.py`, `test_agent_permissions.py`, `test_models.py`, `test_health.py` | 57 | Argon2id auth, JWT rotation + reuse detection, lockout, 5 roles × 23 permissions, IDOR, agent tool allowlists and effect ceilings |
| `test_ingestion.py` | 14 | Six source adapters, normalization, derived process/connection rows |
| `test_detections.py` | 29 | Sigma + custom detections, each proven both ways (fires / doesn't) |
| `test_alerts.py`, `test_risk_scoring.py` | 34 | Scoring formula, dedup, reinforcement, tenant scoping |
| `test_mitre.py` | 15 | Catalog integrity, idempotent sync, coverage matrix |
| `test_hunting.py` | 20 | Safe matcher, execution bounds, truncation bookkeeping |
| `test_ai_investigation.py` | 16 | Full agent pipeline, fabrication-rejection gate |
| `test_incidents.py` | 70 | Lifecycle machine, timeline, metrics, promotion |
| `test_threat_intel.py` | 40 | Providers, aggregation, cache, extraction |
| `test_cloud_iam.py` | 36 | Projection, attack paths, the `account_id` tenancy trap |
| `test_lab.py` | 24 | Every scenario fires its expected detections |
| `test_security.py` | 67 | Adversarial suite, organized by attacker goal |
| `test_hardening.py` | 17 | Fail-closed startup checks, headers, `.gitignore` |

---

## Build phases

| Phase | Scope | Status |
|---|---|---|
| 1 | Architecture, repo, DB schema, Docker | ✅ done |
| 2 | Authentication + RBAC | ✅ done |
| 3 | Event ingestion + normalization | ✅ done |
| 4 | Detection engine (Sigma + custom + behavioral) | ✅ done |
| 5 | Alerts + risk scoring | ✅ done |
| 6 | MITRE ATT&CK integration | ✅ done |
| 7 | Threat hunting | ✅ done |
| 8 | Agentic AI SOC Analyst (multi-agent) | ✅ done |
| 9 | Incident response | ✅ done |
| 10 | Threat intelligence enrichment | ✅ done |
| 11 | Cloud/IAM security + attack-path analysis | ✅ done |
| 12 | SOC dashboard + UI | ✅ done |
| 13 | Security testing | ✅ done |
| 14 | Attack simulation lab | ✅ done |
| 15 | Documentation + hardening | ✅ done |

---

## Repository layout

```
soc-ai/
├── backend/            FastAPI service: API, ORM models, detections, AI agents
│   ├── app/
│   │   ├── api/v1/       REST endpoints (14 routers)
│   │   ├── core/         config, security, permissions, hardening
│   │   ├── models/       SQLAlchemy ORM (37 tables)
│   │   ├── schemas/      Pydantic request/response contracts
│   │   ├── services/     ingestion, risk scoring, incidents, threat intel, lab
│   │   ├── detections/   Sigma engine + custom/behavioral detections
│   │   ├── ai/           provider abstraction, orchestrator, tool registry
│   │   ├── incidents/    IR checklist templates (NIST SP 800-61r2)
│   │   ├── hunting/      hunt engine + built-in query library
│   │   ├── mitre/        ATT&CK data + mapping
│   │   ├── threat_intel/ providers, offline feed, extraction, aggregation
│   │   ├── cloud_iam/    CloudTrail projection + attack-path reconstruction
│   │   └── lab/          attack-simulation scenario library
│   ├── alembic/          migrations
│   └── tests/            422 tests
├── frontend/            Next.js 14 + TypeScript + Tailwind, dark SOC UI
├── detections/          Sigma rules (data, not code)
├── lab/                 sample telemetry
├── docs/                architecture + one doc per phase
├── docker-compose.yml
└── .env.example
```

---

## Documentation

Each phase doc explains not just what was built but **which alternative was
rejected and why** — that is the part worth reading.

- [`ARCHITECTURE.md`](docs/ARCHITECTURE.md) — system design, agent
  architecture, tool permission model, RBAC, data model, scaling, non-goals.
- [`SECURITY.md`](docs/SECURITY.md) — auth, RBAC, the AI agent permission
  model, human-in-the-loop approval, tenant scoping, audit architecture, and
  an attack-by-attack table of what stops it and which test proves it.
- [`DETECTION_ENGINE.md`](docs/DETECTION_ENGINE.md) — Sigma engine design
  (and why it isn't pySigma), custom detections and their documented
  heuristic limitations.
- [`RISK_SCORING.md`](docs/RISK_SCORING.md) — the scoring formula, dedup
  design, and two real bugs caught while building it.
- [`MITRE_ATTACK.md`](docs/MITRE_ATTACK.md) — catalog scope and sourcing, the
  single-tactic simplification, coverage-matrix design.
- [`THREAT_HUNTING.md`](docs/THREAT_HUNTING.md) — hunting vs. detection
  engineering, the shared matcher, execution bounds.
- [`AI_ANALYST.md`](docs/AI_ANALYST.md) — the orchestrator loop, provider
  abstraction, and the evidence-citation "never fabricate" gate.
- [`INCIDENT_RESPONSE.md`](docs/INCIDENT_RESPONSE.md) — the lifecycle state
  machine and its edge shapes, why closing requires a verdict, what makes the
  IR metrics trustworthy, the no-write-route timeline.
- [`THREAT_INTEL.md`](docs/THREAT_INTEL.md) — the unknown-is-not-clean rule,
  the provider contract, aggregation, caching, the documentation-range trap.
- [`CLOUD_IAM.md`](docs/CLOUD_IAM.md) — observed-vs-possible, the projection,
  the `account_id` tenancy trap, walk bounds.
- [`DASHBOARD.md`](docs/DASHBOARD.md) — one aggregation endpoint, `null` is
  not `0`, and surfacing the platform's honesty in the interface.
- [`SECURITY_TESTING.md`](docs/SECURITY_TESTING.md) — the adversarial suite by
  attacker goal, and the two bugs it found.
- [`LAB.md`](docs/LAB.md) — why scenarios replay through the real ingestion
  path, and why the lab is admin-only.
- [`HARDENING.md`](docs/HARDENING.md) — fail-closed startup checks, secret
  handling end to end, and an explicit list of remaining gaps.
