# SOC-AI â€” System Architecture

## 1. What this is

SOC-AI is an **agentic Security Operations Center platform**. It combines the
data-plane of a SIEM (ingest, normalize, store, detect), the workflow-plane of
a SOAR (playbooks, incidents, human approval), and a **multi-agent AI
investigation layer** that behaves like a junior-to-mid SOC analyst: it
gathers evidence through a constrained set of tools, reasons over it, decides
what to look at next, and produces an auditable, evidence-grounded
conclusion â€” never a "chat with an LLM" wrapper.

The single idea that drives every design decision below:

> **The AI never acts directly on the world. It only ever produces
> recommendations grounded in retrieved evidence. Executing anything with
> real-world effect (isolating a host, disabling a user, blocking an IP)
> requires an explicit, logged, human approval step.**

**Build status:** all fifteen phases are complete. Everything this
document describes is implemented, tested against a live PostgreSQL
instance, and reachable through the API and the SOC UI — the enforcement
boundaries in §4.2, §6, §7 and §8.1 (agent tool permissions, RBAC, tenant
scoping); ingestion and normalization (§8.2); the detection engine
(§8.3); alerting and risk scoring (§8.4); the ATT&CK catalog and coverage
matrix (§8.5); threat hunting (§8.6); the LLM-driven agent loop and
provider-agnostic AI layer (§4.3–4.5, §5, §8.7); incident response
(§8.8); threat-intelligence enrichment (§8.9); cloud/IAM attack paths
(§8.10); the SOC dashboard (§8.11); the adversarial security suite
(§8.12); the attack-simulation lab (§8.13); and deployment hardening
(§8.14).

Where the platform deliberately stops short — simulated response
execution, no live cloud or EDR integration, single seeded tenant — it is
said so inline and collected in `docs/HARDENING.md` §8 and §10 below,
rather than left to be discovered.

## 2. Traditional SOAR vs. Agentic SOC

| | Traditional SOAR | SOC-AI (Agentic) |
|---|---|---|
| Control flow | Fixed playbook: step 1 â†’ step 2 â†’ step 3, always the same | Agent has a **goal** ("investigate this alert") and an **evidence state**; it picks the next tool call based on what it has already learned |
| Adaptation | None â€” a playbook can't skip or add steps based on findings | An investigation can branch: e.g. only pivots to IAM attack-path analysis if a cloud identity shows up in the process tree |
| Auditability | Playbook run log | Full **agent trace**: every tool call, every piece of evidence retrieved, every intermediate hypothesis, stored and replayable |
| Blueprints | Playbook *is* the logic | A **SOC Blueprint** is a *goal template with suggested steps* â€” the agent treats it as a starting checklist, not a script it's forced to follow verbatim |
| Action | Executes automatically | Proposes an action; a human approves before anything with real-world effect happens |

SOC-AI implements **both**: a classic deterministic Playbook Engine (for
predictable, low-risk enrichment work) and an Agentic Investigation layer
(for the parts of the job that require judgment). This is intentional â€” it
lets the platform demonstrate *why* agentic reasoning is used only where it
adds value, rather than everywhere.

## 3. High-level architecture

```
 ENDPOINTS / CLOUD / NETWORK (real or simulated in lab/)
   Windows Sysmon | Linux auth | DNS | Firewall | AWS CloudTrail-style
                              |
                              v
                    LOG INGESTION API  (POST /api/v1/events, source adapters)
                              |
                              v
                    NORMALIZATION ENGINE  (common event schema, raw preserved)
                              |
                              v
                        EVENT PIPELINE  (PostgreSQL: events table, indexed)
                 +--------------------+--------------------+
                 |                                         |
                 v                                         v
         DETECTION ENGINE                            THREAT HUNTING API
     (Sigma + custom Python +                    (ad-hoc structured search,
      behavioral correlation rules)                timeline reconstruction)
                 |
                 v
            RISK SCORING  (documented, deterministic formula â€” see
                            docs/DETECTION_ENGINE.md)
                 |
                 v
            ALERT ENGINE  (alerts table, severity, MITRE mapping, evidence refs)
                 |
    +------------+-------------------------------+
    |                                             |
    v                                             v
AI ORCHESTRATOR                              INCIDENT ENGINE
(multi-agent investigation)                  (lifecycle, tasks, notes, timeline,
                                              IR metrics; IOCs land Phase 10)
    |
    +-- Triage Agent          (is this worth investigating? initial severity)
    +-- Investigation Agent   (evidence collection via tools, hypothesis building)
    +-- Threat Hunt Agent     (pivots: "find all hosts where X happened")
    +-- Cloud/IAM Agent       (reconstructs identity -> role -> resource attack paths)
    +-- Response Agent        (proposes containment; NEVER executes without approval)
    |
    v
HUMAN APPROVAL  ---->  CONTROLLED ACTION (SOAR executor, logged, reversible where possible)
    |
    v
FULL INVESTIGATION REPORT + AUDIT TRACE  ---->  SOC DASHBOARD
```

## 4. Agent / tool architecture (the core of the "agentic" claim)

### 4.1 Why tools, not free-form LLM output

Every fact the AI uses comes from a **tool call against real platform data**.
The LLM is never shown raw arbitrary text and asked to "remember" facts; it
must call a tool (`get_process_tree`, `search_events`, `enrich_ioc`, â€¦) and
the tool's structured JSON return value becomes the only evidence it is
permitted to cite. This is what prevents hallucinated evidence: the
evidence objects in the final report carry a `source_tool` and
`source_event_id` back-reference that the API validates exist in the
database before the report is allowed to render.

### 4.2 Agent roster

| Agent | Goal | Tools it may call (as of Phase 9) | Grows in |
|---|---|---|---|
| **Triage Agent** | Decide if an alert deserves full investigation and assign initial severity | `get_alert`, `search_events`, `get_host_info` | â€” |
| **Investigation Agent** | Build an evidence-grounded narrative of what happened | `get_alert`, `search_events`, `get_host_info`, `enrich_ioc`, `get_process_tree`, `get_network_connections`, `map_mitre_technique` | â€” |
| **Threat Hunt Agent** | Answer "has this happened elsewhere?" pivots that Investigation surfaces | `search_events`, `enrich_ioc`, `search_by_technique` | â€” |
| **Cloud/IAM Agent** | Reconstruct identity-based attack paths | `search_events`, `get_host_info` | Phase 11: `get_cloud_identity`, `get_role_assumptions`, `search_cloud_events` |
| **Response Agent** | Turn conclusions into a containment plan | `draft_containment_plan`, `request_response_approval`, `check_related_incidents` | â€” |

Each row above is a real, seeded `agent_identities` database row (not a
comment) â€” `allowed_tools` and `max_effect` live in
`app/ai/agents/permissions.py::AGENT_TOOL_ALLOWLIST` /
`AGENT_MAX_EFFECT`, and `app/db/seed.py` writes them into the DB from that
same source so the enforced allowlist and the seeded data can never drift
apart. **Every agent's `max_effect` is `read_only` except the Response
Agent, which is `propose_only` â€” no agent, ever, has a ceiling that
permits `privileged_action`.** The dispatcher that checks this,
`app.ai.agents.permissions.invoke_agent_tool`, was fully built and tested
in Phase 2 (see `docs/SECURITY.md` Â§"Agent identity model" and
`backend/tests/test_agent_permissions.py`) â€” *before* Phase 8 built the
LLM-driven agent loop that calls it end-to-end. Building the enforcement
boundary before the thing it constrains meant the permission tests never
depended on â€” or waited for â€” any model's behavior, and Phase 8's four new
tools (`get_process_tree`, `get_network_connections`,
`map_mitre_technique`, `search_by_technique`) slotted into that
already-proven gateway with zero changes to how it enforces. Phase 9 added a fifth, `check_related_incidents`, the same way.

All agents share one **AgentContext**: the alert, its related normalized
events, host/user metadata, detection rule that fired, and the running
evidence log. Agents write to a shared `Investigation` object rather than
talking to each other directly â€” this keeps the system inspectable (you can
always look at the Investigation object and see exactly what every agent
contributed) and avoids uncontrolled agent-to-agent chatter.

### 4.3 The loop (goal â†’ investigate â†’ reason â†’ act â†’ verify)

1. **Goal**: Investigation Agent is invoked with an alert ID.
2. **Plan**: it optionally starts from a matching *SOC Blueprint* (a
   suggested checklist of investigation steps for this alert type) but is
   not required to follow it in order.
3. **Investigate**: it selects a tool call, receives structured evidence,
   appends it to the Investigation's evidence log.
4. **Reason**: after each tool result it decides â€” enough evidence to
   conclude, or does a new lead need pivoting (e.g. an unfamiliar external
   IP appears â†’ call `enrich_ioc`; a cloud role shows up â†’ hand off to the
   Cloud/IAM Agent)?
5. **Act (propose only)**: once confidence crosses a threshold, it produces
   the structured report (see Â§4.4) including a Response Agent pass for
   recommended containment.
6. **Human approval**: any action tagged `requires_approval` is surfaced in
   the UI; nothing executes until an analyst with sufficient RBAC role
   clicks Approve.
7. **Verify**: executed actions are logged back onto the Investigation and,
   where possible, the platform re-checks the relevant telemetry to confirm
   the action had the intended effect.
8. Every step above is persisted to `ai_investigations` /
   `agent_steps` / `audit_logs` â€” the full trace is replayable in the UI.

### 4.4 Structured, validated output contract

The AI layer never returns free text to the frontend. It returns JSON
matching a Pydantic schema (`AIInvestigationResult`) which the backend
validates before persisting or displaying:

```json
{
  "severity": "HIGH",
  "risk_score": 87,
  "confidence": 0.91,
  "summary": "Suspicious PowerShell execution",
  "observed_evidence": [
    {"claim": "...", "source_tool": "get_process_tree", "source_event_id": "..."}
  ],
  "hypotheses": [
    {"statement": "...", "likelihood": "medium", "based_on": ["evidence_id_1"]}
  ],
  "mitre_attack": [{"technique_id": "T1059.001", "tactic": "Execution"}],
  "affected_assets": [{"type": "host", "id": "WIN-01"}],
  "recommended_investigation": ["..."],
  "recommended_containment": [
    {"action": "isolate_host", "target": "WIN-01", "requires_approval": true}
  ],
  "false_positive_indicators": ["..."]
}
```

Validation rejects the result (and asks the agent to retry, capped) if:
- any `observed_evidence[].source_event_id` wasn't actually retrieved via a
  real `search_events` tool call *this session*, or doesn't resolve to a
  real row in the organization's data â€” both checks run, since either one
  alone would still permit a plausible-sounding fabrication (see
  `docs/AI_ANALYST.md` for why both are necessary),
- `confidence` is outside `[0,1]` or `risk_score` outside `[0,100]`,
- any `recommended_containment[]` item's `action` isn't a recognized
  privileged-action type, or is missing `requires_approval` â€” this last
  one is actually a schema-level `Literal[True]`, not just a validated
  field, so "the AI proposes an action that skips approval" is a type
  error, not merely a check a future bug could weaken,
- the JSON doesn't match the schema at all (guards against prompt
  injection in ingested logs trying to change output shape/instructions).

### 4.5 Prompt-injection handling

Ingested log content (command lines, usernames, domains, cloud role names,
â€¦) is attacker-controlled data. It is never concatenated into the system
prompt as instructions. Concretely:
- Evidence passed to the model is always wrapped in a clearly delimited,
  labeled data block and the system prompt explicitly instructs the model
  that text inside that block is *data to analyze*, never *instructions to
  follow*.
- Tool results are structured JSON, not free text the model must "parse"
  for hidden commands.
- The model's only write path is the structured output schema above â€”
  there is no tool that lets the model execute shell/OS/API actions
  directly (see Â§5), so even a successful injection can at most produce a
  bad *recommendation*, which still requires human approval and is validated
  against the evidence log before it can be trusted.
- All tool calls the agent makes are logged; an analyst can see exactly
  which evidence "convinced" it of a conclusion.

## 5. Provider-agnostic AI layer

`app/ai/providers/` defines a `LLMProvider` interface
(`complete(messages, tools, response_schema) -> ProviderResponse`). Two
implementations ship: an `OpenAICompatibleProvider` (works with OpenAI,
Azure OpenAI, and any OpenAI-compatible endpoint via `AI_BASE_URL`) and a
`MockProvider` (deterministic, rule-based "analyst" used when no API key is
configured, so the platform is fully demonstrable offline). Provider choice
and model are environment-driven (`AI_PROVIDER`, `AI_MODEL`, `AI_API_KEY`,
`AI_BASE_URL`) â€” never hard-coded, never logged.

## 6. Tool permission model

Tools available to agents are defined in `app/ai/tools/registry.py` with an
explicit `effect` classification:

- `read_only` â€” may be called by any agent whose identity allowlist
  includes it (search, enrich, get_*).
- `propose_only` â€” produces a recommendation or a *pending* request; still
  zero real-world effect (`draft_containment_plan`,
  `request_response_approval`).
- `privileged_action` â€” isolate host, disable account, block IP/domain,
  revoke cloud credentials. These live only in
  `PRIVILEGED_ACTION_CATALOG`, a plain reference dict used to validate
  human-submitted response actions â€” **they are never entered into
  `TOOL_REGISTRY`, so `invoke_agent_tool` cannot dispatch to them for any
  agent under any circumstance.** They only ever happen through
  `/api/v1/response/actions/{id}/approve` + `/execute`, which require a
  human bearer token with `response.approve`.

Enforcement (`app/ai/agents/permissions.py::invoke_agent_tool`) runs, in
order: (1) is this agent identity enabled in the DB, (2) is the tool
name registered at all â€” this alone excludes every privileged action, (3)
is the tool in *this specific agent's* `allowed_tools`, (4) does the
tool's effect exceed the agent's `max_effect` ceiling. Full write-up,
including the tests that try to defeat each layer, in `docs/SECURITY.md`
Â§"Why authorization is enforced server-side rather than through AI
prompts".

This means "the LLM cannot execute a privileged action" is not a prompt
instruction the model could be talked out of â€” it is a structural fact
about which Python functions are even reachable from the agent runtime.

## 7. RBAC model

Roles: `admin`, `soc_manager`, `soc_analyst`, `threat_hunter`, `viewer`.
Permissions are `resource.action` pairs (`alerts.read`, `incidents.assign`,
`response.approve`, `admin.users`, â€¦) stored in `roles` / `permissions` /
`role_permissions` tables â€” the catalog and default role grants live in
`app/core/permissions.py`, not hard-coded per endpoint, so a permission can
be added or a role's grants changed without touching route code. FastAPI
dependencies (`Depends(require_permission("response.approve"))`) enforce
this per-route and audit every denial. Full detail, the complete
permission list, and the RBAC â†’ agent-permission distinction in
`docs/SECURITY.md`.

## 8. Data model (see `backend/app/models/`)

Core domains and their tables:
- **Identity/RBAC**: `organizations`, `users`, `roles`, `permissions`,
  `role_permissions`, `refresh_tokens`
- **Agent governance**: `agent_identities`
- **Telemetry**: `hosts`, `events`, `processes`, `network_connections`
- **Detection**: `detection_rules`, `detections`
- **Alerting**: `alerts`
- **MITRE**: `mitre_tactics`, `mitre_techniques`, `alert_mitre_techniques`
- **Incident response**: `incidents`, `incident_events`, `incident_tasks`,
  `incident_notes`
- **Threat intel**: `iocs`, `threat_intelligence`
- **Agentic AI**: `ai_investigations`, `agent_steps`, `agent_evidence`
- **Automation**: `playbooks`, `playbook_runs`, `soc_blueprints`,
  `response_actions`
- **Cloud/IAM**: `cloud_identities`, `cloud_events`, `iam_attack_paths`
- **Governance**: `audit_logs`

Every table that represents evidence carries enough foreign keys to trace
back to the original raw event â€” normalization never discards the source
payload (`events.raw_event JSONB`).

### 8.1 Multi-tenant / scope architecture

Every resource table an organization should never see across a tenant
boundary (hosts, events, alerts, incidents, IOCs, cloud identities, AI
investigations, playbooks, blueprints, response actions) includes
`organization_id` via `TenantScopedMixin`
(`app/db/base_class.py`), and route handlers read through
`app.core.scope.scoped_query(db, Model, current_user)` rather than
`db.query(Model)` directly. A single-tenant deployment runs with exactly
one seeded `Organization` (`slug="default"`), so today this is enforcing
"you only see your own org" as a no-op in practice â€” but every endpoint
built on `scoped_query` is already tenant-isolated, which is the point:
supporting a second real tenant later is a data-seeding change, not an
application rewrite. Cross-tenant lookups return `404`, not `403` â€” see
`docs/SECURITY.md` for why that distinction matters.

### 8.2 Event ingestion & normalization (Phase 3)

`POST /api/v1/events` accepts a **semi-normalized envelope**
(`app/schemas/event.py::EventIngestRequest`): a `source` field plus a flat
set of optional fields close to what a lightweight forwarder can already
produce (Sysmon-to-JSON, journald, a syslog relay, a CloudTrail
subscriber) without itself understanding SOC-AI's schema. `source`
selects one of six adapters (`app/services/ingestion/adapters/`):
`windows_sysmon`, `linux_auth`, `dns`, `firewall`, `cloudtrail`, and
`synthetic_lab` (a passthrough/inference adapter for the attack-simulation
lab and manual testing). Each adapter's only job is turning
source-specific vocabulary (`event_type="process_creation"`,
`action="failed_password"`, a CloudTrail `eventName`) into the platform's
common `category`/`action` taxonomy, and validating that its own
required fields are present â€” a missing `process` on a
`process_creation` event, or a missing `domain` on a `dns` event, is
rejected with a `422` naming exactly what's missing, not silently dropped
or half-normalized.

Adding a seventh source is: write one `SourceAdapter` subclass, add one
line to `ADAPTER_REGISTRY` in `app/services/ingestion/registry.py`.
Nothing else in the pipeline changes.

`app/services/ingestion/service.py::ingest_event` then, in one
transaction: upserts the `Host` row (by hostname within the caller's
organization, updating `last_seen_at`), writes the `Event` row with
`raw_event` set to the **full, untouched submitted payload** (not just
the fields the adapter used â€” normalization is additive, never
destructive), and â€” where the category warrants it â€” derives a `Process`
row (category=`process`) or `NetworkConnection` row (category=`network`/
`firewall`). Those derived rows are what Phase 7/8's process-tree view and
the `get_process_tree` agent tool will read from directly, rather than
re-deriving lineage from raw events on every click.

`POST /api/v1/events/batch` (capped at 500) reports **per-item partial
success** â€” one malformed event in a batch of 500 doesn't reject the other
499 â€” which matters once a real forwarder is shipping continuously and
occasionally sends a malformed record.

Both ingest endpoints require `events.ingest` (currently `admin`-only in
the seeded role matrix, treated as a machine/service credential rather
than a human analyst permission â€” see `docs/SECURITY.md`'s known
limitations for the natural next step of a dedicated API-key auth path for
high-volume forwarders). `GET /api/v1/events` / `GET /api/v1/events/{id}`
require `events.read` (all roles above `admin`-only functions have it) and
are tenant-scoped like every other resource in Â§8.1.

### 8.3 Detection engine (Phase 4)

Full design rationale, rule format, and how to add a rule:
[`docs/DETECTION_ENGINE.md`](DETECTION_ENGINE.md). Summary:

Every detection â€” whether a Sigma rule or a custom Python correlation â€”
implements one shared interface (`app/detections/base.py::DetectionDefinition`):
`rule_id`, `engine`, `level`, `base_risk_score`, `mitre_technique_ids`,
`relevant_categories`, and a `run(db, organization_id, triggering_event)`
method returning zero or more `DetectionMatch` objects, each of which must
cite the concrete `Event` row(s) it fired on (`matched_event_ids`) â€” the
same evidence-integrity rule that governs the AI agents in Â§4.4: nothing
in this platform is allowed to assert a finding without a pointer back to
re-checkable evidence.

Two engines feed the same registry (`app/detections/registry.py`):

- **Sigma engine** (`app/detections/sigma_engine/`) â€” a self-written,
  dependency-light YAML interpreter, deliberately *not* built on pySigma's
  backend-conversion API (see `sigma_engine/loader.py`'s docstring for
  why: pySigma compiles rules into query languages for specific SIEM
  backends SOC-AI doesn't have â€” events are matched in-process against
  Postgres-backed `Event` rows instead). Supports field selections with
  `|contains`/`|startswith`/`|endswith`/`|re` modifiers, list-OR, dict-AND,
  and an `and`/`or`/`not`/`()` `condition` string evaluated by a small,
  safe AST walker (never `eval()`). Four rules ship in `detections/sigma/`
  covering encoded PowerShell, Office-spawned shells, LSASS credential
  access, and scheduled-task persistence.
- **Custom Python detections** (`app/detections/custom/`) â€” for
  multi-event correlation Sigma's single-event model can't express: brute
  force (N failures â†’ success â†’ optional privileged action), lateral-
  movement fan-out, suspicious outbound C2 ports, DNS DGA entropy,
  impossible-travel (simplified â€” no GeoIP yet, documented as such),
  unusual IAM policy activity, suspicious new-access-key usage, and the
  cloud privilege-escalation chain (AssumeRole â†’ sensitive action) called
  out as one of the platform's strongest identity-security scenarios in
  the project brief.

`app/detections/engine.py::sync_detection_rules` idempotently upserts the
registry into the `detection_rules` table (same pattern as
`app/db/seed.py`'s agent-identity sync), so the DB always reflects exactly
what's loaded in code/YAML with provenance. `run_detections_for_event` is
called synchronously at the end of `ingest_event` (see Â§9 for the queueing
seam this leaves for later) and only invokes detections whose
`relevant_categories` include the event's category. A failing detection
is logged and skipped, not allowed to blind the rest of the engine.
`run_all_detections` re-sweeps a time range for the manual
`POST /api/v1/detections/run` endpoint (`detections.run`, soc_manager/
admin) and for replaying attack-simulation-lab telemetry.

`DetectionRule` (the rule catalog) is intentionally **not**
tenant-scoped â€” every organization runs the same detections. `Detection`
(a firing) **is** tenant-scoped (`TenantScopedMixin`, added in the Phase 4
migration `0658de8e6186`) since it's derived from one organization's
events.

### 8.4 Alerts & risk scoring (Phase 5)

Full formula, rationale, and the two bugs this phase caught and fixed:
[`docs/RISK_SCORING.md`](RISK_SCORING.md). Summary:

`app/services/risk_scoring.py` computes a 0-100 risk score as a small,
fully-documented, pure-function weighted sum â€” a Detection's
`base_risk_score`, plus an asset-criticality adjustment keyed off
`Host.criticality` (-5 to +20), plus a +15 "repeat offender" bonus when
the same asset already has an open alert from a *different* detection
rule within 24 hours. Every weight is a named constant with a one-line
justification; nothing about the score is opaque. A deterministic
threshold table maps the score to a `Severity`.

`app/services/alerting.py::generate_alerts_for_detections` turns fired
Detections into Alerts, called synchronously right after detection
execution (both on the ingest path and from the manual sweep endpoint).
To avoid alert-fatigue-by-flooding, a rule re-firing against the same
asset within a 30-minute window **reinforces** the existing open alert
(merges evidence, raises the score if warranted) instead of creating a
duplicate row â€” standard SIEM dedup behavior.

`GET/PATCH /api/v1/alerts` (`alerts.read`/`alerts.update`, both already
part of the Phase 2 RBAC matrix â€” no new permissions needed) let an
analyst triage: filter/search, update status/severity/assignment, and
append notes, all audit-logged with a before/after diff. Alert status is
ordinary triage bookkeeping, explicitly *not* the human-in-the-loop
approval state machine â€” that guarantee lives entirely in `ResponseAction`
(Phase 2) and nothing in this phase touches it.

Two real bugs were caught and fixed while building this: `Detection.fired_at`
was using wall-clock time instead of the underlying event's timestamp
(would have broken both historical-replay accuracy and this phase's
own dedup/repeat-offender time windows), and `Host.hostname` had a
globally-unique index instead of being scoped to `organization_id` (would
have prevented two different tenants from ever both having a host named
e.g. "WIN-01"). Both are detailed with their fixing migrations/commits in
`docs/RISK_SCORING.md` Â§3-4.

### 8.5 MITRE ATT&CK catalog & coverage matrix (Phase 6)

Full dataset scope, the single-tactic-per-technique simplification, and
the API surface: [`docs/MITRE_ATTACK.md`](MITRE_ATTACK.md). Summary:

`app/mitre/data.py` seeds a **curated** subset of the Enterprise ATT&CK
matrix â€” all 14 real tactics (`TA0043`â€¦`TA0040`, in ATT&CK's own
`matrix_order`) and 49 techniques/sub-techniques â€” rather than importing
the full ~10MB STIX bundle. The curated set is verified, by test, to be a
superset of every technique ID any shipped detection references, the same
kind of explicit, documented scope reduction as the self-written Sigma
engine in Â§8.3. `app/mitre/seed.py::sync_mitre_catalog` idempotently
upserts tactics and techniques by natural key (`tactic_id`/`technique_id`)
in two passes â€” techniques first, then sub-technique
`parent_technique_id` resolution â€” so declaration order in `data.py`
never has to guarantee a parent appears before its children.

Detection-rule-to-technique tagging exists in two forms that are kept in
sync rather than one replacing the other: the cheap JSON list
`DetectionRule.mitre_technique_ids` (present since Phase 1/4, used for
cheap reads with no join) and a proper relational many-to-many,
`DetectionRule.mitre_techniques` via the `detection_rule_mitre_techniques`
join table (new in Phase 6, enables real queries like "every rule that
covers Credential Access"). `app/mitre/seed.py::link_detection_rules_to_techniques`
resolves the JSON IDs against the seeded catalog and populates the
relational side; a rule referencing an ID outside the curated set is
logged as a warning, not a hard failure â€” verified empty against the real
rule set by test.

Every fired detection's alert (`app/services/alerting.py`) now carries
the same relational tags on `Alert.mitre_techniques`, populated from the
firing rule and merged (not overwritten) when an alert is reinforced by a
re-firing rule â€” so `GET /api/v1/alerts` can answer "show me everything
tagged Defense Evasion" via a join instead of string-matching the JSON
evidence blob.

`GET /api/v1/mitre/{tactics,techniques,matrix}` and
`GET /api/v1/mitre/techniques/{technique_id}/coverage` (all gated by a
new `mitre.read` permission, granted to every role â€” this is shared
reference data, not tenant data, and isn't scoped by `scoped_query`) serve
the tactic list with per-tactic technique/coverage counts, filterable
technique search (`tactic_id`, `covered_only`, free-text `q`), per-
technique linked-rule lookup, and a full matrix shape (tactic columns â†’
technique cells, each flagging `covered`/`detection_rule_ids`/
`is_subtechnique`/`parent_technique_id`) â€” the exact data contract the
Phase 12 dashboard's coverage-matrix view will render against.

### 8.6 Threat hunting (Phase 7)

Full design, the built-in hunt library, and the API surface:
[`docs/THREAT_HUNTING.md`](THREAT_HUNTING.md). Summary:

A `HuntQuery` is the same Sigma-shaped selection/condition dict as a
Sigma detection's `detection:` block (named selections + a `condition`
string), evaluated on demand against a bounded historical time range
instead of registered as a persistent auto-firing `DetectionRule`. This
is the deliberate line between detection engineering (Â§8.3) and threat
hunting: a detection rule fires automatically on every future matching
event; a hunt query is a hypothesis a human (or, later, the Phase 8
`threat_hunt` agent type) tests against history on demand, and can be
promoted into a real `DetectionRule` once proven precise enough to run
unattended. `app/hunting/engine.py::run_hunt` evaluates both through the
exact same safe, no-`eval()` matcher
(`app/detections/sigma_engine/matcher.py::evaluate_detection_dict`) â€”
one tested boolean-matching implementation, reused rather than
duplicated.

Same two-tier ownership as `DetectionRule`: built-in library queries
(`app/hunting/builtin_queries.py`, 6 queries seeded via
`app/hunting/seed.py::sync_builtin_hunt_queries`, `organization_id IS
NULL`) are runnable by every organization; analyst-authored custom
queries are scoped to their own org. Every run â€” saved, ad hoc, or an
IOC-value pivot (`POST /hunting/ioc-search`) â€” persists a
`HuntExecution` with a **frozen** `query_definition_snapshot` (so editing
or deleting the saved query later never changes what a past run is
recorded as having searched for) and explicit truncation bookkeeping:
`MAX_EVENTS_SCANNED`/`MAX_HUNT_RANGE_DAYS` bound the scan,
`MAX_MATCHES_RETURNED` bounds what's persisted, and `truncated_scan`/
`truncated_results` flags mean a partial answer is never presented as a
complete one â€” `matched_event_count` always reflects the true total
regardless of what was actually stored.

`GET/POST/PATCH/DELETE /api/v1/hunting/queries`, the three run endpoints
(`.../{id}/run`, `/hunting/run` for ad hoc, `/hunting/ioc-search`), and
`GET /hunting/executions[/{id}[/events]]` are gated by three new
permissions â€” `threat_hunting.read` (browse the library and past runs,
granted to every role including `viewer`), `threat_hunting.write`
(create/edit/delete custom queries), and `threat_hunting.execute`
(actually run a scan) â€” the last of which was already part of the
original Phase 2 permission list, ahead of Phase 7 implementing what it
gates.

### 8.7 The agentic AI SOC Analyst (Phase 8)

Full design â€” the orchestrator loop, the provider abstraction, the
evidence-citation gate, and the multi-agent handoff mechanics â€” is in
[`docs/AI_ANALYST.md`](AI_ANALYST.md). Summary:

Phase 1/2 had already built every piece of the *enforcement* boundary this
phase needed â€” the agent identity model, the tool registry, the
tool-permission gateway, and the `AIInvestigation`/`AgentStep`/
`AgentEvidence`/`SOCBlueprint`/`ResponseAction` tables â€” specifically so
Phase 8's job would be narrower than it looks: build the orchestration
*loop* and the provider abstraction on top of already-solid foundations.
No new migration was needed.

`app/ai/orchestrator.py::run_investigation` runs three phases per alert,
sharing one `AIInvestigation` as context rather than having agents talk to
each other directly: **Triage** (a small `TriageDecision` that can
short-circuit the whole investigation if the alert isn't worth the
expense), **Investigation** (the full evidence-cited
`AIInvestigationResult`, optionally seeded with a matching `SOCBlueprint`'s
suggested checklist), and **handoffs** (one `Threat Hunt Agent` step if a
MITRE technique was identified, one `Response Agent` step per recommended
containment action â€” the latter *files* a pending `ResponseAction`, it
never executes one). Every phase transition and tool call is persisted as
an `AgentStep` under one monotonically increasing `step_number`, so the
full trace â€” across all three phases â€” reads as a single ordered,
replayable timeline (`GET /api/v1/ai/investigations/{id}/steps`).

`app/ai/providers/` implements the `LLMProvider` interface two ways: a
`MockProvider` (the default â€” deterministic, offline-safe, and exercised
by the entire test suite) and an `OpenAICompatibleProvider` (real
`httpx`-based OpenAI-compatible chat completions with function-calling,
selected via `AI_PROVIDER=openai_compatible` and never exercised in CI).
Both implement the exact same interface, so the orchestrator, the
tool-permission gateway, and the evidence validator are all proven against
the real seam a production LLM would use â€” not a special-cased shortcut.

The "never fabricate evidence" rule is enforced computationally, not just
by prompting: `app/ai/orchestrator.py::_validate_investigation_result`
rejects any result whose `observed_evidence[].source_event_id` either (a)
was never actually retrieved via a `search_events` tool call this session,
or (b) doesn't resolve to a real `Event` row in the organization's data.
A rejected result is persisted as a `conclude_rejected` step (never
silently dropped) and the provider gets one corrective retry, bounded by
the same `AI_MAX_TOOL_ITERATIONS` budget as ordinary tool calls â€” if it
never produces a valid, grounded result, the investigation ends `FAILED`
with the rejection reason as its `error`, and `run_investigation` never
raises out to the API layer.

New permission: `ai.read` (view investigation results and their full
agent-step trace, granted to every role including `viewer`) alongside the
pre-existing `ai.investigate` (trigger an investigation, granted from
`threat_hunter` up).

### 8.8 Incident response (Phase 9)

The Incident Engine in Â§3's diagram, filled in. Phase 1 created the four
incident tables and Phase 2 used `incidents` as the concrete resource its
RBAC/IDOR tests exercised; Phase 9 turns that stub into a real case-
management layer. Full detail in `docs/INCIDENT_RESPONSE.md`.

**The lifecycle is a state machine.**
`app/services/incidents.py::INCIDENT_TRANSITIONS` is the whole graph over
`IncidentStatus` (`new â†’ triaged â†’ investigating â†’ contained â†’
eradicated â†’ recovered â†’ closed`), and `transition_incident_status` is the
only function in the codebase that writes `Incident.status`. Illegal
transitions return `409` naming what *is* allowed from the current state.
Two edge shapes are deliberate: `closed` is reachable from everywhere
(deciding at any point that a case is a false positive is normal work),
and backward edges exist where reality has them (`contained â†’
investigating` when new scope surfaces, `eradicated â†’ contained` when an
eradication regresses) â€” but `new â†’ contained` is refused, because you
cannot have contained something you have not scoped.

**Closing requires a verdict.** `closure_classification` (`true_positive`
/ `false_positive` / `benign_true_positive` / `duplicate`) is mandatory on
the transition to `closed`. This is what makes the detection engine's
precision measurable at all; a case file that doesn't record what it
turned out to be is an abandoned case, not a closed one.

**Lifecycle timestamps are derived, never supplied.** `triaged_at`,
`contained_at`, and `closed_at` are stamped by the service at the moment
the transition happens and appear on no request schema â€” an IR metric an
analyst can type in by hand is not a metric. Each is stamped on *first*
entry only, so a case that re-enters containment after a regression keeps
its original time-to-first-containment. `detected_at` is the exception to
"now": it is the earliest *evidence* timestamp across the linked alerts,
so time-to-triage measures the SOC rather than the paperwork. All three
durations in `GET /incidents/{id}/metrics` are measured from it.

**The timeline is append-only and has no write route.** Every status
change, assignment, note, task, alert link, and response-action decision
is written by `app/services/incident_timeline.py` from inside the service
function that performed it, with a server-generated timestamp and actor.
`GET /incidents/{id}/timeline` exists; there is deliberately no
POST/PATCH/DELETE companion, so the case file cannot be back-dated,
re-attributed, or edited after the fact by whoever holds the incident.
That module is separate from `app/services/incidents.py` specifically so
the response-action state machine can write to it without an import cycle.

**Alert linkage drives ATT&CK tagging, not the other way round.**
Promoting alerts into an incident derives its severity from the highest
linked alert and unions their techniques into `incident_mitre_techniques`.
Tags are recomputed wholesale on every link/unlink, which is safe
precisely because there is no way to tag an incident by hand â€” the linked
alerts are the sole source of truth. Linking an alert deliberately does
*not* raise an incident's severity: an analyst who set MEDIUM after
looking at the case has made a judgement, and the escalation is surfaced
on the timeline (`exceeds_incident_severity`) rather than silently
overwriting it.

**Nothing about incident response widens what can execute.** An incident
reaching `contained` is a human recording that containment happened; no
code path leads from a status transition to
`execute_response_action`. Containment still goes through the Phase 2
`pending â†’ approved â†’ executed` machine, gated on a human holding
`response.approve`. Phase 9 only makes those actions *visible* on the
case file, by mirroring each transition onto the timeline. One real gap
was closed here: `ResponseAction.incident_id` had been accepted unchecked
since Phase 2, harmless only while nothing read it â€” now that it is a
write target, it is validated against the requester's own organization.

**Case numbering is per tenant.** `incidents.incident_number` is
sequential within an organization and rendered `INC-000042`. Two tenants
both having an `INC-000001` is correct; a global counter would let one
tenant infer another's case volume. Allocation is `max + 1` guarded by a
`(organization_id, incident_number)` unique constraint with a bounded
retry â€” the correctness comes from the database, not from the read. A
Postgres sequence cannot be used because the numbering restarts per
tenant.

**Response Agent growth.** Â§4.2 promised this agent
`check_related_incidents` in Phase 9, and it now has it: a `read_only`
tool answering "is this host or user already part of an open case?", so
the agent does not propose isolating a host a human isolated forty
minutes ago. It matches through the incident's *linked alerts* rather
than by string-searching titles, and it is granted to the Response Agent
alone. No incident-mutating tool exists in `TOOL_REGISTRY`: agents gain
visibility of the case file, never authorship of it.

**AI investigation â†’ incident.** `POST /incidents/from-investigation`
turns a completed investigation into a case file, and re-applies Phase
8's never-fabricate rule at a second boundary. The orchestrator already
validated every citation when it accepted the result, but a stored result
is just data by the time it reaches promotion â€” so each
`source_event_id` is re-resolved against the database, and any that no
longer resolves is *counted and reported back in the response*
(`evidence_rejected` / `rejected_details`) rather than silently dropped
or written as though it were corroborated. Requires `ai.read` on top of
`incidents.create`, so a role that cannot see investigation output cannot
launder it into an incident it can see.

No new permissions were needed: `incidents.read` / `.create` / `.update` /
`.assign` already existed. Reopening a closed case is gated on
`incidents.assign` (SOC Manager and up) rather than `incidents.update` â€”
closing is line-analyst work, but overturning a recorded verdict the
false-positive metrics are computed from is a supervisory act.

### 8.9 Threat intelligence enrichment (Phase 10)

Provider-agnostic IOC enrichment, built on the same shape as the Phase 8
LLM abstraction. Full detail in `docs/THREAT_INTEL.md`.

**The rule the whole phase is built around: an indicator nobody has
scored is `unknown`, never `clean`.** Collapsing "no provider has an
opinion" into "checked, it's fine" is the threat-intelligence equivalent
of fabricating evidence â€” a reassuring answer manufactured out of
absent data, which an analyst will then close a real incident on.
`ProviderResult.failure()` returns `unknown` with zero confidence, never
`clean`.

`LocalFeedProvider` is always in the chain and needs no network or key;
AbuseIPDB, VirusTotal and OTX join it when `THREAT_INTEL_MODE=live` and
their specific key is set. **Every provider is contractually
non-raising** â€” a timeout or rate limit becomes a recorded
`lookup_failed` result, because enrichment is called from
ingestion-adjacent paths and from an agent tool, where an outage must
degrade the answer rather than take down the request.

Aggregation takes the **worst confident verdict**, deliberately not a
majority vote: three feeds with no data and one confirmed C2 match is
"malicious", not "mostly clean". Verdicts expire (24h; failures 15m)
because a verdict is a point-in-time observation, and `from_cache` is
part of the API response so an analyst knows whether they are acting on
a fresh answer. Cache bypass costs a shared quota, so it needs
`threat_intel.manage` rather than `.lookup`.

The bundled feed is entirely synthetic â€” RFC 5737 addresses and RFC 2606
domains only â€” so a committed file never labels real infrastructure as
malicious. That collided with `ipaddress.is_private`, which reports the
documentation ranges as private; `app/threat_intel/addressing.py` is the
single shared resolution, used by both the extractor and the provider so
they cannot disagree.

New permission: `threat_intel.manage` (SOC Analyst and up). New table
relationship: `incident_iocs`, completing the incident case file's
observables that Phase 9 deferred.

### 8.10 Cloud / IAM security and attack paths (Phase 11)

The Cloud/IAM box in Â§3's diagram, filled in. Full detail in
`docs/CLOUD_IAM.md`.

**It reconstructs what was observed, not what was possible.** A real
attack-path tool answers "who *could* reach this resource" by evaluating
IAM policy; this answers "who *did* what, in what order" by walking
observed CloudTrail activity. The second is what telemetry can honestly
support, and the distinction is stated in the graph's own `explanation`
text rather than only here.

`cloud_events` is a **projection alongside** the generic `events` row,
not a replacement: identity-chain fields (`actor_arn`,
`assumed_role_arn`, `request_parameters`) have nowhere to live in the
flat schema, and `cloud_events.event_id` always points back at the
originating evidence. `cloud_identities` are derived from observed
activity, never imported â€” which is honest about what the platform can
see, and is why `is_privileged` is a naming heuristic that the agent tool
returns under the key `is_privileged_heuristic` so a model cannot report
it as policy fact.

**A tenancy trap worth naming.** `CloudEvent` has no `organization_id`;
scoping on `account_id` would leak the moment two organizations monitor
the same AWS account â€” a managed-service provider's normal shape. The
boundary is a join through `events.organization_id`.
`IAMAttackPath`, by contrast, gained a real tenant column, because a path
can legitimately have neither an alert nor an incident attached.

The walk is bounded (`MAX_DEPTH` 6, 25 actions per identity), terminates
on cyclic role assumption, and **declares truncation** in its
explanation â€” the same discipline as Phase 7's hunts. Every edge carries
the `cloud_event_id` it came from, so no rendered node or edge is an
inference without a citable row.

Three new `read_only` tools â€” `get_cloud_identity`,
`get_role_assumptions`, `search_cloud_events` â€” exactly the growth Â§4.2
promised the Cloud/IAM Agent, whose ceiling stays `read_only`.

### 8.11 SOC dashboard and UI (Phase 12)

Fifteen real routes over the whole platform; `ComingSoon` is gone. Full
detail in `docs/DASHBOARD.md`.

`GET /api/v1/dashboard/overview` returns the SOC picture in **one round
trip** of tenant-scoped aggregates. Having the page fire eight list calls
and count rows client-side would produce page-size lies ("50 alerts"
because that is the limit) and compute security metrics somewhere a user
can tamper with.

**`null` is not `0`.** A mean-time metric with no closed incidents is
`null` all the way to the pixel, because "0s mean time to contain" reads
as flawless performance when it means nothing was contained.

The access token lives in `sessionStorage`; the refresh token stays an
HttpOnly cookie JavaScript never reads. `AuthGate` and the
permission-filtered sidebar are **rendering decisions, not access
control** â€” every route is re-authorized server-side against live role
state, and the code says so where a later contributor would otherwise
mistake client routing for a boundary.

The UI's main job beyond rendering is not flattening the platform's
honesty: hunt truncation, per-claim evidence citations, `requires
approval` badges, AI-vs-analyst note provenance, the cloud
`privileged?` caveat, and the standing note that response execution is
simulated all surface in the interface.

### 8.12 Security testing (Phase 13)

`backend/tests/test_security.py` â€” 67 adversarial tests organised by
**attacker goal** rather than by module: execute something privileged
without a human; read another tenant's data; escalate within a tenant;
forge or replay authentication; tamper with the record; make the AI
assert something unsupported; abuse input, exhaust resources, find a
secret. Full detail in `docs/SECURITY_TESTING.md`.

Two rules kept it honest. **Every test must be able to fail** â€” where a
control is structural, the test asserts the absence directly, so deleting
the control breaks the test. And **nothing duplicates a feature test** â€”
each attacks an existing boundary from a different actor or entry point.

Notable properties it pins down: cross-tenant and nonexistent reads are
*byte-identical*; a revoked permission takes effect on the very next
request with the same token; role grants are monotonic
(`analyst âŠ† manager âŠ† admin`); a refresh token cannot be presented as an
access token; `requires_approval=False` is a type error; and a hunt
condition cannot execute code.

### 8.13 Attack simulation lab (Phase 14)

Eight scenarios replayed through the **real ingestion path** â€” same
adapters, same synchronous detection sweep, same risk scoring, same
alerting, same cloud projection. Nothing writes a detection or an alert
directly. Full detail in `docs/LAB.md`.

That makes a scenario run an end-to-end test with a UI, and makes a
scenario that *stops* firing a regression signal: `tests/test_lab.py`
asserts every shipped scenario still produces the detections it claims.
Results are honest about partial success â€” ingestion succeeding says
nothing about whether detection worked, so `missing_detections` is
reported per rule rather than a blanket "success".

**A simulation here is synthetic telemetry describing an attack, never an
attack.** Nothing executes, drops a file, or opens a socket, and a test
enforces that intent. Scenario data uses only reserved address ranges and
domains, and every generated event is permanently tagged `simulated:
true` with its scenario id.

Admin-only (`events.ingest`), because a run produces real alerts in the
same queue analysts work from; letting anyone manufacture those would
make the queue untrustworthy as a record of what happened.

### 8.14 Hardening (Phase 15)

`app/core/hardening.py` runs deployment-posture checks **before the first
request**. Full detail in `docs/HARDENING.md`.

**Fail closed in production, warn in development.** A placeholder
`JWT_SECRET_KEY`, `DEBUG=true`, a placeholder database password, or a
wildcard CORS origin each raise `InsecureDeploymentError` and stop the
process under `ENVIRONMENT=production`; in development they log as
findings that *would* be fatal, so a developer can still see the login
page without inventing a 48-byte secret. Everything downstream â€” RBAC,
tenant scoping, the approval machine, the agent gateway â€” depends on
token authenticity, so this is the one control that cannot be optional.

Also in this phase: `Content-Security-Policy: default-src 'none'` on
every response including errors, interactive API docs disabled in
production, and the repository's **first `.gitignore`** â€” Phases 1â€“14
shipped without one while a real `backend/.env` sat on disk, one
`git add .` away from a leaked signing key. A test asserts the file
excludes `.env` while keeping `.env.example`.

`docs/HARDENING.md` Â§8 lists the remaining gaps explicitly â€” simulated
response execution, nullable tenant column, no secret manager, no key
rotation, no MFA/SSO, no CI, no cryptographic audit-log integrity â€”
rather than leaving them to be discovered.

## 9. Why this scales

- **Storage**: `events`/`network_connections` are the highest-volume
  tables and are queried directly via SQLAlchemy today; swapping in
  Elasticsearch/OpenSearch or a columnar store behind a repository
  interface is a natural Phase 13+ hardening step once ingest volume in a
  real deployment justifies it â€” not done prematurely in Phase 3.
- **Ingestion**: adapters in `app/services/ingestion/adapters/` are
  pluggable; adding a new log source means adding one adapter class, not
  touching the pipeline. This is built and tested now (Phase 3), not
  aspirational.
- **Queueing**: detection execution runs synchronously inline with
  ingestion as of Phase 4 â€” deliberately, to keep the system simple to
  reason about and test end-to-end while ingest volume is low. The seam
  to move it onto a queued worker (Celery/Redis, already scaffolded as a
  profile-gated service in `docker-compose.yml`) is exactly one call site
  (`ingest_event`'s call to `run_detections_for_event`); agent
  investigations (Phase 8) are expected to need that seam sooner, being
  much more latency-heavy per unit of work. This is also the natural spot
  for swapping in Kafka later.
- **AI provider**: swapping models/vendors is an env var change.
- **Threat intel**: providers implement one `ThreatIntelProvider`
  interface; add a class, register it, done.

## 10. Non-goals / explicit boundaries

- SOC-AI does not attack or scan systems it doesn't own; the lab
  (`lab/simulations/`) only generates *synthetic telemetry* that looks like
  an attack happened â€” it does not perform real exploitation.
- The platform does not auto-remediate. Every `privileged_action` requires
  human approval, by design, regardless of AI confidence.
