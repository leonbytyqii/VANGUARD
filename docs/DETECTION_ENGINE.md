# Detection Engine (Phase 4)

## 1. Goal and shared contract

Two very different kinds of detection logic need to coexist:

- **Single-event pattern matching** — "this one process-creation event's
  command line looks like an encoded PowerShell payload." Sigma is the
  industry-standard way to express this, and SOC-AI ships a rule engine
  for it.
- **Multi-event correlation** — "five failed logins, then a success, then
  a sudo command, all for the same user within 15 minutes." Sigma's
  single-event model can't express this without falling back to its
  aggregation/`near` extensions, which most Sigma backends implement
  inconsistently. SOC-AI expresses these as small, explicit Python
  classes instead.

Both are forced through the same interface
(`backend/app/detections/base.py::DetectionDefinition`) so the engine
(`backend/app/detections/engine.py`) never has to know which kind of
detection it's calling:

```python
class DetectionDefinition(Protocol):
    rule_id: str
    title: str
    description: str
    engine: str                      # "sigma" | "custom_python" | "behavioral_correlation"
    level: str                       # "low" | "medium" | "high" | "critical"
    base_risk_score: int
    mitre_technique_ids: list[str]
    relevant_categories: set[str]    # Event.category values this detection can ever match

    def run(self, db, *, organization_id, triggering_event) -> list[DetectionMatch]: ...
```

A `DetectionMatch` **must** cite the `Event` row(s) that produced it
(`matched_event_ids`) and carries a structured `evidence_summary` dict —
never free text asserting an unverified claim. This mirrors the same
evidence-integrity rule the AI investigation layer will be held to in
Phase 8 (`docs/ARCHITECTURE.md` §4.4): a finding without a pointer back to
re-checkable evidence isn't trusted anywhere in this system, whether it
came from a human-written rule or an LLM.

## 2. Sigma engine — and why it isn't pySigma

`backend/app/detections/sigma_engine/` parses a deliberately-scoped subset
of Sigma YAML with plain PyYAML, not pySigma.

**Why not pySigma:** pySigma's job is *compiling* a Sigma rule into a
target query language (Elasticsearch DSL, Splunk SPL, a specific SIEM
backend's syntax) via its pipeline/backend abstraction. SOC-AI has no such
backend — events live in Postgres and rules are evaluated in-process
against `Event` ORM objects. Pulling in pySigma's backend-conversion
machinery here would mean fighting an API built for a problem this system
doesn't have, for a payoff (spec-complete Sigma support) that isn't
needed yet. Writing ~150 lines of loader + matcher gives full control and
zero risk of an API mismatch, at the explicit cost of not supporting the
full Sigma spec.

**What's supported:**

- `logsource.category` → mapped to the `Event.category` values that can
  ever satisfy the rule (`sigma_engine/__init__.py::LOGSOURCE_CATEGORY_MAP`),
  so the engine's dispatch table never even calls a rule for an
  irrelevant event category.
- Field selections as a dict: every key must match (`AND`).
- A list value under a field: any element matching is enough (`OR`).
- Modifiers: `|contains`, `|startswith`, `|endswith`, `|re` (regex).
  Equality when no modifier is given. All string comparisons are
  case-insensitive, matching Sigma convention.
- `detection.condition`: an `and`/`or`/`not`/`()` boolean expression over
  named selections, evaluated by walking a **restricted** `ast.parse(...,
  mode="eval")` tree (`sigma_engine/matcher.py::evaluate_condition`). Only
  `BoolOp`, `UnaryOp(Not)`, and `Name` nodes are permitted — anything else
  (a function call, an attribute access, a literal) raises
  `SigmaConditionError`. **This is not `eval()`** — no expression is ever
  executed; the tree is walked and reduced by hand against a
  `{selection_name: bool}` dict. A malicious or malformed `condition`
  string cannot execute code.
- Field mapping: conventional Sigma/Sysmon field names (`Image`,
  `ParentImage`, `CommandLine`, `DestinationIp`, `QueryName`, ...) are
  translated to SOC-AI's normalized `Event` columns
  (`sigma_engine/matcher.py::FIELD_MAP`), so rules can be written in the
  vocabulary the wider Sigma ecosystem already uses.
- `tags: [attack.txxxx, ...]` → parsed into `mitre_technique_ids`.

**What's explicitly out of scope** (and why the custom-Python engine
exists instead): Sigma's `count()`/aggregation conditions, `near`/
timeframe correlation, and `1 of them`/`all of them` shortcuts. Those are
exactly the multi-event cases the custom detections below handle with
plain, readable Python instead of a mini query language.

**A path-vs-name normalization note:** real Sysmon `Image` values are
full paths (`C:\Windows\System32\powershell.exe`); SOC-AI's normalized
`Event.process` field deliberately stores just the executable name (see
`app/schemas/event.py`). Rules are still written in the conventional
`Image|endswith: '\powershell.exe'` style (so they read like real-world
Sigma rules an interviewer would recognize) — the matcher strips a
leading `\`/`/` from the expected pattern before comparing, documented
inline in `matcher.py`.

Four rules ship in `detections/sigma/` (repo root, not under `backend/` —
rules are data, not code):

| rule_id | level | what it catches |
|---|---|---|
| `sigma_suspicious_powershell_encoded` | high | PowerShell invoked with `-EncodedCommand`/`-enc` |
| `sigma_powershell_spawned_by_office` | high | Word/Excel/PowerPoint/Outlook spawning a shell |
| `sigma_credential_access_lsass` | critical | Command line referencing a dump tool + `lsass` |
| `sigma_persistence_scheduled_task` | medium | `schtasks.exe ... /create` |

## 3. Custom Python detections

`backend/app/detections/custom/` — eight classes, each implementing
`DetectionDefinition` directly. `_helpers.py::events_in_window` is the
one shared query helper (tenant-scoped, optionally host/user-scoped,
bounded time window) every correlation detection is built on.

| rule_id | pattern | honest limitation, stated |
|---|---|---|
| `custom_brute_force_login` | ≥5 failed logins → success (→ optional sudo/new-session escalates risk_score to 95) within 15 min, same user+host | — |
| `custom_lateral_movement_fanout` | same src IP → ≥3 distinct dst hosts on 445/3389/5985/5986 within 10 min | doesn't weigh process ancestry (psexec.exe/wmic.exe) yet |
| `custom_suspicious_outbound_port` | connection to a C2-framework-default port (4444, 1337, 31337, 6667, ...) | port list only — malware using 443 to blend in isn't caught; that's TI/IOC matching's job (Phase 10) |
| `custom_dns_anomaly_dga` | Shannon entropy ≥3.6 on a domain label ≥12 chars | entropy-thresholding is a known approximation — misses dictionary-based DGAs, flags some legitimate random CDN subdomains |
| `custom_impossible_travel_proxy` | same user, two different source IPs, successful logins within 30 min | **no GeoIP yet** — this is a proxy for real impossible-travel (distance/time/speed) analysis, not the real thing; will false-positive on VPN/network switches |
| `custom_unusual_iam_activity` | any IAM policy/permission-modification API call | fires on every occurrence by design — low base rate + high cost of missing one |
| `custom_suspicious_api_key_usage` | `CreateAccessKey` → usage from a different source IP within 60 min | — |
| `custom_cloud_privilege_escalation_chain` | `AssumeRole` → a sensitive action (policy/logging/bucket-policy change) within 15 min, same actor | the observable signature of Compromised Identity → AssumeRole → Excessive Permission → Sensitive Action called out in the project brief; full attack-path graph reconstruction is Phase 11 |

Every "heuristic" limitation above is stated in the module's own
docstring, not just here — an interviewer question like "why entropy
3.6?" or "doesn't this false-positive on VPN users?" should be answerable
by pointing at the code comment, not by improvising an answer on the
spot.

## 4. Wiring: registry → sync → dispatch

- `app/detections/registry.py::DETECTION_REGISTRY` = every `SigmaDetection`
  loaded from `detections/sigma/*.yml` + every custom detection instance.
  Adding a detection is: drop a YAML file, or add one class + one line
  here. Nothing else changes.
- `app/detections/engine.py::sync_detection_rules(db)` idempotently
  upserts the registry into `detection_rules` (same natural-key-lookup
  pattern as `app/db/seed.py`'s agent-identity sync) — called from
  `seed_all()` on every app start and from the test suite's session-scoped
  baseline fixture, so the DB is always in sync with what's loaded in
  code. A rule an admin has manually disabled (`DetectionRule.enabled =
  False`) stays disabled across a sync — sync only touches
  title/description/engine/level/risk/MITRE-IDs/logsource, never
  `enabled`.
- `run_detections_for_event(db, organization_id, event)` — called
  synchronously at the end of `app/services/ingestion/service.py::ingest_event`.
  Builds a per-category dispatch table once at import time
  (`_DISPATCH_TABLE`) so an event only ever reaches detections whose
  `relevant_categories` include it. One detection raising an exception is
  caught, logged, and skipped — it does not prevent the other detections
  from running against the same event.
- `run_all_detections(db, organization_id, since)` — full sweep over
  `[since, now]`, used by `POST /api/v1/detections/run` (manual trigger,
  `detections.run` permission — soc_manager/admin only) and for replaying
  attack-simulation-lab telemetry after a rule is added or edited.

## 5. API surface

| Endpoint | Permission | Notes |
|---|---|---|
| `GET /api/v1/detections/rules` | `detections.read` | The rule catalog — not tenant-scoped (every org runs the same rules) |
| `GET /api/v1/detections` | `detections.read` | Fired detections, tenant-scoped, filterable by rule/host/user/risk/time |
| `GET /api/v1/detections/{id}` | `detections.read` | 404 (not 403) on cross-tenant access, same IDOR-avoidance rule as every other resource |
| `POST /api/v1/detections/run` | `detections.run` | Manual sweep trigger — soc_manager/admin only |

## 6. Data model

`DetectionRule` (the catalog) is **not** tenant-scoped — it's shared,
org-independent code/config, not tenant data. `Detection` (a firing) **is**
tenant-scoped (`TenantScopedMixin`, added in migration `0658de8e6186` —
missed in the Phase 2 tenant-scoping pass because the detection engine
didn't exist yet to populate the table).

## 7. Testing

`backend/tests/test_detections.py` (29 tests) proves, for every detection:
**known malicious pattern → detection fires** and **benign pattern → no
detection fires** — the master spec's explicit requirement — plus rule-
sync idempotency, RBAC on the read/run endpoints (viewer can read, only
soc_manager/admin can trigger a manual run), and tenant scoping of fired
detections. All 29 run against a real Postgres test database through the
real HTTP ingestion API, not mocked.

## 8. What's deliberately deferred

- **Alert generation from detections + documented risk-scoring formula**
  — Phase 5. `Detection.risk_score` today is just `base_risk_score`
  (or a per-match override, e.g. brute-force-then-privileged-action
  scores 95 instead of 80) — not yet the fuller formula (asset
  criticality, historical false-positive rate, MITRE tactic weighting)
  the project brief calls for.
- **MITRE tactic/technique DB tables** — Phase 6. `mitre_technique_ids`
  is already a JSON list of technique-ID strings on both `DetectionRule`
  and populated from Sigma `tags`/custom detection class attributes; no
  FK relationship to a `mitre_techniques` table exists yet.
- **Queued/async detection execution** — currently synchronous inline
  with ingestion; the seam to move it onto Celery/Redis is documented in
  `docs/ARCHITECTURE.md` §9.
