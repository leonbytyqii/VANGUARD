# Threat Hunting (Phase 7)

## 1. Detection engineering vs. threat hunting — the line this phase draws

Phase 4 built the always-on detection engine: a `DetectionRule` fires
automatically on every future matching event, forever, at whatever
precision it was written with. That's exactly wrong for testing a new
idea — "I wonder if anyone's been running LOLBins against user-writable
temp directories" isn't precise enough to alert on unattended, but it's
absolutely worth running against the last week of history to find out.

Phase 7 is that second workflow: a `HuntQuery` is a hypothesis, evaluated
on demand against a bounded historical time range, reviewed by a human
(or, once Phase 8 lands, the `threat_hunt` agent type already reserved in
`app/models/enums.py::AgentType`). A hunt that turns out to be precise
enough to run unattended is promoted into a real `DetectionRule` — a
manual step today (copy the query into a Sigma YAML file or custom Python
detection), but the two share the same underlying selection/condition
shape on purpose, so that promotion is a translation, not a rewrite.

## 2. One matcher, two consumers

`HuntQuery.query_definition` is byte-for-byte the same shape as a Sigma
rule's `detection:` block: named selections (each a dict of
`Field|modifier: value` pairs, dict-AND within a selection, list-OR
within a value) plus a `condition` string combining selection names with
`and`/`or`/`not`/`()`.

Rather than write a second matcher, `app/detections/sigma_engine/matcher.py`
was refactored to extract `evaluate_detection_dict(event, detection)` —
the same field-mapping and safe-AST condition logic `match_event()`
already used for Sigma rules, now callable directly against any
Sigma-shaped dict. `app/hunting/engine.py::run_hunt` calls this exact
function per `Event` row in the scanned time range. Two consequences:

- **No `eval()`, anywhere, for either engine.** The condition string is
  parsed with `ast` and only `BoolOp`/`UnaryOp(Not)`/`Name`/`Expression`
  nodes are permitted — a hunt query built from a request body (an
  analyst-authored custom query, or an ad hoc unsaved one) gets the exact
  same safety guarantee as a Sigma YAML file loaded from disk.
  `app/hunting/engine.py::validate_query_definition` dry-runs this
  AST-safety check (with every selection forced to `False`) before a
  query is ever saved or executed, so a malformed or unsafe condition
  fails as a 422 at request time, not mid-scan.
- **One tested implementation, one set of edge cases.** A bug fix or a
  new field mapping in `matcher.py` benefits both the detection engine
  and the hunting engine simultaneously, and `tests/test_detections.py`
  and `tests/test_hunting.py` both exercise the same underlying function.

## 3. The built-in hunt library

`app/hunting/builtin_queries.py` ships 6 curated hunts, seeded into
`hunt_queries` rows with `organization_id IS NULL, is_builtin=True` by
`app/hunting/seed.py::sync_builtin_hunt_queries` (idempotent upsert by
`name`, same pattern as `app/detections/engine.py::sync_detection_rules`
and `app/mitre/seed.py::sync_mitre_catalog`). Several deliberately cover
the same *topic* as an existing Phase 4 detection but cast a **wider**
net — a detection has to be precise enough to alert unattended; a hunt is
reviewed by a human, so higher recall / lower precision is the right
tradeoff, and it's a concrete illustration of the hunt-then-promote
workflow §1 describes:

| Hunt | Wider than | MITRE tags |
|---|---|---|
| Broad PowerShell Obfuscation/Bypass Indicators | `sigma_suspicious_powershell_encoded` (only `-EncodedCommand` variants) | T1059.001, T1027 |
| Living-off-the-Land Binary (LOLBin) Proxy Execution | — (no equivalent detection) | *(none — see below)* |
| Remote Administration Protocol Connections | `custom_lateral_movement_fanout` (only a 3+-host fan-out) | T1021, T1021.001/.002/.006 |
| Broad IAM Sensitive / Reconnaissance Actions | `custom_unusual_iam_activity` (only policy/permission modification) | T1098.001, T1550.001, T1078.004 |
| DNS Queries to Suspicious TLDs | `custom_dns_anomaly_dga` (entropy-based, misses low-entropy-but-suspicious domains) | T1568.002, T1071.004 |
| Process Execution from User-Writable Temp Paths | — (no equivalent detection) | T1204.002, T1105 |

**Honest MITRE tagging, even for the platform's own metadata:** the
LOLBin hunt is deliberately left with `mitre_technique_ids: []`. The real
ATT&CK technique for this pattern (T1218, Signed Binary Proxy Execution)
isn't in the curated 49-technique catalog (`app/mitre/data.py`, see
`docs/MITRE_ATTACK.md`), and forcing it onto a loosely-related cataloged
ID would be a fabricated mapping. This is the same "never assert what
isn't actually true" discipline that governs AI-generated evidence
(docs/ARCHITECTURE.md §6) applied to the platform's own tagging — an
untagged hunt is honest; a mistagged one isn't.
`tests/test_hunting.py::test_every_builtin_hunt_mitre_id_is_in_the_seeded_catalog`
enforces that every tag actually used is real, the same invariant Phase 6
enforces for detection rules.

## 4. Execution engine: bounds and evidence integrity

`app/hunting/engine.py::run_hunt` is deliberately synchronous — same
"simple now, documented seam to a queue/streaming engine later" posture
as detection execution (Phase 4) and alert generation (Phase 5) — but
explicitly bounded in three ways, because unlike a single triggering
event, a hunt is a request to scan a whole time range:

- `MAX_HUNT_RANGE_DAYS` (30) caps how wide a window can be requested at
  all — rejected before any query touches the database.
- `MAX_EVENTS_SCANNED` (20,000) caps how many `Event` rows are pulled
  into Python for matching; a window with more events than that stops
  the scan and sets `truncated_scan=True` on the resulting
  `HuntExecution` — a partial scan is never presented as if it were
  complete.
- `MAX_MATCHES_RETURNED` (500) caps how many matched event IDs are
  persisted/returned per run. `matched_event_count` is computed from the
  **full** match set before truncation and always reflects the true
  total, even when `matched_event_ids` (and `truncated_results=True`)
  reflects only the first 500 — the count is never quietly wrong just
  because the detail list was capped.

Every run — successful, truncated, or failed mid-scan (an unexpected
exception is caught and recorded as `status="failed"` with the error
message, never allowed to 500 past leaving an audit trail) — persists a
`HuntExecution` row with a **frozen** `query_definition_snapshot`: the
exact selection/condition dict that ran, independent of whatever the
saved `HuntQuery` looks like later if it's edited or deleted. This is the
same evidence-integrity reasoning that governs `Detection.matched_event_ids`
(Phase 4): a record of "what was searched for and what it found" must
stay independently re-checkable even after the definition that produced
it changes underneath it.

## 5. API surface

All endpoints live under `/api/v1/hunting`
(`backend/app/api/v1/hunting.py`), gated by three permissions added this
phase — `threat_hunting.read`, `threat_hunting.write`, and the
pre-existing `threat_hunting.execute` (part of the original Phase 2
permission list, ahead of this phase actually implementing what it
gates) — see `app/core/permissions.py`.

- **`GET/POST /hunting/queries`**, **`GET/PATCH/DELETE
  /hunting/queries/{id}`** — browse the union of built-in library queries
  and the caller's own org's custom queries (`_visible_hunt_queries_query`
  deliberately doesn't use `scoped_query`, which would hide the
  organization-independent library entirely — the same reason
  `app/api/v1/mitre.py` and the detection-rule-catalog endpoint don't use
  it either); create/edit/delete are restricted to an org's own custom
  queries — a built-in query 403s on edit/delete attempts, and another
  org's custom query 404s (not 403) on any operation, per the platform's
  standard IDOR-prevention posture (docs/SECURITY.md).
- **`POST /hunting/queries/{id}/run`** — run a saved query; omitting the
  time range defaults to `now - default_lookback_hours .. now`.
- **`POST /hunting/run`** — execute an unsaved `query_definition`
  directly, never persisted as a `HuntQuery`, only as the resulting
  execution's snapshot — the natural "test it before you save it" entry
  point.
- **`POST /hunting/ioc-search`** — builds a selection dict server-side
  from an IOC type + value (ip/domain/url/file_hash, reusing the existing
  Phase 1 `IOC` table's vocabulary) and runs it, so a caller pivoting off
  an indicator doesn't have to hand-write field/modifier syntax for
  "has this indicator shown up anywhere?".
- **`GET /hunting/executions[/{id}[/events]]`** — tenant-scoped list/get
  of past runs, plus resolving a run's `matched_event_ids` back into full
  `Event` rows so an analyst can actually review the hits, not just their
  IDs.

## 6. What's explicitly deferred

- **Relational MITRE tagging for hunt queries** — `HuntQuery.mitre_technique_ids`
  is JSON-only, not a many-to-many join like `DetectionRule.mitre_techniques`
  (Phase 6). Nothing yet needs to query "every hunt covering technique X"
  via a join the way the coverage-matrix API needs it for detections;
  adding the M2M later is schema-additive, not a rewrite, if that need
  appears.
- **Frontend rendering** — `frontend/app/hunting/page.tsx` (if scaffolded)
  still renders the Phase 1 `ComingSoon` placeholder. The data model and
  API contract this doc describes are real and tested; wiring a hunt
  builder/results UI is Phase 12 per the project's established
  frontend-last-per-phase division of labor.
- **Automatic promotion to a DetectionRule** — turning a proven hunt query
  into a permanent Sigma/custom detection is a manual step today (the two
  share a selection/condition shape by design, making the translation
  straightforward, but nothing automates it yet).
