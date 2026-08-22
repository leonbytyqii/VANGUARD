# Incident Response (Phase 9)

What this phase built, and why each piece is shaped the way it is.

Phase 1 created `incidents`, `incident_tasks`, `incident_notes`, and
`incident_events` as part of the full data model, and Phase 2 used
`incidents` as the concrete, organization-scoped resource its RBAC, IDOR
and tenant-isolation tests exercised against a real table rather than a
synthetic example. What existed before this phase was therefore a table
with a `status` column that any handler could assign to, and three child
tables nothing wrote to. Phase 9 turns that into a case-management layer.

---

## 1. Detection ends where response begins

Phases 3–8 answer *"what happened?"* — ingest, detect, score, hunt,
investigate. None of them answer *"what did we do about it, when, and who
decided?"* That is the incident record, and it is a different kind of
object from an alert:

| | Alert | Incident |
|---|---|---|
| Produced by | the detection engine, automatically | a human (or a promoted AI investigation) deciding this matters |
| Lifespan | seconds to write, then triaged | hours to weeks, worked by shifts |
| Cardinality | thousands | tens |
| Mutability | status/assignment | a running case file with tasks, notes, and a history |
| The question it answers | "did something fire?" | "what is our response, and how is it going?" |

An incident is the unit a SOC is actually measured on: mean time to
triage, mean time to contain, and how many of the cases it opened turned
out to be false positives. Every design decision below follows from
wanting those three numbers to be *trustworthy*.

---

## 2. The lifecycle state machine

`app/services/incidents.py::INCIDENT_TRANSITIONS` is the entire graph, and
`transition_incident_status` is the only function in the codebase that
writes `Incident.status`. This is the same shape as Phase 2's
response-action approval machine, for the same reason: a status column
that any route handler can assign to is a status column that eventually
holds a value no downstream consumer expected.

```
        ┌──────────────────────────────────────────────┐
        │                                              v
new ──> triaged ──> investigating ──> contained ──> eradicated ──> recovered
 │         │              ^               │  ^           │              │
 │         │              └───────────────┘  └───────────┘              │
 │         │                                                            │
 └─────────┴──────────────────> closed <────────────────────────────────┘
                                  │
                                  └──> investigating   (reopen, incidents.assign)
```

States follow the incident-handling phases of **NIST SP 800-61r2**.
Three shapes are deliberate rather than accidental:

- **`closed` is reachable from every state.** Deciding at any point that a
  case is a false positive and closing it is normal SOC work. Forcing it
  to walk the full chain first would mean recording containment,
  eradication and recovery that never happened — corrupting exactly the
  metrics this phase exists to produce.
- **Backward edges exist where reality has them.** `contained →
  investigating` (new scope surfaced) and `eradicated → contained` (the
  eradication regressed) are both real. `recovered → investigating`
  covers the attacker returning through a missed persistence mechanism.
- **Forward jumps that skip evidence are refused.** `new → contained`
  returns `409`: you cannot have contained something you have not yet
  scoped. The error names what *is* legal from the current state, so a
  client does not have to guess:

  ```
  409  Illegal transition 'new' -> 'contained'.
       Allowed from 'new': closed, investigating, triaged.
  ```

### Closing requires a verdict

`closure_classification` is mandatory on the transition to `closed`, and
must be one of `true_positive`, `false_positive`, `benign_true_positive`
(real activity, but authorized — a sanctioned pentest), or `duplicate`.

This is the single most load-bearing "annoying" requirement in the phase.
A closed case that does not record what it turned out to be is an
abandoned case, and without it the detection engine's precision is
unmeasurable — you cannot tune a rule you cannot score. Making it
optional would mean it was populated for the first month and empty
thereafter.

### Reopening is a supervisory act

`closed → investigating` is the only edge out of `closed`, and it is
gated on `incidents.assign` (SOC Manager and up) rather than the
`incidents.update` that governs every other transition. Closing a case is
line-analyst work; overturning a verdict that has already been recorded,
and that the SOC's false-positive rate is computed from, is not.

Reopening clears `closure_classification`, `closure_summary` and
`closed_at` — but the timeline entry written for the transition carries
the previous verdict in `reopened_from_classification`, so *"this was
closed as a false positive and then reopened"* stays answerable from the
case file. Reopening lands in `investigating` rather than restoring the
prior status: a case being looked at again is, by definition, under
investigation.

No new permission was invented for any of this. `incidents.read` /
`.create` / `.update` / `.assign` already existed from Phase 2, and
reusing `incidents.assign` for the one supervisory transition avoided a
permission that would have needed its own migration and role grants for
a single edge.

---

## 3. Metrics you can trust

`GET /incidents/{id}/metrics` returns time-to-triage, time-to-contain,
time-to-close, open duration, and task completion. Three rules make those
numbers mean something.

**Timestamps are derived, never supplied.** `triaged_at`, `contained_at`
and `closed_at` are stamped by the service at the moment the transition
actually happens. They appear on no request schema anywhere in
`app/schemas/incident.py` — deliberately, because an IR metric an analyst
can type in by hand is not a measurement, it is a claim.

**Milestones are stamped on first entry only.** A case that regresses
from `contained` back to `investigating` and is contained again keeps its
original `contained_at`. Time-to-*first*-containment is the number the
SOC is measured on; resetting it on the second pass would let a case look
faster the worse it went.

**Everything is measured from `detected_at`, not `created_at`.** This is
the one field that is not "now": it is the earliest *evidence* timestamp
across the linked alerts — when the platform first had a signal, not when
somebody got round to opening the case. Measuring from case creation
would flatter the SOC by excluding precisely the delay that matters most.
Linking an older alert later moves `detected_at` backwards; it never
moves forwards, because evidence does not become newer.

That last rule has a consequence worth naming: linking an alert whose
evidence predates an already-recorded triage can make a duration
negative. That is legitimate data, but "contained −3 minutes after
detection" is not a number any dashboard should render, so
`_elapsed_seconds` clamps at zero. The timeline still shows the real
ordering. Durations are `null`, never `0`, where the milestone has not
been reached — so an un-triaged case stays visibly distinct from one
triaged instantly.

---

## 4. The timeline is a case file, not a comment thread

Every status change, assignment, note, task action, alert link/unlink,
evidence item and response-action decision is written as an
`IncidentEvent` by `app/services/incident_timeline.py`, from *inside* the
service function that performed the underlying change, with a
server-generated timestamp.

**There is no POST, PATCH, or DELETE route for the timeline.** Not a
permission check — no route at all. `GET /incidents/{id}/timeline` exists
and nothing else does. A caller cannot author an entry, cannot back-date
one, and cannot attribute one to another actor. That is what makes the
timeline usable as an incident-response record: its integrity does not
depend on an authorization check that a later refactor could relax, but
on the absence of a code path. `test_timeline_is_read_only_over_http`
asserts all four verbs return `405`.

`actor` is a **label, not a foreign key** — deliberately. An entry can be
attributed to a human (their email), to an AI agent
(`ai_agent:investigation`), or to the platform itself (`null`, for
entries that are a consequence of a rule rather than of somebody's
action, such as the checklist being seeded). Tying it to `users.id` would
make the second and third unrepresentable.

The module is separate from `app/services/incidents.py` for a structural
reason: the response-action state machine has to *write* to the timeline
while the incident service has to *read* response actions. A
dependency-free timeline module means neither has to import the other.

---

## 5. Alert linkage and ATT&CK derivation

Creating an incident with `alert_ids` derives its severity from the
highest-severity linked alert (so the analyst does not restate a severity
the alerts already carry, which is only an opportunity to get it wrong),
and unions the alerts' techniques into `incident_mitre_techniques`.

Tags are **recomputed wholesale** on every link and unlink rather than
incrementally added. That is only safe because there is no way to tag an
incident with a technique by hand — the linked alerts are the sole source
of truth for the field — and it means unlinking an alert correctly
removes the techniques only that alert contributed.

**Linking an alert does not raise the incident's severity.** This looks
like a missing feature and is a deliberate refusal. An analyst who set a
case to MEDIUM after looking at it has made a judgement; silently
overriding it because a noisy CRITICAL alert got attached would destroy
that judgement invisibly. Instead the timeline entry carries
`exceeds_incident_severity: true`, so the escalation is *surfaced* and
the analyst can act on it or dismiss it.

Cross-tenant linking is refused as `422 Unknown alert id(s): …` rather
than `403`. Confirming that some other organization has an alert with
that id would itself be the cross-tenant leak — same reasoning as
`app/core/scope.py`'s 404-not-403 rule for incidents.

---

## 6. The response checklist

New incidents are seeded with a twelve-item checklist
(`app/incidents/task_templates.py`) structured by NIST SP 800-61r2's
handling phases: Detection & Analysis, Containment, Eradication,
Recovery, Post-Incident. "Preparation", the framework's first phase, is
deliberately absent — it is org-level work done *before* any incident
exists, so it has no place on a specific case's checklist.

Two decisions about it are worth defending:

**These are prompts, not automation.** Every item is something a human
does and then ticks. Nothing in the template triggers a tool call, and in
particular *"Request approval for any required containment actions"* is a
checklist line whose actual execution still goes through the
`pending → approved → executed` machine. The checklist can remind an
analyst to contain a host; it can never contain one.

**The template is fixed, not severity-branched.** An earlier cut varied
the checklist by incident severity, which sounds smarter and is worse: a
case downgraded from HIGH to MEDIUM would silently lose checklist items
an analyst might already be working, and "did we follow the process?"
becomes unanswerable without knowing what the severity was at creation
time. One checklist, always the same, is auditable. Analysts add
case-specific tasks on top of it, and `sort_order` is spaced by 10 so an
added task can be slotted between two template items without renumbering.

Un-ticking a completed task clears `completed_at` and `completed_by_id`
rather than leaving a stale "completed by" on an open task.

---

## 7. Notes and honest provenance

`IncidentNote.is_ai_generated` distinguishes analyst text from AI-authored
narrative. The guarantee is structural, not conventional:

- `IncidentNoteCreateRequest` has **no `is_ai_generated` field**, so a
  client sending one is ignored by the schema, not merely overruled.
- `POST /incidents/{id}/notes` passes `is_ai_generated=False` as a
  hard-coded literal, never a value read from the request.
- The only caller that passes `True` is
  `promote_investigation_to_incident`, an internal service path with no
  HTTP surface of its own.

So no caller can post text that renders in the case file with a
provenance it did not have — in either direction. AI output cannot be
laundered as an analyst's conclusion, and an analyst's note cannot be
disowned as machine-generated.

---

## 8. Response actions on a case — visibility without new power

`ResponseAction.incident_id` has existed since Phase 2. Phase 9 makes it
mean something: each transition of an action attached to an incident
(`requested → approved/rejected → executed`) is mirrored onto that
incident's timeline, and `GET /incidents/{id}/response-actions` lists
them.

**The direction of that arrow is the whole point.** The case file gains
visibility of containment; containment gains nothing from the case file:

- `_mirror_to_incident_timeline` runs *after* the state transition it
  describes has already been decided. It cannot influence that decision.
- Moving an incident to `contained` approves nothing and executes
  nothing. There is no code path from `transition_incident_status` to
  `execute_response_action`. `test_containing_an_incident_executes_nothing`
  asserts the action is still `pending`, with `approved_at` and
  `executed_at` still null, after the case is marked contained.
- Reading a case file is `incidents.read`. Requesting, approving and
  executing all remain on `/api/v1/response/*` behind `response.request`
  / `response.approve`. Nothing about incident response widens what its
  reader can cause to happen.

### A real gap closed here

`create_response_action_request` accepted `incident_id` **unvalidated**
before this phase. That was harmless only while nothing read the field.
The moment it became a write target — an entry appended to that
incident's timeline — an unvalidated id would let a caller write onto
another tenant's case file. It is now resolved within the requester's own
organization and rejected as `422 Unknown incident_id for this
organization` (not `403`, for the usual reason) if it is not.
`test_cannot_attach_a_response_action_to_another_tenants_incident`
asserts both the rejection and that the victim's timeline stayed empty.

---

## 9. `check_related_incidents` — the Response Agent's Phase 9 growth

`docs/ARCHITECTURE.md` §4.2's agent roster promised the Response Agent
this tool "in Phase 9", and it now has it. It answers one question: *is
this host or user already part of an open case?*

It exists to stop a specific, realistic failure mode: the agent proposing
to isolate a host that a human analyst isolated forty minutes ago on an
incident the agent could not see. A duplicate containment request is not
harmless — it costs a second human approval decision and muddies the case
file.

Design notes:

- **`read_only`**, even though it belongs to the one agent whose ceiling
  is `propose_only`. Reading the incident queue is not a proposal.
  Classifying a tool by the agent that happens to own it, rather than by
  what it does, would weaken the effect-ceiling check into a tautology.
- **Matched through linked alerts, not free text.** An incident is
  related to a host because an alert about that host is attached to it.
  String-searching titles and summaries would let an unrelated case that
  merely mentions a hostname in prose masquerade as containment that
  already happened.
- **Closed cases are excluded by default** (`include_closed=False`). A
  case that was closed is not a reason to skip containing a host now.
- **Granted to the Response Agent alone.** Widening it to Triage would
  hand the cheapest, most frequently-run agent a view of the whole
  incident queue for no investigative gain. Four parametrised tests
  assert the other agent types are denied it with reason
  `tool_not_in_agent_allowlist`.
- **Both parameters optional at the signature level.** A call with
  neither returns a structured `{"error": …}` rather than raising,
  because the agent loop only catches `ToolPermissionError` — a
  `TypeError` from a missing keyword would abort the entire
  investigation instead of becoming a tool result the model can correct
  from.

**No incident-mutating tool exists in `TOOL_REGISTRY`.** Agents gain
visibility of the case file in this phase; they never gain authorship of
it. `test_no_incident_mutating_tool_exists_in_the_registry` asserts that
`create_incident`, `close_incident`, `update_incident`,
`add_incident_note` and `assign_incident` are all absent.

---

## 10. AI investigation → incident

`POST /incidents/from-investigation` turns a completed `AIInvestigation`
into a case file: an incident linked to the investigation's alert, with
the AI's summary as an AI-attributed note, its evidence on the timeline,
and any response actions it filed attached to the case (still pending —
attaching an action to an incident approves nothing).

**The Phase 8 never-fabricate rule is re-applied here, at a second
boundary.** The orchestrator already validated every citation when it
accepted the result. This re-validates them against the database anyway,
because the two happen at different moments and *a stored result is just
data by the time it reaches promotion*. Each `source_event_id` is
re-resolved against `events` within the investigation's organization:

- resolves → an `evidence` timeline entry with `event_backed: true`;
- no `source_event_id` at all → recorded, but explicitly flagged
  `event_backed: false`. These are claims grounded in a non-Event source
  (the alert, a host lookup, an IOC enrichment) that the orchestrator
  validated differently, and the case file says so rather than implying
  corroboration it does not have;
- present but does not resolve → **rejected**: not written to the
  timeline, counted in `evidence_rejected`, and itemised with a reason in
  `rejected_details` **in the API response**.

That last point is the design choice, not the check itself. A citation
that did not resolve is exactly the thing this platform refuses to let
pass silently, so the caller is told in the same response what was
dropped and why, rather than it becoming a log line nobody reads.
`test_promotion_rejects_evidence_whose_source_event_no_longer_resolves`
tampers with a stored result to add a citation pointing at a nonexistent
event, then asserts the promotion still succeeds, reports
`evidence_rejected == 1`, and that the fabricated claim is absent from
the case file.

Promotion requires **`ai.read` in addition to `incidents.create`**, so a
role that is not allowed to see AI investigation output cannot launder it
into an incident it *is* allowed to read.

---

## 11. Per-tenant case numbering

`incidents.incident_number` is a per-organization sequential integer,
rendered `INC-000042` by the API. Two tenants both having an `INC-000001`
is correct; a global counter would let one tenant infer another's case
volume from its own reference numbers.

`max(incident_number) + 1` is racy by construction, so the correctness
comes from the database rather than from the read: a unique constraint on
`(organization_id, incident_number)` turns a lost race into an
`IntegrityError` instead of two cases sharing a reference, and
`_insert_incident_with_number` retries against the now-higher maximum
inside a `SAVEPOINT` (up to five attempts, then `503`). A Postgres
sequence would be the obvious tool and does not work here, because the
numbering has to restart per tenant.

---

## 12. API surface

All routes under `/api/v1/incidents`.

| Method | Path | Permission |
|---|---|---|
| GET | `/` (filters: `status`, `severity`, `assigned_to_id`, `open_only`) | `incidents.read` |
| POST | `/` | `incidents.create` |
| POST | `/from-investigation` | `incidents.create` + `ai.read` |
| GET | `/{id}` | `incidents.read` |
| GET | `/{id}/metrics` | `incidents.read` |
| PATCH | `/{id}` (title/summary/severity) | `incidents.update` |
| PATCH | `/{id}/status` | `incidents.update` (+ `incidents.assign` to reopen) |
| PATCH | `/{id}/assign` | `incidents.assign` |
| POST | `/{id}/alerts` | `incidents.update` |
| DELETE | `/{id}/alerts/{alert_id}` | `incidents.update` |
| GET / POST | `/{id}/notes` | `incidents.read` / `.update` |
| GET / POST | `/{id}/tasks` | `incidents.read` / `.update` |
| PATCH / DELETE | `/{id}/tasks/{task_id}` | `incidents.update` |
| GET | `/{id}/timeline` | `incidents.read` |
| GET | `/{id}/response-actions` | `incidents.read` |

Tasks are reached only *through* an already-tenant-checked incident, so a
task id from another organization cannot be operated on by pairing it
with an incident id from the caller's own.

---

## 13. Migration

`a1da091fdd8d_incident_response_lifecycle`. Three departures from what
`alembic revision --autogenerate` produced, each deliberate and
documented in the migration's own docstring:

1. The four new `NOT NULL` columns on `incident_tasks` are added **with a
   `server_default` that is then dropped**. Autogenerate emitted them
   bare, which fails outright on any table that already has rows. Adding
   the default backfills existing rows in the same statement; dropping it
   afterwards hands responsibility for new rows back to the ORM defaults,
   so the schema does not acquire a second source of truth for what a new
   task looks like.
2. The `completed_by_id` foreign key is **named**. Autogenerate emitted
   `create_foreign_key(None, …)` / `drop_constraint(None, …)`; the latter
   cannot execute, so the downgrade path was broken as generated.
3. `incident_number` and `detected_at` are **backfilled** —
   `ROW_NUMBER() OVER (PARTITION BY organization_id ORDER BY created_at)`
   for the former, and the earliest linked alert's own timestamp (falling
   back to `created_at`) for the latter, matching the rule
   `_refresh_detected_at` applies going forward rather than inventing a
   different one for historical rows.

`closure_classification` is deliberately **not** backfilled for incidents
already in status `closed`. There is no honest value to invent — nobody
recorded a verdict because there was nowhere to record one — and guessing
`true_positive` would silently corrupt the false-positive rate the column
exists to make measurable. Those rows stay null and are visibly
pre-Phase-9.

Verified `upgrade → downgrade → upgrade` against a live Postgres 16, with
`alembic check` reporting no drift afterwards.

---

## 14. What this phase does *not* do

- **No IOC attachment.** The `iocs` table exists and
  `IncidentTimelineKind` reserves nothing for it yet; observables and
  reputation enrichment are Phase 10's subject, and splitting the
  enrichment half across two phases would have produced a half-built
  feature in both.
- **No SLA timers or breach alerting.** The metrics endpoint reports
  elapsed durations; it does not compare them against a target or notify
  anyone when one is exceeded.
- **No incident merge/split.** Duplicate cases are closed with
  classification `duplicate`; there is no operation that folds one case's
  alerts, tasks and timeline into another.
- **No frontend.** `frontend/app/incidents/page.tsx` is still the
  `ComingSoon` placeholder, consistent with every other page — the UI is
  Phase 12.
- **Response execution is still simulated.** Unchanged from Phase 2:
  `execute_response_action` sets `result.simulated = True` because no
  real EDR/IAM/firewall integration exists yet. The guarantee being
  demonstrated is the approval state machine and its audit trail, not a
  live integration.

---

## 15. Test coverage

`backend/tests/test_incidents.py` — 70 tests.

- **Data-integrity invariants (no DB):** the transition graph covers
  every `IncidentStatus` and references no unknown one; `closed` is
  reachable from every non-closed state; reopen is the only edge out of
  `closed`; the checklist covers every task category and has unique
  titles; `max_severity` picks the highest rather than the last.
- **Creation:** checklist seeding and opt-out, per-tenant sequential case
  numbers that restart independently across two organizations, severity
  required when not deriving from alerts.
- **Alert linkage:** severity/ATT&CK/`detected_at` derivation, idempotent
  re-linking, technique recomputation on unlink, analyst severity not
  overridden but escalation surfaced, cross-tenant link and cross-tenant
  create both refused.
- **Lifecycle:** the full seven-state walk, first-entry-only milestone
  stamping across a containment regression, illegal transition `409` with
  the legal set named, same-status `409`, closure classification required
  and validated, `new → investigating` still recording triage,
  assignment auto-triaging, cross-org assignee refused.
- **Reopen authorization:** analyst can close but not reopen; manager
  can; the prior verdict survives on the timeline.
- **Notes:** round-trip, and a caller attempting `is_ai_generated: true`
  gets `false`.
- **Tasks:** create/complete/un-complete with attribution cleared on
  un-tick, deletion recorded, unknown category refused, and a task from
  another incident unreachable through this one.
- **Timeline:** full history in order with correct actors, all four write
  verbs `405`, platform-generated entries carrying a null actor.
- **Metrics:** null-until-reached, measured from `detected_at` rather
  than creation, never negative, task counts.
- **Response actions:** all three phases mirrored, containment status
  executing nothing, cross-tenant `incident_id` refused with the victim's
  timeline left empty.
- **AI promotion:** grounded case file end to end, fabricated citation
  rejected and reported, incomplete investigation refused `409`,
  cross-tenant investigation `404`, `ai.read` required.
- **`check_related_incidents`:** effect and allowlist, open-case match,
  closed excluded by default, tenant isolation, no-criteria error rather
  than exception, four other agent types denied, and no
  incident-mutating tool in the registry.
- **RBAC / IDOR:** viewer read-only, analyst can update but not assign,
  unauthenticated `401`, a parametrised sweep asserting all six nested
  routes `404` on another tenant's incident id, mutation attempts on a
  foreign incident leaving it untouched, list scoping, and filters.

Full suite: **255 passing** (185 from Phases 1–8, 70 new).
