# Alerts & Risk Scoring (Phase 5)

## 1. The formula, in full

```
score = clamp(0, 100, round(
    base_risk_score                              # from the firing Detection (Phase 4)
  + ASSET_CRITICALITY_BONUS[host.criticality]     # -5 / 0 / +10 / +20
  + (REPEAT_OFFENDER_BONUS if repeat_offender else 0)   # +15
))
```

`app/services/risk_scoring.py` is the entire implementation — two pure
functions, no DB access, every weight a named module-level constant with
a one-line justification in the docstring. This is a deliberate design
choice: "why did this alert score 78?" should always be answerable by
pointing at three numbers and one line of arithmetic, never at a black
box. `backend/tests/test_risk_scoring.py` tests every constant directly —
if a weight's value silently changed, a test would fail.

**Asset criticality** (`ASSET_CRITICALITY_BONUS`, keyed off `Host.criticality`,
default `"standard"`): a brute-force hit on a disposable dev VM and the
same pattern on the domain controller are not the same risk, even with an
identical base detection score. `low: -5, standard: 0, important: +10,
critical: +20`.

**Repeat offender** (`REPEAT_OFFENDER_BONUS = 15`): true when the same
host (or user, for host-less IAM/cloud alerts) already has an **open**
alert from a **different** detection rule within the last
`REPEAT_OFFENDER_LOOKBACK_HOURS` (24). This is deliberately keyed on
*distinct rule* count, not repeat firings of the same rule — repeated
firings of one rule are handled by dedup/reinforcement (§2), not by
inflating the score. A second, different kind of malicious signal on the
same asset within a day is a materially stronger indicator of an ongoing
compromise than either signal alone.

**Severity thresholds** (`risk_score_to_severity`): `>=85 CRITICAL, >=65
HIGH, >=40 MEDIUM, >=20 LOW, else INFO`. Chosen so a Sigma `level:
critical` rule (base 90) lands as `CRITICAL` on a standard asset with no
other factors, and a `level: medium` rule (base 50) on a low-criticality
asset doesn't get rounded up into `HIGH` territory.

**Explicitly not included yet, and why that's stated rather than hidden:**
MITRE tactic/technique weighting (Phase 6 hasn't seeded the real ATT&CK
catalog yet — hardcoding a technique→tactic weight map here would mean
throwing it away in two phases), and a historical false-positive-rate
adjustment per rule (needs enough analyst-closed-alert history to be
signal rather than noise — a natural Phase 9+ enhancement once that
feedback loop exists).

## 2. Alert generation: dedup and reinforcement

`app/services/alerting.py::generate_alerts_for_detections` is called
synchronously right after `run_detections_for_event` persists its
`Detection` rows (see `app/services/ingestion/service.py`), and again
from the manual `POST /api/v1/detections/run` sweep.

Naively, one Detection would always mean one Alert — but a rule
re-firing repeatedly against the same asset in a short window (a brute
force detection re-evaluating on every subsequent failed-login event,
say) would flood the queue with near-duplicate alerts. Instead:

- If an **open** alert already exists for the same detection rule and the
  same host (or user) within `DEDUP_WINDOW_MINUTES` (30) of the new
  detection's `fired_at`, the existing alert is **reinforced**: its
  `risk_score` is raised to `max(existing, new)`, `related_event_ids` are
  merged, `alert_timestamp` advances, and `evidence.reinforcement_count`
  increments — instead of a new row being created.
- Otherwise a new `Alert` is created.

"Open" means `status` is `new`/`triaged`/`investigating`/`escalated` — an
alert an analyst has already closed (`false_positive`/`closed`) is not a
dedup target; a re-firing after that point opens a fresh alert rather
than silently reinforcing a decision the analyst already made.

Every fired detection becomes an alert today — Phase 4's detections are
already reasonably high-precision (no purely-informational/telemetry-only
rules exist), so a minimum-severity-to-alert filter isn't needed yet.
Documented here as the natural next lever if low-value alert volume ever
becomes a problem.

## 3. Why `Detection.fired_at` uses the event's timestamp, not wall-clock time

Caught and fixed while building this phase: every detection
implementation originally set `DetectionMatch.fired_at =
datetime.now(timezone.utc)` — the time the detection *engine happened to
run*, not the time the underlying evidence occurred. That's wrong for two
reasons that only show up once you build something on top of it: replaying
historical telemetry through the attack-simulation lab (Phase 14) would
make every finding's timestamp say "now" regardless of when the simulated
attack "happened," and — directly relevant here — the dedup and
repeat-offender time windows in this phase would be measuring wall-clock
proximity between when ingestion requests happened to arrive, not
proximity between when the actual security events occurred. Fixed by
setting `fired_at` to the triggering (or, for multi-event correlations,
the deciding) event's `event_timestamp` in all twelve detections. This
also made the dedup/repeat-offender tests in `test_alerts.py`
deterministic — they construct events at fixed offsets from a fixed base
timestamp rather than depending on real elapsed wall-clock time between
test steps.

## 4. A second bug fix this phase depended on: tenant-scoped hostnames

`Host.hostname` had a **globally unique** index since Phase 1 — meaning
two different organizations could never both register a host named e.g.
`WIN-01`, a near-certain collision in real deployments. This was latent
(the ingestion service's `_get_or_create_host` already scoped its
*lookup* by `organization_id`) until asset-criticality lookups for risk
scoring made it worth fixing properly: migration
`ac52294ad8d5_host_hostname_tenant_scoped_uniqueness` replaces the global
unique index with a composite `UNIQUE(organization_id, hostname)`
constraint. Regression test:
`test_ingestion.py::test_hostname_collision_across_organizations_is_allowed`.

## 5. API surface

| Endpoint | Permission | Notes |
|---|---|---|
| `GET /api/v1/alerts` | `alerts.read` | Tenant-scoped, filterable by status/severity/host/user/assignee/risk/time, sorted by risk_score desc |
| `GET /api/v1/alerts/{id}` | `alerts.read` | 404 (not 403) cross-tenant |
| `PATCH /api/v1/alerts/{id}` | `alerts.update` | Status / severity / assignment / analyst-note — all optional, at least one required. Assigning a `new` alert auto-transitions it to `triaged`. Every update is audit-logged with a before/after diff. |

No new permissions were needed — `alerts.read`/`alerts.update` were
already part of the Phase 2 RBAC matrix (viewer+ read, soc_analyst+
update).

Note on scope: alert status here is ordinary analyst triage bookkeeping
(`new → triaged → investigating → escalated → false_positive/closed`),
not validated against a strict state machine. That's intentional — the
human-in-the-loop *approval* state machine that must never be bypassed
(pending → approved/rejected → executed) lives entirely in `ResponseAction`
(Phase 2) and is untouched by anything in this phase. Alerts don't gate
privileged actions; they're what an analyst looks at before deciding to
request one.

## 6. Data model

`Alert` already existed in the Phase 1 schema with exactly the fields
this phase needed (`risk_score`, `severity`, `status`, `detection_id` FK,
`evidence` JSON, `related_event_ids` JSON) — no migration required for
the `alerts` table itself. `Alert.mitre_techniques` (the M2M to
`MitreTechnique`) is deliberately left unpopulated until Phase 6 seeds
the real ATT&CK catalog; in the meantime the raw technique ID strings
from the firing rule are carried in `evidence.mitre_technique_ids`, so
alerts are still fully informative today.

## 7. Testing

- `backend/tests/test_risk_scoring.py` (23 tests) — pure unit tests of
  the formula: every criticality bonus, the repeat-offender bonus, both
  clamp boundaries, and every severity threshold boundary.
- `backend/tests/test_alerts.py` (11 tests) — end to end through the real
  ingestion → detection → alert pipeline and the real HTTP API: alert
  creation, dedup/reinforcement (both inside and outside the window),
  asset-criticality scoring, repeat-offender scoring, the PATCH update
  API (status/note/assignment, invalid-status rejection), RBAC, and
  tenant scoping.
- `backend/tests/test_ingestion.py` gained one regression test for the
  hostname tenant-scoping fix (§4).

All 134 backend tests pass against a real Postgres test database.

## 8. What's deliberately deferred

- MITRE tactic/technique weighting in the score, and relational MITRE
  tagging on `Alert` — Phase 6.
- Alert → Incident linkage/escalation workflow — Phase 9 (the `incident_alerts`
  join table already exists from Phase 1's schema).
- Historical false-positive-rate feedback into scoring — needs enough
  closed-alert history to be meaningful; natural Phase 9+ enhancement.
- A strict alert-status state machine (if ever needed) — today PATCH
  accepts any valid `AlertStatus` value in any order, which is fine for
  analyst bookkeeping but would need tightening if automated workflows
  start depending on specific transitions.
