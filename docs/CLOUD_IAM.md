# Cloud / IAM Security and Attack-Path Analysis (Phase 11)

## 1. The claim this phase makes, and the one it refuses to make

**It reconstructs what was *observed*, not what was *possible*.**

A real IAM attack-path tool — Cartography, PMapper — answers "who *could*
reach this resource?" by evaluating policy documents. This platform
answers "who *did* what, in what order?" by walking observed CloudTrail
activity.

The second question is the one telemetry can honestly answer. Presenting
a policy-derived hypothesis as an observation would be the same class of
dishonesty as the AI fabricating evidence, so the distinction is stated
in the graph's own `explanation` text, in the API schema, and in the UI —
not just here. Answering the first question properly needs a live AWS
policy fetch, which this platform does not have; see §7.

## 2. Why `cloud_events` exists alongside `events`

Phase 3's adapter writes every CloudTrail-shaped log into the generic
`events` table. That table is flat — one row, one set of normalized
columns — which is right for search and detection and wrong for
reconstructing an identity chain, because "who assumed what, and what did
that assumed identity then do?" is a graph question over
`actor → role → action` triples.

So Phase 11 adds a **projection, not a replacement**
(`app/cloud_iam/projection.py`): a `cloud_events` row alongside the
`events` row it came from, carrying the identity-chain fields the flat
schema has nowhere to put (`actor_identity`, `actor_arn`,
`assumed_role_arn`, `request_parameters`, `response_elements`,
`error_code`).

`cloud_events.event_id` always points back at the originating `events`
row. Nothing here is a second source of truth — the raw payload remains
the only evidence, and every cloud row traces to it.

## 3. Identities are derived, not imported

A `CloudIdentity` exists in this platform because it was **observed
acting**, not because somebody imported an IAM inventory. That is honest
about what the platform can see: an identity that never appears in logs
never appears here.

It is also a real limitation, and the visible consequence is
`is_privileged`. Without a policy fetch the platform cannot know a role's
effective permissions, so it infers from naming (`admin`, `root`,
`breakglass`, …). The API field is documented as a heuristic, the UI
renders it as "privileged?" with a caption, and the agent tool returns it
under the key **`is_privileged_heuristic`** — so a model summarising the
tool output cannot honestly report it as an IAM policy fact.

## 4. The tenancy trap

`CloudEvent` carries no `organization_id` of its own — the same situation
as `Process`/`NetworkConnection` in the tool registry.

Scoping on `account_id` alone would be a **real cross-tenant leak** the
moment two organizations monitor the same AWS account, which is exactly
what a managed-service provider does. `scoped_cloud_events()` therefore
joins through `events.organization_id`, and
`test_two_tenants_monitoring_the_same_aws_account_cannot_see_each_other`
exists specifically to fail if someone "simplifies" that join away.

`IAMAttackPath` **was** given a real `organization_id` (a migration
column) rather than inferring visibility from its nullable
`alert_id`/`incident_id`. A path can legitimately have neither — an
analyst reconstructing a chain ad hoc — and deriving visibility from a
nullable FK meant such paths were visible either to everyone or to no
one. The first attempt at this shipped a convoluted, slow subquery; the
column is the correct fix.

## 5. Action classification

`classify_action()` sorts every event name into one of four signals,
which weight the graph and drive path severity:

| Signal | Meaning | Severity |
|---|---|---|
| `defense_evasion` | `StopLogging`, `DeleteTrail`, `DeleteFlowLogs`, … | **CRITICAL** |
| `privilege_escalation` | `AttachRolePolicy`, `CreateAccessKey`, `PassRole`, … | HIGH |
| `role_assumption` | `AssumeRole` | MEDIUM |
| `access` | everything else | LOW |

Defense evasion outranks privilege escalation deliberately: turning off
logging removes the defender's ability to see everything that follows,
which is worse than a single permission grant. A test asserts that
ordering so it cannot be quietly inverted.

## 6. The walk

`reconstruct_attack_path()` starts from a seed actor and follows
`AssumeRole` edges forward in time within a bounded window, collecting
each identity's subsequent actions.

Three bounds, all declared rather than silent:

1. **`MAX_DEPTH` (6) caps role-assumption hops.** Cyclic assumption
   (`A → B → A`) is legitimate in some architectures and would not
   terminate; visited identities are tracked and depth is capped.
2. **`MAX_ACTIONS_PER_IDENTITY` (25)** stops one noisy principal
   producing an unrenderable graph.
3. A path that hit either bound says **`TRUNCATED`** in its
   `explanation` — the same bookkeeping discipline as Phase 7's hunt
   truncation. A partial chain is never presented as a complete one.

**Every edge carries the `cloud_event_id` it came from.** No node or edge
in a rendered graph is an inference the platform cannot point at a row
for, and a test walks every edge of a generated path and resolves it
against the database.

An empty result returns `None` rather than persisting an empty graph — an
empty graph is not a finding, and storing them would fill the view with
noise.

### Known imprecision, stated

Role-assumption chains are matched on **identity naming**, not on STS
session tokens. CloudTrail's true chain link is the assumed-role session
identity in `userIdentity.sessionContext`, which lab-shaped payloads
often do not carry. The walk links `actor → role` when the actor assumed
that role and then acts *as* that role name. This is correct for the
common case and can produce a false link if two unrelated principals use
the same role name inside one window — which is why every edge cites its
source event, so a reviewer can check.

## 7. What this does not do

- **No IAM policy evaluation.** No "who could reach this bucket"
  analysis, no permission-boundary or SCP reasoning, no unused-permission
  reporting. All of that needs a real AWS integration.
- **No live AWS connection at all.** Everything is derived from ingested
  telemetry.
- **No remediation.** Revoking cloud credentials remains a
  `PRIVILEGED_ACTION_CATALOG` entry requiring human approval, and no
  cloud tool in the registry can touch an account.
- **AWS-shaped only.** `provider` is a column, but the projection
  understands CloudTrail vocabulary specifically.

## 8. Agent tools

The three tools `ARCHITECTURE.md` §4.2 promised the Cloud/IAM Agent for
Phase 11, all `read_only` and granted to that agent alone:

| Tool | Answers |
|---|---|
| `get_cloud_identity` | "What do we know about this principal?" |
| `get_role_assumptions` | "What roles has it assumed, and when?" |
| `search_cloud_events` | "What has happened in this account?" |

The Cloud/IAM Agent's ceiling stays `read_only`. Reconstructing an
identity chain is analysis over already-ingested telemetry; nothing here
can touch a cloud account.

## 9. API surface

| Method | Path | Permission |
|---|---|---|
| GET | `/cloud/identities` | `iam.read` |
| GET | `/cloud/identities/{id}` (+recent activity, roles assumed) | `iam.read` |
| GET | `/cloud/events` | `cloud.read` |
| GET | `/cloud/attack-paths` | `iam.read` |
| GET | `/cloud/attack-paths/{id}` | `iam.read` |
| POST | `/cloud/attack-paths` (reconstruct) | `iam.read` |

Building a path is `iam.read`, not a write permission: reconstruction is
a pure read over ingested telemetry that derives a graph. The row it
persists is a cached view of that derivation, not new evidence.

No new permissions were needed — `iam.read` and `cloud.read` have existed
since Phase 2 and are granted to every role, because read-only visibility
into which identity did what is exactly what the people who most often
need to look at an attack path have.

## 10. Migration

`4c8afcfe1dfe_cloud_iam_attack_paths` — one nullable
`iam_attack_paths.organization_id` column with a **named** foreign key
(autogenerate emitted `create_foreign_key(None, …)`, whose
`drop_constraint(None, …)` counterpart cannot execute, so the downgrade
was broken as generated).

## 11. Test coverage

`backend/tests/test_cloud_iam.py` — 36 tests: action classification and
the defense-evasion-outranks-escalation ordering, the projection and its
back-reference, identity upsert idempotency, the full escalation chain
end to end, every edge citing a resolvable row, window exclusion,
declared truncation, cyclic-assumption termination, the three agent tools
and their exclusivity, and tenancy — including two tenants on one AWS
account and a walk that must not cross the boundary.
