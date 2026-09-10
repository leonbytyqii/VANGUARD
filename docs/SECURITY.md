# VANGUARD — Security Model

This document covers authentication, authorization (human RBAC + AI agent
permissions), the human-in-the-loop approval model, multi-tenant scoping,
audit architecture, and the threat model for VANGUARD's own security surface.
Written to be read alongside the code it describes — every claim below
names the file that enforces it and, where relevant, the test that proves
it.

## 1. Authentication architecture

### 1.1 Passwords

Hashed with **Argon2id** via passlib (`app/core/security.py`), OWASP's
current recommendation for new applications — memory-hard, resistant to
GPU/ASIC cracking, tunable as hardware improves. Bcrypt is kept as a
secondary scheme purely so any historically-bcrypt hash still verifies;
`passlib`'s `deprecated="auto"` means a successful login against an old
hash transparently re-hashes it to Argon2id, so migration is automatic and
lazy rather than a big-bang rehash job.

Password policy (`validate_password_policy`): minimum 12 characters,
requires lowercase, uppercase, digit, and special character, and rejects a
small embedded blocklist of catastrophically common passwords. This is
enforced in the Pydantic schema layer (`UserCreateRequest`,
`ChangePasswordRequest`) so a bad password never reaches the database.

### 1.2 Tokens: short-lived stateless access + long-lived stateful refresh

- **Access tokens** are JWTs (HS256), default 30 minute TTL, never
  persisted server-side. They carry `sub` (user id), `org`, `role`, and a
  `perms` snapshot — the `perms` claim is a UI convenience only; every
  server-side permission check re-reads the database
  (`User.has_permission`), so revoking a permission takes effect on the
  very next request rather than waiting for token expiry.
- **Refresh tokens** are opaque random strings (`secrets.token_urlsafe`),
  default 7 day TTL, and *are* persisted — as a SHA-256 hash, never the raw
  value — in the `refresh_tokens` table (`app/models/auth.py`), because
  unlike access tokens they need to be revocable. They're delivered as an
  **httpOnly, `SameSite=Lax` cookie** scoped to `/api/v1/auth` (never
  readable by JavaScript, never sent to non-auth routes), while the access
  token is returned in the JSON response body for the frontend to hold in
  memory.
- **Rotation**: every `/auth/refresh` call issues a brand-new refresh
  token and immediately revokes the one just used
  (`app/services/auth_service.py::rotate_refresh_token`). A refresh token
  is single-use.
- **Reuse detection**: if a refresh token that's already been rotated away
  is presented again, that's a strong signal someone is replaying a stolen
  token after the legitimate client already moved past it. The first time
  this happens for a given token, every other active refresh token for
  that user is revoked and the incident is audited
  (`refresh_token_reuse_detected`) — forcing full re-authentication.
  Subsequent replays of the *same* already-flagged token are just denied
  without re-triggering the cascade (`RefreshToken.reuse_detected_at`) —
  otherwise an attacker holding one dead token could keep forcing the
  legitimate user's *new* sessions offline forever just by replaying it
  repeatedly. Both behaviors are covered by
  `backend/tests/test_auth.py::test_refresh_reuse_revokes_all_sessions`.
- **Logout** revokes the current refresh token and clears the cookie.

### 1.3 Account lockout + rate limiting (two independent layers)

- **Per-account lockout**: `MAX_FAILED_LOGIN_ATTEMPTS` (default 5)
  consecutive failures locks the account for `ACCOUNT_LOCKOUT_MINUTES`
  (default 15). A successful login resets the counter. Survives an
  attacker rotating source IPs, because it keys on the account, not the
  request.
- **Per-IP rate limiting**: `/auth/login` and `/auth/refresh` are
  decorated with `@limiter.limit(settings.RATE_LIMIT_AUTH)` (slowapi,
  default 10/minute per IP) — independent of and in addition to account
  lockout, so a distributed attempt against *many* accounts from one
  source is still throttled even though no single account has failed
  enough times to lock.
- Login responses are **identical in shape and status code** whether the
  email doesn't exist or the password is wrong (`401` either way), so the
  endpoint can't be used to enumerate valid usernames.

### 1.4 Provisioning — no public self-registration

There is no public "sign up" endpoint. Users are created by an
administrator (`POST /api/v1/admin/users`, requires `admin.users`) or by
the one-time bootstrap seed (`app/db/seed.py::seed_bootstrap_admin`), which
runs only when the `users` table is empty. If `ADMIN_BOOTSTRAP_PASSWORD`
isn't set in the environment, a random password is generated and printed
**once** to the startup log — never written to code, never stored
anywhere else, and the account is created with `must_change_password=True`
so it can't be used indefinitely.

## 2. RBAC architecture

Five roles: `admin`, `soc_manager`, `soc_analyst`, `threat_hunter`,
`viewer`. Permissions are `resource.action` strings, not baked into the
role check — the canonical list and default role grants live in
`app/core/permissions.py`:

| Permission | Viewer | Threat Hunter | SOC Analyst | SOC Manager | Admin |
|---|:---:|:---:|:---:|:---:|:---:|
| `alerts.read` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `alerts.update` | | | ✅ | ✅ | ✅ |
| `incidents.read` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `incidents.create` | | | ✅ | ✅ | ✅ |
| `incidents.update` | | | ✅ | ✅ | ✅ |
| `incidents.assign` | | | | ✅ | ✅ |
| `events.read` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `events.ingest` *(service credential)* | | | | | ✅ |
| `threat_hunting.execute` | | ✅ | ✅ | ✅ | ✅ |
| `threat_intel.lookup` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `ai.investigate` | | ✅ | ✅ | ✅ | ✅ |
| `blueprints.execute` | | | ✅ | ✅ | ✅ |
| `playbooks.execute` | | | | ✅ | ✅ |
| `response.request` | | | ✅ | ✅ | ✅ |
| `response.approve` | | | | ✅ | ✅ |
| `iam.read` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `cloud.read` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `admin.users` | | | | | ✅ |
| `admin.roles` | | | | | ✅ |
| `admin.agents` | | | | | ✅ |
| `audit.read` | | | | ✅ | ✅ |

`events.ingest`, `incidents.update`, and `admin.agents` are additions
beyond the base spec, needed for the platform to function end-to-end
(service-credentialed log ingestion, incident lifecycle edits beyond just
assignment, and governance over AI agent identities) — called out
explicitly in `app/core/permissions.py` rather than silently added.

Enforcement: `Depends(require_permission("response.approve"))`
(`app/core/deps.py`). The dependency (a) resolves the current user from
the JWT, (b) re-checks `user.has_permission(code)` against live DB state,
and (c) on denial, writes an `audit_logs` row (`permission_denied`) with
the resource path, required permission, and the user's actual role, then
returns `403`. `is_superuser=True` (reserved for the bootstrap admin)
bypasses the role/permission list entirely — this is deliberate and
documented, not an accidental backdoor
(`test_superuser_bypasses_role_permission_list...`).

## 3. Agent identity model — the part built specifically to survive an interview question

**The question this section answers: "how do you actually stop the AI from
doing something it shouldn't, given that you can't fully control what an
LLM decides to try?"**

The answer is: don't try to control what it *decides* — control what it
can *reach*. An AI agent is never a `User` row. It never authenticates,
never holds a JWT, never calls an HTTP endpoint. It runs entirely
server-side, and the only interface it has to the rest of the system is
`app.ai.agents.permissions.invoke_agent_tool(db, agent_type, tool_name,
organization_id, **kwargs)`. That function is the entire attack surface,
and it enforces four checks in order before a single line of tool code
runs:

1. **Is this agent identity enabled?** `agent_identities` is a real table
   (`app/models/agent_identity.py`), seeded from
   `AGENT_TOOL_ALLOWLIST`/`AGENT_MAX_EFFECT` in
   `app/ai/agents/permissions.py` so the enforced values and the seeded
   values can never drift apart. An admin can disable an agent type at
   runtime (`admin.agents`) and every subsequent call fails closed.
2. **Does the tool even exist in `TOOL_REGISTRY`?**
   (`app/ai/tools/registry.py`). This is the load-bearing check:
   `isolate_host`, `disable_account`, `block_ip`, `block_domain`, and
   `revoke_cloud_credentials` are defined *only* in
   `PRIVILEGED_ACTION_CATALOG`, a separate dict used exclusively to
   validate human-submitted response actions. They were never added to
   `TOOL_REGISTRY`. There is no flag, no permission, no allowlist entry
   that could accidentally expose them here — the dispatcher literally
   cannot look them up.
3. **Is the tool in *this specific agent's* `allowed_tools`?** A Triage
   Agent asking for `request_response_approval` — a real, legitimate,
   `propose_only` tool — is refused, because Triage was never granted it.
   Specialization is enforced per-agent, not just per-effect-tier.
4. **Does the tool's `effect` exceed the agent's `max_effect` ceiling?**
   Defense in depth against a future allowlist misconfiguration. Every
   agent's ceiling is `read_only` except the Response Agent
   (`propose_only`) — **no agent's ceiling is ever `privileged_action`.**

Every denial writes an `audit_logs` row
(`ai_tool_permission_denied`, actor labeled `ai_agent:<type>`) with the
reason code (`tool_not_registered`, `tool_not_in_agent_allowlist`,
`tool_effect_exceeds_agent_ceiling`, `agent_identity_disabled_or_missing`);
every successful call is also audited (`ai_tool_invoked`).

Proof, not just description — `backend/tests/test_agent_permissions.py`:
- `test_privileged_actions_are_never_registered_as_ai_tools` — asserts the
  full `PRIVILEGED_ACTION_CATALOG` has zero overlap with `TOOL_REGISTRY`.
- `test_no_agent_can_call_a_nonexistent_privileged_tool_name` — simulates
  every agent type asking for `isolate_host` directly (the "jailbroken/
  prompt-injected agent" scenario) and confirms all five are refused.
- `test_triage_agent_cannot_call_tool_outside_its_allowlist` — confirms a
  *legitimate, registered, low-risk* tool is still refused to an agent
  that wasn't granted it.
- `test_disabled_agent_identity_blocks_all_tool_calls` — runtime kill
  switch works.
- `test_tool_permission_denial_is_audited` /
  `test_successful_tool_invocation_is_also_audited`.

## 4. Human-in-the-loop approval model

State machine (`app/models/automation.py::ResponseAction`,
`app/services/response_actions.py`):

```
pending --approve(human, response.approve)--> approved --execute(human, response.approve)--> executed
   \--reject(human, response.approve)--> rejected
```

- **Origin**: a request is created either by a human
  (`POST /api/v1/response/actions`, `response.request`) or by an AI agent
  via the `request_response_approval` tool
  (`requested_by_agent_type` set instead of `requested_by_id`). Both land
  in the exact same table and state machine.
- **Approval requires a human.** `approve_response_action` /
  `reject_response_action` take an `approver: User` parameter and are only
  reachable via `PATCH /api/v1/response/actions/{id}/approve|reject`,
  which requires `response.approve` (SOC Manager/Admin) and a valid JWT.
  There is no tool in `TOOL_REGISTRY` that calls these functions, and
  agents have no JWT to authenticate with even if there were — so an
  agent cannot approve its own request, structurally, not by policy.
- **Execution requires `status == approved`.**
  `execute_response_action` raises `ResponseActionError` (mapped to HTTP
  `409`) on anything else — confirmed directly at the service layer
  (`test_cannot_execute_a_pending_action_directly`) and through the API
  (`test_full_lifecycle_via_api_agent_request_human_approval_execution`,
  which asserts a pre-approval execute attempt returns `409`).
- **Execution is simulated, honestly.** Phase 2 has no real EDR/IAM/
  firewall integration wired up. `execute_response_action` always sets
  `result.simulated = True`. The guarantee being demonstrated is the state
  machine and the audit trail, not a live integration — claiming otherwise
  would be dishonest about the platform's current capability. Wiring a
  real executor for a given `action_type` is additive, not a redesign.
- **No auto-approval, ever, regardless of AI confidence.** There is no
  code path — not a confidence threshold, not a severity check, not a
  config flag — that transitions `pending → approved` without a human
  request through the approve endpoint. This was a deliberate choice to
  not build a "shortcut" even for a demo: the point of the platform is
  that this boundary holds unconditionally.

## 5. Multi-tenant / scope architecture

Covered in depth in `docs/ARCHITECTURE.md` §8.1. Summary: every
tenant-relevant resource table carries `organization_id`
(`TenantScopedMixin`); route handlers query through
`app.core.scope.scoped_query`, which filters by
`current_user.organization_id`. Cross-tenant access to a specific resource
(`GET /api/v1/incidents/{id}` for an incident in another org) returns
**404, not 403** — confirming a resource *exists* in a tenant you can't see
is itself an information leak, so "not found" and "not yours" are
indistinguishable from the outside
(`test_cross_tenant_incident_access_returns_404_not_403`). List endpoints
are filtered server-side, not client-side
(`test_cross_tenant_incident_list_never_leaks_other_org_rows`). Assigning
a resource to a user outside the caller's organization is rejected
(`test_cannot_assign_incident_to_user_in_another_organization`).

## 6. Audit architecture

`AuditLog` (`app/models/audit.py`) is append-only — no application code
path updates or deletes a row — and every entry captures:

| Field | Meaning |
|---|---|
| `actor_id` / `actor_label` | WHO — a user id, or `ai_agent:<type>` for agent-originated events |
| `action` | WHAT — a fixed vocabulary (see below) |
| `timestamp` | WHEN |
| `source_ip` | FROM WHERE |
| `resource_type` / `resource_id` | AGAINST WHAT |
| `outcome` | RESULT — `success` / `denied` / `error` |
| `details` | structured context specific to the action |

Actions logged today: `login`, `login_failed`, `login_blocked_lockout`,
`login_blocked_inactive`, `logout`, `token_refresh`,
`token_refresh_failed`, `refresh_token_reuse_detected`,
`password_changed`, `password_change_failed`, `permission_denied`,
`user_created`, `user_changed`, `role_changed`, `incident_created`,
`incident_assigned`, `approval_request`, `approval_decision`,
`privileged_action_executed`, `ai_tool_invoked`,
`ai_tool_permission_denied`. `GET /api/v1/audit` (requires `audit.read`)
exposes it to SOC Managers/Admins.

Logging is synchronous and part of the same request as the action it
records, not a fire-and-forget background job — an audit entry that
silently failed to write would defeat the point.

## 7. Why authorization is enforced server-side rather than through AI prompts

A system prompt that says "never isolate a host without approval" is a
request to a language model, not a guarantee. Prompt injection (an
attacker-controlled command line, domain name, or cloud role name
embedded in ingested telemetry) can attempt to override system
instructions, and a sufficiently adversarial or simply confused model can
comply. VANGUARD's design assumes this will eventually be attempted and
makes it structurally irrelevant when it is:

- The model never has network/shell/API access of its own — its only
  output channel is the validated structured-JSON contract
  (`docs/ARCHITECTURE.md` §4.4) and the tool-calling interface in §3
  above.
- The tool-calling interface's own registry contains zero privileged
  actions — there's nothing to "trick" it into calling because the
  function doesn't exist in the dispatch table, independent of anything
  the model outputs.
- The one path from "AI recommendation" to "real-world effect"
  (`request_response_approval` → `ResponseAction` → human `approve` →
  `execute`) requires a human with the right RBAC permission at a step the
  agent cannot reach or forge, because approval is a separate
  authenticated HTTP call the agent has no credentials to make.

In short: a compromised or successfully-injected agent can, at absolute
worst, produce a bad *recommendation*. It cannot produce an *action*. The
tests in §3 and §4 verify the boundary directly rather than asserting the
model "won't" do something.

## 8. Attacks against the authorization system, and what stops them

| Attack | What stops it | Test |
|---|---|---|
| Guess/brute-force a password | Argon2id (slow to brute force) + account lockout + per-IP rate limit | `test_account_locks_after_repeated_failed_logins` |
| Enumerate valid usernames via login errors | Identical 401 response for unknown-user and wrong-password | `test_login_does_not_leak_whether_user_exists` |
| Replay a stolen/expired access token | Short TTL (30 min default); server-side permission re-check on every request | `test_expired_access_token_rejected` |
| Forge or tamper with a JWT | HS256 signature verification against `JWT_SECRET_KEY` | `test_invalid_signature_token_rejected` |
| Replay a rotated-away refresh token | Single-use rotation + reuse detection revokes all sessions | `test_refresh_reuse_revokes_all_sessions` |
| Lower-privileged role calls a higher-privileged endpoint (vertical escalation) | Per-route `require_permission` re-checked against live DB role state | `test_soc_analyst_cannot_manage_users_vertical_escalation` |
| Guess another tenant's resource id (IDOR) | `scoped_query` filters by `organization_id`; 404 either way | `test_cross_tenant_incident_access_returns_404_not_403` |
| Assign a resource to an outsider to pivot access | Assignee is looked up scoped to the caller's org | `test_cannot_assign_incident_to_user_in_another_organization` |
| AI agent asked (via injection or otherwise) to call a privileged action | Action isn't in the tool registry — nothing to dispatch to | `test_no_agent_can_call_a_nonexistent_privileged_tool_name` |
| AI agent asked to call a legitimate tool outside its role | Per-agent allowlist checked independently of tool existence | `test_triage_agent_cannot_call_tool_outside_its_allowlist` |
| AI agent "approves" its own response-action request | No tool exists that calls the approval function; agents hold no credentials to call the HTTP endpoint directly | `test_full_lifecycle_via_api_agent_request_human_approval_execution` |
| Execute a response action that was never approved | State machine requires `status == approved`; enforced at the service layer, not just the route | `test_cannot_execute_a_pending_action_directly` |
| Analyst approves their own escalation to bypass review | `response.approve` is SOC Manager/Admin only, distinct from `response.request` | `test_soc_analyst_cannot_approve_response_actions` |
| Forge, back-date, or re-attribute an incident timeline entry (Phase 9) | No write route exists for the timeline at all — entries are only produced by the service layer, from inside the operation they describe, with a server-generated timestamp | `test_timeline_is_read_only_over_http` |
| Post text into a case file with a provenance it didn't have (Phase 9) | `is_ai_generated` is absent from the note request schema and hard-coded `False` at the route; only the internal promotion path sets `True` | `test_notes_round_trip_and_are_never_flagged_ai_generated_via_the_api` |
| Write onto another tenant's case file via `ResponseAction.incident_id` (Phase 9) | `incident_id` is resolved within the requester's own organization before the action is created; rejected as "unknown", not "forbidden" | `test_cannot_attach_a_response_action_to_another_tenants_incident` |
| Drive a privileged action by moving an incident to `contained` (Phase 9) | No code path leads from a status transition to execution; the `pending → approved → executed` machine is untouched | `test_containing_an_incident_executes_nothing` |
| Launder AI investigation output into an incident a role can read, without being allowed to read investigations (Phase 9) | Promotion requires `ai.read` in addition to `incidents.create` | `test_promotion_requires_ai_read_as_well_as_incidents_create` |
| Smuggle an unbacked evidence claim into a case file via a tampered stored result (Phase 9) | Every `source_event_id` is re-resolved against the database at promotion time; non-resolving citations are dropped and itemised in the response | `test_promotion_rejects_evidence_whose_source_event_no_longer_resolves` |
| Overturn a recorded closure verdict to massage the false-positive rate (Phase 9) | Reopening a closed case requires `incidents.assign` (SOC Manager+), and the prior verdict is preserved on the timeline | `test_analyst_can_close_but_cannot_reopen` |
| AI agent creates, edits, or closes a case to cover its tracks (Phase 9) | No incident-mutating tool exists in `TOOL_REGISTRY`; `check_related_incidents` is read-only and Response-Agent-only | `test_no_incident_mutating_tool_exists_in_the_registry`, `test_other_agents_are_denied_check_related_incidents` |
| Reach another tenant's incident through a nested route rather than the detail endpoint (Phase 9) | Every nested route resolves the incident through `scoped_query` first; tasks are reached only through an already-checked incident | `test_every_nested_route_is_tenant_isolated` |

## 9. Known limitations (honest, as of Phase 2)

- Refresh tokens are bound to a user, not additionally to a device
  fingerprint — theft of the raw cookie value (e.g. via a compromised
  client) is still viable until rotation-reuse is detected on the
  *attacker's* next use of it, not the moment of theft. This is a standard
  tradeoff of cookie-based refresh; a device-binding claim could be added
  later without a schema change (`user_agent`/`ip_address` are already
  recorded per token for anomaly review).
- There is no email verification or password-reset-via-email flow yet
  (no outbound email integration exists in the platform at all) —
  password resets today are admin-mediated
  (`PATCH /api/v1/admin/users/{id}` + a forced `must_change_password`).
- `admin.agents` is defined as a permission and agents can be
  enabled/disabled directly via the ORM/DB today; a dedicated
  `/api/v1/admin/agents` HTTP surface for it is not built yet (planned
  alongside Phase 8, when there's a UI that needs it).
- CSRF: state-changing endpoints authenticate via `Authorization: Bearer`
  header (not cookies), which is inherently not exploitable via classic
  CSRF. The two cookie-authenticated endpoints (`/auth/refresh`,
  `/auth/logout`) are scoped to `SameSite=Lax` and to the `/api/v1/auth`
  path; a dedicated CSRF token is not yet implemented for them and is a
  reasonable Phase 13 hardening item.
