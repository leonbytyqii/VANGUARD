# Security Testing (Phase 13)

## 1. What makes this different from the other test files

Every other test file asks *"does this feature work?"*. This one asks
*"can I break the security model?"*, and it is organised by **attacker
goal** rather than by module — the same way `docs/SECURITY.md`'s threat
model is organised, and the way a reviewer will read it.

`backend/tests/test_security.py` — 67 tests across seven goals.

## 2. The two rules that kept it honest

**1. Every test must be able to fail.** A test asserting a boundary
nothing could ever cross proves nothing and provides false comfort. Where
a control is *structural* — a tool that is not in a registry, a route
that does not exist — the test asserts the absence directly, so deleting
the control breaks the test:

```python
for action_type in PRIVILEGED_ACTION_CATALOG:
    assert action_type not in TOOL_REGISTRY
```

Add `isolate_host` to the registry and this fails immediately. That is
the property a security test needs.

**2. Nothing duplicates a feature test.** Where an existing file already
proves a boundary, this one attacks it from a different direction — a
different actor, a different entry point, or a composition of two
features that are each safe alone.

## 3. The seven goals

### Goal: execute something privileged without a human

- No `PRIVILEGED_ACTION_CATALOG` entry appears in `TOOL_REGISTRY`; no
  registry tool is classified `privileged_action`.
- No agent's `max_effect` permits `privileged_action`.
- **Every allowlisted tool exists and is within its agent's ceiling** —
  catches a renamed tool silently doing nothing, or an allowlist widened
  past its declared ceiling.
- Parametrised over *every* agent × *every* privileged action: all
  refused with reason `tool_not_registered`.
- An agent files a request and then cannot approve it — asserted by
  showing no registry tool is named like an approver or executor, and the
  row stays `pending`.
- **Execution requires approval at the service layer, not just the
  route** — calling `execute_response_action` directly still 409s.
- **A superuser flag does not bypass the state machine.**

### Goal: read another tenant's data

- No list endpoint (alerts, events, incidents, IOCs, cloud identities, AI
  investigations, hunt executions, response actions) returns another
  tenant's rows.
- **Cross-tenant reads are indistinguishable from nonexistent ones** —
  the test asserts the two responses are byte-identical, because a
  different status code would let an attacker enumerate ids.
- Agent tools stay tenant-scoped even when handed another tenant's
  hostname, so a prompt-injected argument cannot widen a read.

### Goal: escalate privilege within a tenant

- Lower roles cannot reach admin endpoints.
- An analyst cannot promote themselves by PATCHing their own user.
- **A revoked permission takes effect on the very next request** with the
  same token — the test that proves the JWT's `perms` claim is
  decorative and enforcement reads live database state.
- The permission catalog and role grants are internally consistent (no
  role granted a nonexistent permission, no duplicates).
- **Role grants are monotonic**: `analyst ⊆ manager ⊆ admin`. A manager
  who cannot do something their analyst can is an
  escalation-by-delegation bug waiting to happen.
- Viewer holds no write-shaped permission (`.create`, `.update`,
  `.approve`, `.manage`, `.ingest`, …).

### Goal: forge or replay authentication

Wrong signing key; **token type confusion** (a refresh token presented as
an access token); expired token; a token for a user deactivated
mid-session; a token whose subject does not exist; malformed
`Authorization` headers; and login responses being byte-identical for
"wrong password" and "no such user".

### Goal: tamper with the record

- **No write route exists for the audit log** (all four verbs).
- **No write route exists for an incident timeline** (all four verbs).
- A permission denial is recorded with the actor, the exact route, and
  the permission that was missing.
- A refused *agent tool call* is audited with its refusal reason.

### Goal: make the AI assert something unsupported

- A citation that does not resolve is rejected by the orchestrator's
  validator.
- **`requires_approval` cannot be set to `False`** — a `ValidationError`,
  because the schema types it `Literal[True]`.
- No agent tool can write to the case file or the alert queue: agents
  gained *read* access to incidents in Phase 9 and to cloud telemetry in
  Phase 11, and neither may become write access.
- A human cannot post an AI-attributed note.

### Goal: abuse input, exhaust resources, find a secret

- Unknown source, missing adapter-required field, and an over-cap batch
  are all rejected.
- **SQL-shaped input is treated as data** — asserted behaviourally, so it
  would catch a future hand-rolled query, not just today's ORM.
- **A hunt condition cannot execute code**: `__import__`, attribute
  access, `open()`, and a lambda call are each refused by the restricted
  AST walker.
- Unicode and zero-width characters in a hostname do not break ingestion.
- No endpoint leaks a hash or a secret — and the check deliberately does
  *not* grep for the bare word "password", because `must_change_password`
  is a legitimate field; it looks for `hashed_password`, `$argon2`,
  `jwt_secret`, and the caller's actual password string.
- **Settings contain no baked-in production secret**: the JWT default is
  a `CHANGE_ME` placeholder and every provider key defaults to `None`.
- Provider `raw_response` is redacted of key-shaped material.
- Every list endpoint enforces a maximum page size and rejects negative
  pagination.
- The agent loop is bounded (`AI_MAX_TOOL_ITERATIONS`), so the platform
  cannot DoS itself.

## 4. Findings this phase produced

Writing adversarially found two real problems, both fixed:

1. **`ResponseAction.incident_id` was accepted unvalidated** (found while
   building Phase 9, hardened there). Harmless while nothing read the
   field; a cross-tenant *write* the moment Phase 9 started mirroring
   actions onto incident timelines.
2. **`cloud_events` had no tenant column** and the obvious scoping key
   (`account_id`) is shared between tenants in a managed-service
   deployment. Fixed by joining through `events.organization_id`, with a
   dedicated test that fails if the join is "simplified" away.

Both are the kind of bug that only shows up when you ask "who else could
reach this?" rather than "does this work?".

## 5. What this phase is not

- **Not a penetration test.** No fuzzing, no dependency CVE scanning, no
  DAST, no infrastructure review. Those need tooling and an environment
  this repository does not include.
- **Not a substitute for the per-phase RBAC/IDOR tests.** Those cover
  breadth across every endpoint; this covers depth against the model.
- **No load or stress testing.** Resource limits are asserted to *exist*,
  not measured under pressure.
