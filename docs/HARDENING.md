# Hardening and Deployment Posture (Phase 15)

## 1. Fail closed in production, warn loudly in development

A platform whose entire value proposition is *"privileged actions require
a human"* cannot also boot happily with a placeholder signing key.
Anyone who can forge a token **is** that human as far as the API is
concerned, and every other control in this repository — RBAC, tenant
scoping, the approval state machine, the agent tool gateway — is
downstream of token authenticity.

So `app/core/hardening.py::run_startup_checks` runs **before the first
request**, called at import time in `app/main.py`, and sorts findings
into two kinds:

**Fatal** — the deployment is not safe to serve traffic:

| Check | Why |
|---|---|
| `JWT_SECRET_KEY` unset, placeholder, or < 32 chars | Every access token would be forgeable |
| `DEBUG=true` | Tracebacks and internal detail served to callers |
| `DATABASE_URL` still contains the `.env.example` placeholder password | Nobody set a real one |
| `CORS_ORIGINS` contains `*` | The API replies with credentials; a wildcard lets any site read them |

In `ENVIRONMENT=production` these raise `InsecureDeploymentError` and the
process exits. In development they are logged as
`insecure_configuration_would_be_fatal_in_production` and the app starts
— a developer running `uvicorn --reload` against a local Postgres should
not have to invent a 48-byte secret to see the login page.

**Advisory** — worth flagging anywhere, not a reason to refuse to start:
plaintext-HTTP CORS origins (localhost excepted), access-token lifetimes
over two hours, `THREAT_INTEL_MODE=live` with no provider key,
`AI_PROVIDER=openai_compatible` with no `AI_API_KEY`, and
`ADMIN_BOOTSTRAP_PASSWORD` present in the process environment.

Nothing tries to guess whether a secret is "strong enough" beyond a
length floor and the placeholders this repo itself ships. A check that
scores entropy gives false confidence.

## 2. Response headers

Applied to **every** response, including 401s and 500s — a rejected
request is exactly when a browser most needs them:

| Header | Value |
|---|---|
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | `geolocation=(), microphone=(), camera=()` |
| `Content-Security-Policy` | `default-src 'none'; frame-ancestors 'none'` |
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains` *(production only)* |

The CSP is maximally restrictive because it can be: the API serves JSON
only, renders no HTML and loads no subresources. It costs nothing and
blunts any future response that accidentally reflects caller-controlled
content.

## 3. Interactive docs are disabled in production

`/api/docs`, `/api/redoc` and `/api/openapi.json` are served only when
`ENVIRONMENT != production`. They enumerate every route, parameter and
schema — genuinely useful in development, gratuitous reconnaissance
surface in production.

## 4. `.gitignore`

The repository had **no `.gitignore` at all** through Phases 1–14. With a
real `backend/.env` on disk carrying the JWT signing key, the database
password, and any provider keys, that is one `git add .` away from a
leaked signing key.

Secrets are the first section of the file, on purpose: `.env`, `.env.*`
(with `!.env.example` re-included, since the template must stay
committed), `*.pem`, `*.key`, `*.p12`, `*.pfx`, `secrets.json`,
`credentials.json`. Then the ordinary Python/Node/cache/build exclusions.

`test_hardening.py::test_gitignore_excludes_env_files_but_keeps_the_template`
asserts this, so deleting the file breaks the build rather than passing
silently.

## 5. Secret handling, end to end

- **Config**: every credential is read from the environment via
  pydantic-settings. No secret has a working default; `JWT_SECRET_KEY`
  defaults to an obvious `CHANGE_ME` placeholder and every provider key
  defaults to `None`. A test asserts this.
- **At rest**: passwords are Argon2id hashes. Refresh tokens are stored
  as SHA-256 hashes, never raw.
- **In transit to the client**: the refresh token is an HttpOnly cookie
  that JavaScript never reads; the access token lives in
  `sessionStorage`, so it does not survive the browser closing.
- **In logs**: no secret is logged. Threat-intel provider responses pass
  through `_redact()` before persistence, stripping anything key-shaped
  recursively.
- **In responses**: a test asserts no endpoint returns a hash, an
  `$argon2` string, or the caller's own password.

## 6. Bounds that keep the platform from harming itself

| Bound | Setting / constant |
|---|---|
| Agent loop iterations | `AI_MAX_TOOL_ITERATIONS` (12) |
| Hunt scan + result caps | Phase 7 engine, with truncation declared |
| Attack-path depth and per-identity actions | `MAX_DEPTH` (6), `MAX_ACTIONS_PER_IDENTITY` (25) |
| Enrichment cache TTL | `ENRICHMENT_TTL_HOURS` (24), failures 15 min |
| Ingest batch size | 500 events |
| List page size | 500 max, enforced by `Query(le=…)` |
| Per-IP rate limits | `RATE_LIMIT_DEFAULT`, `RATE_LIMIT_AUTH` |
| Login attempts / lockout | `MAX_FAILED_LOGIN_ATTEMPTS`, `ACCOUNT_LOCKOUT_MINUTES` |

## 7. Documentation completeness

Phase 15 also closed the documentation gap: every phase now has a doc
that explains not just what was built but **which alternative was
rejected and why**. That is the part worth reading — the design
decisions this platform makes are mostly refusals.

## 8. Honest remaining gaps

Stated rather than quietly omitted:

- **Response execution is simulated.** No EDR, IAM, or firewall
  integration exists; `result.simulated` is always `true`. The approval
  state machine and its audit trail are real.
- **Single-tenant in practice.** Every table and query is tenant-scoped
  and tested against a second organization, but a deployment seeds one
  `Organization`. `TenantScopedMixin.organization_id` is still nullable;
  making it non-nullable is the remaining step.
- **No secret manager integration.** Secrets come from the environment,
  not from Vault/KMS/Secrets Manager.
- **No key rotation procedure.** Rotating `JWT_SECRET_KEY` invalidates
  every session at once; there is no dual-key grace window.
- **No MFA, SSO, or SCIM.** Password + JWT only.
- **No outbound email**, so no password-reset-by-email and no alert
  notification channel.
- **No dependency vulnerability scanning or SBOM** in CI — there is no CI
  pipeline in this repository at all.
- **No infrastructure hardening.** `docker-compose.yml` is a development
  topology: no TLS termination, no network policy, no read-only
  filesystems, no non-root container users beyond what the base images
  provide.
- **Audit log has no cryptographic integrity.** It is append-only by
  application design (no write route, no update path), not by hash
  chaining or a WORM store — a database superuser could still alter it.
- **No log shipping or retention policy.**

## 9. Test coverage

`backend/tests/test_hardening.py` — 17 tests: a correctly configured
production deployment passing cleanly, each fatal finding individually,
production actually refusing to start, development starting anyway, each
advisory finding, security headers on both a normal and a rejected
response, and the `.gitignore` guarantee.
