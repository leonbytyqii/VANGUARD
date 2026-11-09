# Security Policy

## Supported versions

VANGUARD is currently in pre-release development. The `main` branch is the only actively maintained version.

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.**

To report a security issue in VANGUARD:

1. Email **leonbytycii@gmail.com** with the subject line `[VANGUARD SECURITY] <brief description>`.
2. Include: a description of the vulnerability, steps to reproduce, affected component, and your assessment of impact.
3. You will receive an acknowledgement within 72 hours.
4. We will work with you on a timeline for disclosure and credit.

We follow coordinated disclosure: please give us reasonable time to investigate and patch before public disclosure.

## Security architecture

VANGUARD's core security model is documented in `docs/SECURITY.md` and `docs/ARCHITECTURE.md`. Key properties:

- **AI agents have zero privileged execution.** No action that isolates a host, disables an account, blocks an IP, or revokes a credential is reachable through the AI tool registry.
- **Every AI conclusion must be grounded in retrieved evidence.** The evidence validation gate rejects any citation that was not retrieved via a real tool call in the current investigation session.
- **Human approval is mandatory for every consequential response action.**
- **Tenant isolation is enforced server-side** via organization-scoped queries; a client cannot access another tenant's data regardless of what it sends.
- **Prompt injection is contained** by explicit system prompt guards and by the tool registry boundary.

Security findings related to these properties are treated as the highest priority.

## Out of scope

- Vulnerabilities in dependencies that do not affect VANGUARD's deployed attack surface.
- Issues that require an authenticated admin account with no other constraint (admin-only paths are explicitly privileged).
- Theoretical issues with no plausible attack scenario.
- Denial of service by resource exhaustion (rate limiting is implemented but tunable).
