# SOC Dashboard and UI (Phase 12)

## 1. Scope

Phases 1–11 built the platform behind an API. Phase 12 makes it operable
by a human: authentication, a live SOC overview, and a working view for
every capability the backend exposes. Fifteen routes, all real —
`ComingSoon` is gone from the codebase.

| Route | What it does |
|---|---|
| `/` | SOC overview: open alerts, open incidents, pending approvals, MTTx, volume chart, severity split, top hosts/users/rules |
| `/alerts`, `/alerts/[id]` | Triage queue; detail with evidence, status change, IOC enrichment, "Investigate with AI", promote to incident |
| `/incidents`, `/incidents/[id]` | Case list; detail with lifecycle transitions, IR metrics, NIST checklist, notes, indicators, containment actions, append-only timeline |
| `/ai`, `/ai/[id]` | Investigation list; full replayable agent trace with per-step evidence |
| `/hunting` | Hunt library, IOC pivot, results with truncation state, frozen query snapshot |
| `/threat-intel` | Indicator table, lookup, per-provider verdicts, cache state |
| `/mitre` | Coverage matrix, click-through to the rules behind a technique |
| `/cloud-iam` | Observed identities, cloud activity, attack-path graph with per-edge evidence |
| `/automation` | Response-action approval queue |
| `/lab` | Attack simulation scenarios with pass/gap results |
| `/audit` | Audit log with denial highlighting |
| `/admin` | Users, role changes, permission catalog |

## 2. One aggregation endpoint, not eight list calls

`GET /api/v1/dashboard/overview` returns the whole SOC picture in one
round trip. Having the page fire eight parallel list requests and count
rows client-side would be wrong twice over:

- **The counts would be page-size lies.** A dashboard reading "50 alerts"
  because that is the pagination limit is worse than showing nothing.
- **Security metrics would be computed somewhere the user can tamper
  with.**

Everything is a `COUNT`/`GROUP BY` inside the caller's tenant scope.
Nothing is cached: a SOC overview quietly ninety seconds stale gets acted
on ninety seconds late, and at this data volume the aggregates are cheap.

Gated on `alerts.read` — the narrowest permission every role that should
see an overview already holds. The payload contains only counts, never
row contents, so it cannot leak anything the caller could not already
list.

## 3. `null` is not `0`

The single most important rendering rule in this phase.

`mean_time_to_contain_seconds` is `null` when no incident closed in the
window. A dashboard that renders that as **"0s"** reads as flawless
performance when it actually means *nothing was contained*.

The backend returns `null`; `lib/format.ts::duration()` renders `null` as
an em dash and never as a zero; the overview tile shows "No incidents
closed in this window" as its hint. The distinction survives all the way
to the pixel, and the same rule applies to per-incident metrics and hunt
result counts.

## 4. Authentication

`lib/auth.ts` holds the access token in memory (zustand) mirrored to
**`sessionStorage`**, not `localStorage`: a token should not survive the
browser closing. The refresh token is never touched by JavaScript at all
— the backend sets it as an HttpOnly cookie, which is the whole point of
that design and would be defeated by reading it.

`AuthGate` renders the app chrome for an authenticated session and the
login form otherwise. **This is a rendering decision, not access
control.** Every request is authorized server-side against live database
role state, so a user who forced the component to render would see empty
panels and 401s. The comment in that file says so, to stop a later
contributor mistaking client routing for a security boundary.

A 401 from any call clears the session rather than silently refreshing —
hiding a revoked session behind a transparent retry is exactly what an
operator does not want.

## 5. Permission-aware UI, honestly labelled

The sidebar hides nav entries the signed-in role lacks the permission
for, and detail pages hide action buttons the same way. Both are **UX
affordances**: the route and its API remain enforced server-side, and the
sidebar's own footer text says navigation reflects your role while every
route is re-authorized.

Where a permission gap is meaningful, the UI says so rather than just
hiding the control — a pending response action shows "requires a SOC
manager" to a user who cannot approve it, because a silently missing
button looks like a bug.

## 6. Surfacing the platform's honesty in the interface

The properties the backend is careful about are only worth anything if
the UI does not flatten them:

- **Hunt results** show `complete over the window` or
  `scan bounded — this is a partial answer`, and expose the frozen query
  snapshot.
- **AI evidence** renders `source_tool` and the event id under every
  claim; a `conclude_rejected` step is labelled "rejected — citation did
  not resolve" rather than hidden.
- **Containment recommendations** carry a visible `requires approval`
  badge next to the action.
- **AI-authored incident notes** render with a bot icon and the words
  "AI-generated"; analyst notes say "Analyst".
- **Cloud `is_privileged`** renders as "privileged?" with a caption
  explaining it is inferred from naming.
- **Attack-path edges** show the truncation warning and the citing
  `cloud_event_id`.
- **Response execution** carries a standing note that execution is
  simulated and no EDR/IAM/firewall integration exists.
- **MITRE coverage** states that covered means "a shipped rule references
  this technique", not "this technique is mitigated".

## 7. Stack notes

Next.js 14 App Router, all data-fetching pages are client components
(`"use client"`) because they need the in-memory token. Tailwind with the
existing `soc-*` dark palette. Recharts for the one chart that earns
itself. `lucide-react` for icons. No component library — the shared
primitives in `components/ui/primitives.tsx` (Panel, Table, Badge,
SeverityBadge, StatusBadge, StatTile, Button, Select, TextInput,
Loading, EmptyState, ErrorState, KeyValue) are enough and keep the bundle
at ~88 kB shared JS.

Browser calls go to `/api/backend/*`, which `next.config.mjs` rewrites to
the backend's `/api/*` — same-origin, so no CORS and no preflight.

## 8. What this does not do

- **No websockets or live push.** Views refresh on navigation and on
  action, not on a socket.
- **No saved views, no bulk triage, no dark/light toggle** — the platform
  is dark-only by design.
- **No client-side test suite.** The frontend is verified by
  `tsc --noEmit` and a production `next build`; behavioural coverage
  lives in the backend suite against the same API the UI calls.
- **No accessibility audit.** Semantic HTML and focus states are used
  throughout, but no formal WCAG pass was done.
