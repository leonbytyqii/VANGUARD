# MITRE ATT&CK Catalog & Coverage Matrix (Phase 6)

## 1. Why a curated dataset, not the full STIX bundle

The real MITRE ATT&CK Enterprise matrix ships as a ~10MB STIX 2.1 bundle
with hundreds of techniques/sub-techniques, dozens of relationship types,
and a `technique -> tactic` mapping that is genuinely many-to-many (a
single technique can appear under several tactics depending on how it's
used). Importing that whole bundle for a platform whose detection library
currently covers 19 distinct technique IDs would mean carrying a large,
mostly-unused dataset and building a general-purpose STIX parser for
marginal benefit at this project's scale — the same trade-off already
made for the Sigma engine in Phase 4 (see `docs/DETECTION_ENGINE.md` §1
for why that's a self-written interpreter, not pySigma).

Instead, `backend/app/mitre/data.py` hand-curates:

- **All 14 real Enterprise ATT&CK tactics**, with their real `TAxxxx`
  IDs and ATT&CK's own canonical ordering (`matrix_order` 1–14,
  Reconnaissance through Impact) — nothing invented here, this is the
  actual matrix column order.
- **49 real techniques/sub-techniques**, each with its real `Txxxx[.xxx]`
  ID, name, and description, verified by
  `test_every_detection_registry_technique_id_is_in_the_seeded_catalog`
  to be a strict superset of every technique ID any shipped detection
  references (19 distinct IDs as of Phase 6), plus enough additional
  breadth that all 14 tactics have at least one seeded technique.

This is an explicit, documented scope reduction, not a hidden gap: a new
detection that cites a MITRE technique ID outside the curated set fails
that data-integrity test loudly at CI time, rather than silently
producing an alert with a dangling MITRE tag at runtime. Growing the
catalog is a one-line addition to `TECHNIQUES` in `data.py`, no schema or
migration changes required.

## 2. The single-tactic-per-technique simplification

Real ATT&CK technique-to-tactic mapping is many-to-many — for example,
T1078 (Valid Accounts) legitimately appears under Initial Access,
Persistence, Privilege Escalation, *and* Defense Evasion depending on how
an adversary uses a compromised credential. `app/models/mitre.py`
deliberately models one primary tactic per technique
(`MitreTechnique.tactic_id`, a single FK) rather than a second M2M join
table for tactic membership.

This is stated as a simplification, not silently gotten wrong: both
`app/models/mitre.py`'s class docstring and `app/mitre/data.py`'s module
docstring call it out, and the two techniques in the curated set with the
most real-world tactic ambiguity — T1078 (Valid Accounts) and T1550 (Use
Alternate Authentication Material) — are explicitly commented at their
`data.py` definition explaining which one tactic (Defense Evasion) was
picked and why. If a future phase needs true multi-tactic membership, it
is a schema-additive change (a new join table) rather than a rewrite —
nothing downstream assumes single-tactic membership beyond the coverage
matrix's column grouping.

## 3. Two representations of rule-to-technique tagging, kept in sync

`DetectionRule` carries MITRE tags two ways, and Phase 6 keeps both
consistent rather than replacing one with the other:

1. **`mitre_technique_ids: list[str]`** (JSON column, existed since
   Phase 1/4) — cheap to read with no join, used inside
   `evidence["mitre_technique_ids"]` on every alert for quick display.
2. **`mitre_techniques` relationship** (new in Phase 6, via the
   `detection_rule_mitre_techniques` many-to-many table) — real
   queryability: "every rule that covers Credential Access" is a join,
   not a string search over a JSON array.

`app/mitre/seed.py::link_detection_rules_to_techniques` is the function
that keeps them in sync: for every `DetectionRule`, it resolves the
strings in `mitre_technique_ids` against the seeded catalog and sets the
relational list to match. A technique ID referenced by a rule but not
found in the catalog is logged as a structured warning
(`mitre_technique_ids_not_in_catalog`) rather than raising — verified
empty against the real shipped rule set by
`test_detection_rules_are_relationally_linked_to_their_techniques`, but a
warning (not a hard failure) is the right posture for sync code that runs
on every deploy, the same reasoning `sync_detection_rules` (Phase 4) and
`seed_agent_identities` (Phase 2) already follow.

## 4. Alert tagging

`app/services/alerting.py::generate_alerts_for_detections` sets
`Alert.mitre_techniques = list(rule.mitre_techniques)` when creating a new
alert, and **merges** (`existing.mitre_techniques | rule.mitre_techniques`,
deduped) rather than overwrites when a re-firing rule reinforces an
existing open alert (§2 of `docs/RISK_SCORING.md` covers the
dedup/reinforcement mechanics this hooks into). The raw JSON IDs also stay
in `evidence["mitre_technique_ids"]` for cheap display — the same
kept-in-sync-not-replaced pattern as §3.

`GET /api/v1/alerts` exposes the relational tags as
`AlertOut.mitre_technique_ids: list[str]`, populated by a small
`_serialize_alert()` helper in `app/api/v1/alerts.py` that extracts
`technique_id` strings from the ORM relationship after
`AlertOut.model_validate(alert)` — Pydantic's `from_attributes` can't
auto-map an ORM relationship of `MitreTechnique` objects onto a
`list[str]` field, so this is done explicitly rather than fought via
schema tricks.

## 5. Sync mechanics

`app/mitre/seed.py::sync_mitre_catalog(db)` idempotently upserts by
natural key (`tactic_id` / `technique_id`), matching the pattern already
established by `seed_permissions`/`seed_roles`/`seed_agent_identities`
(Phase 2) and `sync_detection_rules` (Phase 4). It runs in two passes:

1. Create-or-update every `MitreTactic` row, then every `MitreTechnique`
   row (name/description/tactic_id), without yet resolving sub-technique
   parentage.
2. A second pass resolves `MitreTechnique.parent_technique_id` for every
   technique that declares one in `data.py`.

The two-pass split means `TECHNIQUES`' declaration order in `data.py`
never has to guarantee a parent technique is listed before its
sub-techniques — `test_mitre_sync_is_idempotent` and
`test_subtechnique_parent_linkage_resolved` cover both the idempotency and
the parent-resolution behavior directly.

`app/db/seed.py::seed_all()` calls `sync_mitre_catalog` then
`link_detection_rules_to_techniques` after `sync_detection_rules`, so a
fresh environment (or `docker compose up` from empty volumes) ends up with
a fully-populated, fully-linked catalog with no manual step.

## 6. API surface

All endpoints live under `/api/v1/mitre` (`backend/app/api/v1/mitre.py`),
gated by a new `mitre.read` permission — granted to every role, including
`viewer` (`backend/app/core/permissions.py`). This catalog and the
detection-rule library are shared reference data, identical across every
tenant, so — unlike almost everything else in this platform —
these endpoints are **deliberately not** run through `scoped_query`;
there is nothing organization-specific to scope.

- **`GET /mitre/tactics`** — all 14 tactics, ordered by `matrix_order`,
  each with `technique_count` and `covered_technique_count` computed
  in-process.
- **`GET /mitre/techniques`** — filterable list: `tactic_id` (404 if
  unknown), `covered_only: bool`, and free-text `q` (case-insensitive
  substring match against name or technique ID).
- **`GET /mitre/techniques/{technique_id}/coverage`** — 404 if the
  technique ID isn't in the catalog, else the list of `DetectionRule`s
  relationally linked to it.
- **`GET /mitre/matrix`** — the full coverage-matrix shape: tactic
  columns (in `matrix_order`) each containing technique cells
  (`technique_id`, `name`, `is_subtechnique`, `parent_technique_id`,
  `covered`, `detection_rule_ids`), plus `total_techniques`,
  `covered_techniques`, and `coverage_pct` — the exact data contract the
  Phase 12 dashboard's ATT&CK heat-map view will render directly, no
  reshaping needed.

As of Phase 6, hitting `/mitre/matrix` against the seeded dev database
returns 14 tactics, 49 total techniques, 19 covered, and a 38.8% coverage
percentage — matching what `test_matrix_shape_and_coverage_percentage`
asserts by independently recomputing the same numbers from
`DETECTION_REGISTRY`.

## 7. What's explicitly deferred

- **Tactic/technique-weighted risk scoring** — `docs/RISK_SCORING.md` §1
  already calls out that MITRE-aware scoring was deferred pending a real
  ATT&CK catalog; now that one exists, a next-phase enhancement could add
  a small bonus for techniques in historically-higher-severity tactics
  (e.g. Credential Access, Lateral Movement) — not built in Phase 6 to
  keep this phase's scope to the catalog and coverage API themselves.
- **Frontend rendering** — `frontend/app/mitre/page.tsx` still renders the
  `ComingSoon` placeholder from the Phase 1 scaffold. The data model and
  API contract this doc describes are real and tested; wiring the
  dashboard's ATT&CK heat-map view against them is Phase 12 per the
  project's established frontend-last-per-phase division of labor (the
  same reasoning `alerts`/`detections` pages follow until their phases'
  dashboard work lands).
- **True multi-tactic technique membership** — see §2.
