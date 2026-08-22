# Attack Simulation Lab (Phase 14)

## 1. What a "simulation" means here

**Synthetic telemetry describing an attack — never an attack.**

Nothing in this phase executes a command, drops a file, opens a socket,
or touches the machine it runs on. A scenario is an ordered list of event
payloads. Adding one that shells out would turn a SOC training tool into
malware, and `test_scenarios_contain_no_executable_instructions` exists
to make that intent enforceable rather than merely stated.

## 2. Why it replays through the real ingestion path

`run_scenario` submits each payload through
`app.services.ingestion.service.ingest_event` — the same adapters, the
same normalization, the same synchronous detection sweep, the same risk
scoring, the same alert dedup, the same Phase 11 cloud projection.
**Nothing is written directly into `detections` or `alerts`.**

A demo that inserts pre-baked alerts proves nothing about the detection
engine. A demo that replays realistic telemetry and lets the engine find
it is an end-to-end test of the whole platform that a person can watch
happen.

The consequence is the valuable part: **a scenario that stops firing is a
regression signal.** `tests/test_lab.py` runs every shipped scenario and
asserts each one still produces the detections it claims, which makes
this phase a regression harness for Phases 3–5 and 11 as much as a demo.

## 3. Honest results

A run reports which of its `expected_detections` actually fired
(`detections_fired`), which did not (`missing_detections`), and anything
else that fired (`unexpected_detections`).

`fully_detected` is false if anything is missing. **Ingestion succeeding
tells you nothing about whether detection worked**, so reporting
"success" because events were accepted would be the wrong answer to the
question a person clicking "Run" is asking. The UI renders each expected
rule green or red individually.

## 4. Timing: anchored to the end, not the start

`start_time` defaults so the scenario's **last** event lands now, rather
than its first.

Correlation detections look back over windows ending at the present. A
scenario whose events were spread forward over the next twenty minutes
would sit in the future and never correlate — the brute-force burst would
not be a burst, the C2 beacons would not be repeated. Anchoring the end
is what makes a replay behave the way real telemetry does.

## 5. Safety constraints on scenario data

Same rules as the threat-intel sample feed, and tested the same way:

- IPv4 only from RFC 5737 documentation ranges, RFC 1918 private space,
  or loopback.
- Domains only from RFC 2606 reserved TLDs (`.invalid`, `.test`).
- Hostnames obviously fictional (`SIM-*`).
- Every generated event is tagged `simulated: true` with its
  `scenario_id` and step index inside `raw_event`, so synthetic telemetry
  stays distinguishable from real telemetry permanently.

## 6. The scenario library

| Scenario | Exercises | Expected detections |
|---|---|---|
| `encoded_powershell_c2` | Sigma + DNS + outbound correlation together | `sigma_suspicious_powershell_encoded`, `sigma_powershell_spawned_by_office`, `custom_suspicious_outbound_port` |
| `credential_access_lsass` | LSASS memory read | `sigma_credential_access_lsass` |
| `ssh_brute_force` | Failed-auth burst then success | `custom_brute_force_login` |
| `dga_beaconing` | High-entropy domain run | `custom_dns_anomaly_dga` |
| `lateral_movement` | SMB fan-out to many hosts | `custom_lateral_movement_fanout` |
| `cloud_privilege_escalation` | AssumeRole → AttachRolePolicy → CreateAccessKey → StopLogging | `custom_cloud_privilege_escalation_chain` |
| `impossible_travel` | Same account, incompatible source IPs | `custom_impossible_travel_proxy` |
| `persistence_scheduled_task` | Logon-triggered scheduled task | `sigma_persistence_scheduled_task` |

`cloud_privilege_escalation` is the widest: it drives the Phase 4
detection, the Phase 11 `cloud_events` projection, the derived
`cloud_identities`, and a reconstructable IAM attack path from one run.

## 7. Why the lab is admin-only

Gated on `events.ingest`, which by default only `admin` holds.

A scenario run produces **real detections, real alerts, and real
incident-worthy noise in the same tables an analyst is working from.**
Letting any analyst manufacture alerts would make the alert queue
untrustworthy as a record of what actually happened. Every run is
audited (`lab_scenario_run`) with its outcome and any missing detections,
because it manufactures evidence.

## 8. A bug this phase caught

`Detection.rule_id` is a **UUID foreign key** into `detection_rules`; the
human-readable identifier a scenario declares lives on
`DetectionRule.rule_id`. The first implementation compared
`Detection.rule_id` directly against rule-name strings — which never
matched, and additionally put a `UUID` into an audit-log JSON column,
where it failed to serialize.

The fix is a join, and the code comment says why, because the two
same-named fields on related tables are an easy trap to fall into twice.

## 9. API surface

| Method | Path | Permission |
|---|---|---|
| GET | `/lab/scenarios` | `events.ingest` |
| POST | `/lab/scenarios/{id}/run` | `events.ingest` |

## 10. What this does not do

- **No cleanup or reset.** Generated events, detections and alerts stay
  in the database like any other telemetry. They are tagged, so they can
  be identified, but there is no "undo run" — deleting evidence on
  request is not a capability this platform should have.
- **No custom scenario authoring** through the API. Scenarios are code,
  reviewable in a diff, which is the right shape for something that
  manufactures evidence.
- **No adversary-emulation framework integration** (Atomic Red Team,
  CALDERA). Those execute real techniques on real hosts; this
  deliberately does not.
- **No timing realism beyond relative offsets** — no jitter, no
  business-hours modelling.

## 11. Test coverage

`backend/tests/test_lab.py` — 24 tests: scenario-data integrity (unique
ids, every expected rule real, every MITRE id seeded, no real address or
domain, bounded offsets), one parametrised end-to-end run **per
scenario** asserting its detections fire, alert creation through the
normal path, permanent synthetic tagging, the cloud projection, tenant
isolation, the API, admin-only access across all four non-admin roles,
and audit coverage.
