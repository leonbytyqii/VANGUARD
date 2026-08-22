# Detections

- `sigma/` — Sigma rule YAML files (loaded by `backend/app/detections/sigma_engine`).
- `custom/` — custom Python detection modules and behavioral/correlation rule
  definitions that don't map cleanly to Sigma's single-event model (e.g.
  "10 failed logins + 1 success + new privileged session").

Populated starting in Phase 4 (Detection Engine). See
`docs/DETECTION_ENGINE.md` for the rule format and risk-scoring contract
once that phase lands.
