# Attack Simulation Lab

`simulations/` will hold scripts that generate **synthetic telemetry** —
JSON events posted to `POST /api/v1/events` — that looks like a real attack
technique occurred (brute force, encoded PowerShell, privilege escalation,
persistence, lateral movement, cloud IAM anomalies, ...). These scripts do
not perform real exploitation and never target systems outside this
platform's own database.

`sample_logs/` will hold static example log batches (Sysmon, Linux auth,
DNS, firewall, CloudTrail-style) for local testing and detection-engine
unit tests.

Each simulation will document, per the master spec:

```
Attack Simulation → Expected Telemetry → Expected Detection →
Expected Alert → Expected MITRE Technique → Expected AI Analysis
```

Populated starting in Phase 14, once ingestion (Phase 3) and detection
(Phase 4) exist to validate against. See `docs/LAB.md` when that phase lands.
