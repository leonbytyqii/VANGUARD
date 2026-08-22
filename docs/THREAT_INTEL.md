# Threat Intelligence Enrichment (Phase 10)

## 1. The one rule this phase is built around

**An indicator nobody has scored is `unknown`, never `clean`.**

Every design decision below follows from that. Collapsing "no provider
has an opinion" into "checked, it's fine" is the threat-intelligence
equivalent of the AI fabricating evidence — it manufactures a reassuring
answer out of an absence of data, and an analyst who triages on it will
close a real incident. `IOCReputation` has four values for exactly this
reason, and `ProviderResult.failure()` returns `unknown` with zero
confidence, never `clean`.

## 2. Provider abstraction

`app/threat_intel/providers/base.py` mirrors the Phase 8 LLM provider
abstraction, for the same reason: the platform depends on an interface,
not a vendor.

**Every provider is contractually non-raising.** A timeout, a rate
limit, or a malformed response comes back as a `ProviderResult` with
`lookup_failed=True` and a reason. Enrichment is called from an
ingestion-adjacent path and from an AI tool handler; a provider outage
must degrade the answer, not take down the request.

| Provider | Types | When active |
|---|---|---|
| `LocalFeedProvider` | ip, domain, url, file_hash | **always**, including live mode |
| `AbuseIPDBProvider` | ip | `THREAT_INTEL_MODE=live` + `ABUSEIPDB_API_KEY` |
| `VirusTotalProvider` | ip, domain, url, file_hash | `THREAT_INTEL_MODE=live` + `VIRUSTOTAL_API_KEY` |
| `OTXProvider` | ip, domain, file_hash | `THREAT_INTEL_MODE=live` + `OTX_API_KEY` |

`supported_types` means a provider is *skipped* rather than asked a
question it cannot answer — an IP-reputation service is never queried
about a file hash and billed for it.

The local provider stays in the chain in live mode on purpose: it costs
nothing, needs no network, and its curated entries are what the Phase 14
lab scenarios resolve against. Dropping it the moment an operator adds an
API key would silently break the demo path.

### Vendor thresholds are visible, not buried

`ABUSEIPDB_MALICIOUS_AT`, `VT_MALICIOUS_AT`, `OTX_MALICIOUS_AT` and their
`SUSPICIOUS` counterparts are module-level constants in
`providers/live.py`. They are tuning decisions a SOC will want to argue
with, not implementation details.

### Keys never reach storage

`_redact()` strips anything key-shaped (`apikey`, `authorization`,
`token`, …, recursively) from a provider response before it is persisted
into `threat_intelligence.raw_response`. None of these APIs echo
credentials today; a stored JSON blob is exactly where a leaked one would
sit unnoticed, so it is stripped on the way in rather than trusted not to
be there.

## 3. The offline feed, and why almost everything is `unknown`

`app/threat_intel/sample_feed.py` ships ~16 curated indicators. **Every
one is synthetic**: IPv4 only from RFC 5737 documentation ranges
(`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), domains only from
RFC 2606 reserved TLDs (`.invalid`, `.test`), hashes hand-constructed.

That constraint is deliberate rather than fussy. A demo feed seeded with
realistic-looking public IPs would mean this repository ships a file that
labels somebody's actual infrastructure as malicious — wrong on its own
terms, and actively harmful if it ever leaked into a real blocklist.
Reserved ranges cannot belong to anyone. `test_threat_intel.py` asserts
this property, so a future contributor cannot casually add a real address.

The rejected alternative was hashing an unknown indicator into a
pseudo-random verdict so demos look lively. That manufactures threat
intelligence out of nothing, which is the same failure mode this platform
refuses everywhere else.

**The one thing the offline provider asserts without the feed** is that
private, loopback and link-local addresses are `clean` — and the payload
carries an explicit caveat saying this is a statement about *routability*
(no public feed could ever have an opinion on `10.0.0.5`), not about the
host being safe. An attacker's foothold is usually on RFC 1918 space.

### The documentation-range trap

`ipaddress.IPv4Address.is_private` returns **True** for the RFC 5737
documentation ranges — correct about the real internet, wrong for this
platform, where those ranges stand in for external attacker
infrastructure. Naively trusting it produced two real bugs during this
phase: the extractor silently discarded every indicator in the lab
scenarios, and the offline provider reported known C2 addresses as
"clean".

`app/threat_intel/addressing.py` is the single shared answer, used by
both the extractor and the provider so they cannot disagree, and it
documents the trade-off rather than hiding it.

## 4. Aggregation

`app/threat_intel/registry.py::aggregate` folds several providers into
one verdict and a 0–100 score:

1. **Failed lookups are excluded from the verdict** but still stored. A
   provider that could not be reached has not voted.
2. **Only results at or above `MIN_CONFIDENCE` (0.5) vote.** A provider
   20% sure something is malicious has not established that it is.
3. **The worst confident verdict wins** — deliberately *not* a majority
   vote. Three feeds with no data and one confirmed C2 match is
   "malicious", not "mostly clean". False negatives cost more than false
   positives in triage, and every per-provider row is retained so an
   analyst can see the disagreement.
4. `threat_score` = winning verdict's weight × its confidence × 100.
5. **No confident verdict → `unknown`, score 0.** Never `clean`.

## 5. Caching, and why verdicts expire

Enrichment is the one operation in this platform that costs money per
call and consumes somebody else's rate limit, so a non-expired
`ThreatIntelligence` row is reused rather than re-queried.

- Successful verdicts live `ENRICHMENT_TTL_HOURS` (24). **A verdict is a
  point-in-time observation, not a permanent property**: an IP that was
  clean last month is not evidence that it is clean now.
- Failed lookups expire after `FAILED_LOOKUP_TTL_MINUTES` (15) — a
  provider being down for a minute must not blind the platform to that
  indicator for a day.
- `from_cache` is part of the **API response**, not an internal detail.
  An analyst acting on a verdict is entitled to know whether a provider
  was just asked or whether this is a twenty-hour-old answer.

`force_refresh` is gated behind `threat_intel.manage` rather than
`threat_intel.lookup`, because a cache bypass spends a real, shared
quota and needs an actor accountable for it.

## 6. Extraction from evidence

`app/threat_intel/extraction.py` projects *already-normalized* event
fields (`src_ip`, `dst_ip`, `domain`, `url`, `file_hash`) — it does not
regex-sweep `raw_event`. Phase 3's adapters already decided which field
is a destination IP; re-deriving that from free text would produce
indicators the platform cannot explain the provenance of. Every extracted
IOC records the `source_field` it came from.

Alert enrichment is scoped to `alert.related_event_ids` — the evidence
the detection engine actually used — not to "every event on that host",
so an enriched indicator always traces back to something the alert
genuinely rests on.

Non-routable addresses are skipped: an internal 10.x host is a real and
important artefact, but it is not an *indicator* — no external feed can
score it, and tracking thousands of them would bury the handful that
matter.

## 7. Tenancy

`iocs` is unique on `(organization_id, ioc_type, value)`. One
organization observing `203.0.113.7` says nothing about whether another
has, so the same indicator in two tenants is two independent rows with
independent enrichment histories. Losing the insert race is handled by
re-reading the winner, not by failing the caller — the unique constraint
is the authority, not the read that preceded it.

## 8. API surface

| Method | Path | Permission |
|---|---|---|
| GET | `/threat-intel/iocs` (filters: type, reputation, min_score, active_only, search) | `threat_intel.lookup` |
| POST | `/threat-intel/iocs` | `threat_intel.manage` |
| POST | `/threat-intel/lookup` | `threat_intel.lookup` (+`.manage` for `force_refresh`) |
| GET | `/threat-intel/iocs/{id}` | `threat_intel.lookup` |
| PATCH | `/threat-intel/iocs/{id}` (tags, notes, retire) | `threat_intel.manage` |
| POST | `/threat-intel/iocs/{id}/refresh` | `threat_intel.manage` |
| POST | `/threat-intel/alerts/{id}/enrich` | `threat_intel.lookup` |
| GET/POST/DELETE | `/incidents/{id}/iocs` | `incidents.read` / `.update` |

One new permission: **`threat_intel.manage`** (SOC Analyst and up). An
indicator an analyst adds by hand becomes evidence other people act on,
so a viewer must not be able to inject one.

`reputation`, `threat_score` and `last_enriched_at` appear on **output
models only**. A verdict somebody typed in is not intelligence.

## 9. Retirement, not deletion

`IOC.is_active=False` retires an indicator. Deleting one would orphan the
incidents that cite it, so retirement is a flag. Retired indicators are
hidden from the default listing but remain individually retrievable.

## 10. Agent integration

`enrich_ioc` was a Phase 2 stub returning `reputation: "unknown"`. It is
now the real service, with two properties that matter for an
agent-callable tool:

- **It never force-refreshes.** An agent loop can call a tool many times
  per investigation; letting a model bypass the cache would hand it the
  ability to burn a paid, shared quota.
- **It returns a structured `error` rather than raising** on a malformed
  value, because the agent loop only catches `ToolPermissionError` —
  anything else aborts the whole investigation instead of becoming a
  correctable tool result.

## 11. What this does not do

- **No automatic enrichment on ingest.** Enrichment is triggered per
  alert or per lookup. Enriching every indicator in every event at
  ingestion time would multiply provider calls by event volume.
- **No risk-score feedback loop.** A malicious IOC does not retroactively
  raise its alert's risk score. Phase 5's formula is documented and
  deterministic; quietly adding a term to it from a different phase would
  make the documented formula wrong.
- **No IOC expiry/decay policy** beyond the enrichment TTL.
- **No STIX/TAXII import or export.**

## 12. Test coverage

`backend/tests/test_threat_intel.py` — 40 tests: sample-feed safety
invariants (every IP reserved, every domain a reserved TLD), the
provider contract, the unknown-not-clean property, aggregation rules
including the worst-confident-verdict-wins case, cache hit/expiry,
extraction filters and provenance, IOC CRUD and retirement, alert
enrichment scoped to cited evidence, incident attachment, the
`enrich_ioc` agent tool, and RBAC / tenant isolation including two
tenants tracking the same indicator independently.
