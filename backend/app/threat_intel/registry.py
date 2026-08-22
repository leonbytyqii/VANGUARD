"""
Which enrichment providers are active, and how their answers combine.

## Provider resolution

`LocalFeedProvider` is **always** in the chain, including in live mode.
It costs nothing, needs no network, and its curated entries are the ones
the attack-simulation lab depends on — dropping it in live mode would
make the lab scenarios stop resolving the moment an operator added an API
key. Live providers are appended only when `THREAT_INTEL_MODE=live` and
their specific key is configured, so a half-configured deployment gets
the providers it actually has credentials for rather than a chain of
guaranteed failures.

## Aggregation

`aggregate(results)` folds several providers' opinions into the single
verdict and 0-100 score stored on the IOC row. The rules, in order:

1. **Failed lookups are excluded from the verdict** but still recorded as
   rows. A provider that could not be reached has not voted.
2. **Only results at or above `MIN_CONFIDENCE` vote.** A provider that is
   0.2 confident an indicator is malicious has not established that it
   is; letting it set the verdict would make the aggregate noisier than
   any single input.
3. **The worst confident verdict wins** — `malicious` over `suspicious`
   over `clean`. This is deliberately *not* a majority vote: three feeds
   with no data and one feed with a confirmed C2 match should produce
   "malicious", not "mostly clean". False negatives cost more than false
   positives in triage, and the per-provider rows are all retained so an
   analyst can see the disagreement.
4. **`threat_score`** is the confidence of the winning verdict, scaled by
   that verdict's weight, as an integer 0-100. It exists so alerts and
   indicators can be ordered by "how bad is this" without re-deriving it.
5. **No confident verdict at all → `unknown`, score 0.** Never `clean`:
   absence of evidence is recorded as absence of evidence.
"""
from __future__ import annotations

from app.core.config import settings
from app.models.enums import IOCReputation
from app.threat_intel.providers.base import ProviderResult, ThreatIntelProvider
from app.threat_intel.providers.local import LocalFeedProvider

#: Below this, a provider's opinion is recorded but does not vote.
MIN_CONFIDENCE = 0.5

_VERDICT_WEIGHT: dict[str, float] = {
    IOCReputation.MALICIOUS.value: 1.0,
    IOCReputation.SUSPICIOUS.value: 0.6,
    IOCReputation.CLEAN.value: 0.0,
    IOCReputation.UNKNOWN.value: 0.0,
}

_VERDICT_SEVERITY: dict[str, int] = {
    IOCReputation.UNKNOWN.value: 0,
    IOCReputation.CLEAN.value: 1,
    IOCReputation.SUSPICIOUS.value: 2,
    IOCReputation.MALICIOUS.value: 3,
}


def get_providers() -> list[ThreatIntelProvider]:
    providers: list[ThreatIntelProvider] = [LocalFeedProvider()]

    if settings.THREAT_INTEL_MODE == "live":
        # Imported lazily so a mock-mode deployment never imports httpx
        # clients it will not use.
        from app.threat_intel.providers.live import AbuseIPDBProvider, OTXProvider, VirusTotalProvider

        if settings.ABUSEIPDB_API_KEY:
            providers.append(AbuseIPDBProvider())
        if settings.VIRUSTOTAL_API_KEY:
            providers.append(VirusTotalProvider())
        if settings.OTX_API_KEY:
            providers.append(OTXProvider())

    return providers


def aggregate(results: list[ProviderResult]) -> tuple[str, int]:
    """Returns `(reputation, threat_score)`. See the module docstring for the rules."""
    voting = [r for r in results if not r.lookup_failed and r.confidence >= MIN_CONFIDENCE]
    if not voting:
        return IOCReputation.UNKNOWN.value, 0

    winner = max(voting, key=lambda r: (_VERDICT_SEVERITY.get(r.reputation, 0), r.confidence))
    if _VERDICT_SEVERITY.get(winner.reputation, 0) == 0:
        return IOCReputation.UNKNOWN.value, 0

    score = int(round(_VERDICT_WEIGHT.get(winner.reputation, 0.0) * winner.confidence * 100))
    return winner.reputation, max(0, min(100, score))
