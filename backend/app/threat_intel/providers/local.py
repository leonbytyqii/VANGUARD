"""
The default, offline, deterministic enrichment provider.

This is the threat-intelligence counterpart to `app/ai/providers/mock.py`:
the platform must be fully demonstrable and fully testable with no API
keys, no network, and no per-lookup cost. It answers from
`app/threat_intel/sample_feed.py` plus a small amount of purely local
reasoning about address space.

**It returns `unknown` for almost everything, and that is the point.** An
offline provider genuinely has no opinion on an arbitrary indicator. The
tempting alternative — hashing the value into a pseudo-random verdict so
demos look lively — would manufacture threat intelligence out of nothing,
which is precisely the fabrication this platform refuses to do anywhere
else. A SOC analyst reading "malicious, confidence 0.8" is entitled to
assume something actually said so.

The one thing it will assert without the feed is that **RFC 1918 private,
loopback, and link-local addresses are `clean`** — not because they are
trustworthy hosts, but because "is this internal address on a public
reputation blocklist?" has a real, knowable, offline answer, and it is
no. That is a statement about routability, and the docstring on
`_address_verdict` says so rather than letting it read as a safety
judgement.
"""
from __future__ import annotations

from datetime import datetime, timezone

from app.models.enums import IOCType
from app.threat_intel.addressing import is_internal_address
from app.threat_intel.providers.base import ProviderResult, ThreatIntelProvider
from app.threat_intel.sample_feed import lookup_sample


class LocalFeedProvider(ThreatIntelProvider):
    name = "local_feed"
    supported_types = (IOCType.IP.value, IOCType.DOMAIN.value, IOCType.URL.value, IOCType.FILE_HASH.value)

    def lookup(self, ioc_type: str, value: str) -> ProviderResult:
        normalized = value.strip().lower()

        hit = lookup_sample(normalized)
        if hit is not None:
            reputation, confidence, tags, description = hit
            return ProviderResult(
                provider=self.name,
                reputation=reputation,
                confidence=confidence,
                raw={"tags": tags, "description": description, "source": "bundled_sample_feed", "synthetic": True},
                last_seen=datetime.now(timezone.utc),
            )

        if ioc_type == IOCType.IP.value:
            verdict = self._address_verdict(normalized)
            if verdict is not None:
                return verdict

        return ProviderResult(
            provider=self.name,
            reputation="unknown",
            confidence=0.0,
            raw={"source": "bundled_sample_feed", "reason": "indicator not present in the offline feed"},
        )

    def _address_verdict(self, value: str) -> ProviderResult | None:
        """
        A judgement about *routability*, not about trustworthiness.

        A private or loopback address cannot appear on a public reputation
        feed, so "clean" here means "no public feed has anything to say
        about this, and none ever could" — it emphatically does not mean
        the host is safe. An attacker's foothold is usually on 10.0.0.0/8.
        The `reason` string is carried into `raw` so this never renders in
        the UI as a bare, misreadable "clean".
        """
        if is_internal_address(value):
            return ProviderResult(
                provider=self.name,
                reputation="clean",
                confidence=0.9,
                raw={
                    "source": "address_space",
                    "reason": "non-routable address; cannot appear on a public reputation feed",
                    "caveat": "this is a statement about routability, not about host trustworthiness",
                },
            )
        return None
