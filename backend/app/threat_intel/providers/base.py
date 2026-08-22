"""
The provider abstraction for IOC enrichment.

Same shape, and same reasoning, as `app/ai/providers/base.py`: the
platform depends on an interface, not on any one vendor. A deployment
with no API keys at all still runs — it resolves to `LocalFeedProvider`,
which is honest about only knowing what ships with the repo — and adding
a real feed is a settings change, not a code change.

Every provider must be **non-raising**. A network failure, a rate limit,
or a malformed response is returned as a `ProviderResult` with
`lookup_failed=True` and a reason, never as an exception. Enrichment is
called from ingestion-adjacent paths and from an AI tool handler; a
provider outage must degrade the answer, not take down the request.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class ProviderResult:
    provider: str
    reputation: str  # IOCReputation value
    confidence: float  # 0.0-1.0
    raw: dict[str, Any] = field(default_factory=dict)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    lookup_failed: bool = False
    error: str | None = None

    @classmethod
    def failure(cls, provider: str, error: str) -> "ProviderResult":
        """
        A failed lookup is recorded as `unknown` with zero confidence —
        never as `clean`. Treating "we could not reach the provider" as
        "the provider said it's fine" is the single most dangerous
        default this module could have.
        """
        return cls(
            provider=provider,
            reputation="unknown",
            confidence=0.0,
            raw={},
            lookup_failed=True,
            error=error[:500],
        )


class ThreatIntelProvider(ABC):
    name: str = "base"
    #: IOC types this provider can meaningfully answer for. A provider is
    #: skipped rather than asked a question it cannot answer, so an
    #: IP-reputation service is never queried about a file hash and
    #: charged for it.
    supported_types: tuple[str, ...] = ()

    def supports(self, ioc_type: str) -> bool:
        return ioc_type in self.supported_types

    @abstractmethod
    def lookup(self, ioc_type: str, value: str) -> ProviderResult:
        """Score one indicator. Must not raise — see the module docstring."""
        raise NotImplementedError
