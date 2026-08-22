"""
Adapter contract. One class per log source; adding a new source means
adding one class here and one line in the registry
(app/services/ingestion/registry.py) — nothing else in the pipeline
changes. See docs/ARCHITECTURE.md §"Event normalization" for the design
rationale.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.schemas.event import EventIngestRequest


class AdapterValidationError(ValueError):
    """Raised when a source-specific required field is missing or malformed."""


@dataclass
class NormalizedFields:
    """
    The subset of the common event schema an adapter is responsible for
    deriving. Anything not set here is copied straight through from the
    request by the ingestion service (host, user, ip/port fields, etc.) —
    adapters only need to own the parts that require source-specific
    interpretation: `category` and `action`, plus any field they compute
    or validate specially.
    """

    category: str
    action: str
    overrides: dict = field(default_factory=dict)  # optional field overrides, e.g. cleaned/derived values


class SourceAdapter:
    source_name: str

    def normalize(self, payload: "EventIngestRequest") -> NormalizedFields:
        raise NotImplementedError
