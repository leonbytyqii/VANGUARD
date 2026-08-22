"""
Pulling candidate indicators out of normalized events.

This is deliberately a *projection of already-normalized fields*, not a
regex sweep over `raw_event`. Phase 3's adapters have already decided
which field is a destination IP and which is a queried domain; re-deriving
that from free text would produce indicators the platform cannot explain
the provenance of, and every extracted IOC here can name the event field
it came from.

Two filters matter:

- **Non-routable addresses are skipped.** An internal 10.x host is a real
  and important artefact, but it is not an *indicator of compromise* —
  no external feed can score it, and tracking every internal address as
  an IOC would bury the handful that matter under thousands that cannot
  be enriched. They remain fully searchable as events.
- **`src_ip` on inbound-shaped events and `dst_ip` on outbound-shaped
  ones are both taken.** Which one is "the attacker" depends on direction,
  and the normalized schema does not always carry direction, so both
  public addresses are candidates and enrichment decides which is
  interesting.
"""
from __future__ import annotations

from dataclasses import dataclass

from app.models.enums import IOCType
from app.models.event import Event
from app.threat_intel.addressing import is_scoreable_address

_HASH_LENGTHS = {32, 40, 64}  # md5 / sha1 / sha256 hex


@dataclass(frozen=True)
class ExtractedIOC:
    ioc_type: str
    value: str
    #: The normalized event field this came from — carried through so the
    #: IOC's provenance is answerable, not guessed at.
    source_field: str


def extract_from_event(event: Event) -> list[ExtractedIOC]:
    found: dict[tuple[str, str], ExtractedIOC] = {}

    def add(ioc_type: str, value: str | None, field: str) -> None:
        if not value:
            return
        cleaned = value.strip().lower()
        if not cleaned:
            return
        key = (ioc_type, cleaned)
        if key not in found:
            found[key] = ExtractedIOC(ioc_type=ioc_type, value=cleaned, source_field=field)

    for field in ("src_ip", "dst_ip"):
        value = getattr(event, field, None)
        if value and is_scoreable_address(value):
            add(IOCType.IP.value, value, field)

    add(IOCType.DOMAIN.value, event.domain, "domain")
    add(IOCType.URL.value, event.url, "url")

    file_hash = (event.file_hash or "").strip()
    if file_hash and len(file_hash) in _HASH_LENGTHS and all(c in "0123456789abcdefABCDEF" for c in file_hash):
        add(IOCType.FILE_HASH.value, file_hash, "file_hash")

    return list(found.values())


def extract_from_events(events: list[Event]) -> list[ExtractedIOC]:
    seen: dict[tuple[str, str], ExtractedIOC] = {}
    for event in events:
        for ioc in extract_from_event(event):
            seen.setdefault((ioc.ioc_type, ioc.value), ioc)
    return list(seen.values())
