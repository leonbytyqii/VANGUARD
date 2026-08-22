"""
One shared answer to "is this address internal?", used by both IOC
extraction and the offline provider so they cannot disagree.

## The documentation-range decision

Python's `ipaddress.IPv4Address.is_private` returns **True** for the RFC
5737 documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`,
`203.0.113.0/24`), because IANA lists them as not-globally-reachable. That
is correct about the real internet and wrong for this platform: those are
precisely the ranges `app/threat_intel/sample_feed.py` and the
attack-simulation lab use to stand in for external attacker
infrastructure, for the safety reason documented there (a committed feed
must not name a real operator's host).

So `is_internal_address` deliberately treats the documentation ranges as
**external**. Naively trusting `is_private` would mean the extractor
silently discarded every indicator in the lab scenarios and the offline
provider reported known C2 addresses as "clean" — the two bugs this
module exists to prevent.

The trade-off is stated rather than hidden: in a real deployment ingesting
real telemetry, a documentation-range address should never appear, so
classifying it as external costs nothing. If one ever did appear, it would
be an anomaly worth surfacing anyway.
"""
from __future__ import annotations

import ipaddress

#: Treated as external despite `is_private` being True for them.
#: See the module docstring.
DOCUMENTATION_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)


def is_documentation_address(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any(addr in network for network in DOCUMENTATION_NETWORKS)


def is_internal_address(value: str) -> bool:
    """
    True for address space no public reputation feed could ever score:
    RFC 1918 private, loopback, link-local, and multicast.

    Returns False for anything that does not parse as an IP address —
    callers decide separately whether a non-address is worth handling.
    """
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False

    if is_documentation_address(addr):
        return False

    return bool(addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast)


def is_scoreable_address(value: str) -> bool:
    """True when `value` parses as an IP address that a public feed could plausibly have an opinion on."""
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return not is_internal_address(value)
