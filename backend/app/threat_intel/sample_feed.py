"""
The offline indicator feed that ships with the repo.

**Every indicator in here is synthetic.** IPv4 entries come only from the
documentation/test ranges reserved by RFC 5737 (`192.0.2.0/24`,
`198.51.100.0/24`, `203.0.113.0/24`); domains use the `.invalid` and
`.test` TLDs reserved by RFC 2606; hashes are hand-constructed. Nothing
here names a real host, and nothing here is a real threat-intelligence
verdict.

That constraint is deliberate rather than lazy. A demo feed seeded with
"realistic-looking" public IPs would mean this repo ships a file that
labels somebody's actual infrastructure as malicious — which is both
wrong and, if it ever leaked into a real deployment's blocklist, harmful.
Reserved ranges cannot belong to anyone, so the feed can be committed,
shared, and demonstrated with no risk of defaming a real operator.

The consequence is that `LocalFeedProvider` returns `unknown` for almost
everything, which is the *correct* behaviour for an offline provider:
it genuinely does not know. See `app/threat_intel/providers/local.py`
for why `unknown` is never collapsed into `clean`.
"""
from __future__ import annotations

# value -> (reputation, confidence, tags, description)
SAMPLE_INDICATORS: dict[str, tuple[str, float, list[str], str]] = {
    # --- IPv4 (RFC 5737 documentation ranges only) ---
    "203.0.113.7": ("malicious", 0.95, ["c2", "cobalt-strike"], "Synthetic C2 beacon destination used by the lab scenarios."),
    "203.0.113.13": ("malicious", 0.9, ["c2"], "Synthetic secondary C2 node."),
    "203.0.113.66": ("suspicious", 0.6, ["scanning"], "Synthetic host observed performing broad port scans."),
    "198.51.100.23": ("malicious", 0.92, ["exfiltration"], "Synthetic exfiltration endpoint."),
    "198.51.100.99": ("suspicious", 0.55, ["tor-exit"], "Synthetic Tor exit node."),
    "192.0.2.44": ("suspicious", 0.5, ["bruteforce"], "Synthetic source of distributed SSH brute-force attempts."),
    # --- Domains (RFC 2606 reserved TLDs only) ---
    "malware-delivery.invalid": ("malicious", 0.97, ["malware", "dropper"], "Synthetic first-stage payload host."),
    "c2-panel.invalid": ("malicious", 0.95, ["c2"], "Synthetic C2 web panel."),
    "exfil-drop.invalid": ("malicious", 0.93, ["exfiltration"], "Synthetic data-staging domain."),
    "kj3h4kj2h34kjh.test": ("suspicious", 0.7, ["dga"], "Synthetic DGA-style domain."),
    "update-service.test": ("suspicious", 0.5, ["typosquat"], "Synthetic typosquat of a legitimate updater."),
    # --- URLs ---
    "http://malware-delivery.invalid/stage2.ps1": ("malicious", 0.96, ["malware", "powershell"], "Synthetic second-stage script URL."),
    # --- File hashes (synthetic, not real sample hashes) ---
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": (
        "clean", 0.99, ["empty-file"], "SHA-256 of the empty file — genuinely benign, included so 'clean' is exercised."
    ),
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": (
        "malicious", 0.94, ["ransomware"], "Synthetic ransomware payload hash."
    ),
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": (
        "suspicious", 0.6, ["packed"], "Synthetic packed binary hash."
    ),
}


def lookup_sample(value: str) -> tuple[str, float, list[str], str] | None:
    return SAMPLE_INDICATORS.get(value.strip().lower())
