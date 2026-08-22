"""
Real, network-backed enrichment providers: AbuseIPDB, VirusTotal, OTX.

All three are only ever constructed when `THREAT_INTEL_MODE=live` *and*
the relevant API key is present in settings
(`app/threat_intel/registry.py`). Keys are read from settings only, never
hard-coded, and never written to a log line or into `raw_response` — the
`_redact` helper strips any header-shaped material before a response is
persisted.

Each provider maps its vendor-specific score into the platform's shared
`IOCReputation` vocabulary. Those thresholds are stated as module-level
constants rather than buried in the mapping code, because they are
tuning decisions a SOC will want to argue with, not implementation
details.

None of these raise: every failure path returns
`ProviderResult.failure(...)`, so an outage or a rate limit degrades the
verdict to `unknown` instead of taking down whatever called it.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import httpx

from app.core.config import settings
from app.models.enums import IOCType
from app.threat_intel.providers.base import ProviderResult, ThreatIntelProvider

_TIMEOUT = 15.0

# --- Mapping thresholds (tuning decisions, deliberately visible) --------
# AbuseIPDB reports an abuse confidence score 0-100.
ABUSEIPDB_MALICIOUS_AT = 75
ABUSEIPDB_SUSPICIOUS_AT = 25
# VirusTotal reports per-engine verdicts; these are counts of engines
# calling the sample malicious.
VT_MALICIOUS_AT = 5
VT_SUSPICIOUS_AT = 1
# OTX reports the number of threat "pulses" an indicator appears in.
OTX_MALICIOUS_AT = 5
OTX_SUSPICIOUS_AT = 1


def _redact(payload: Any) -> Any:
    """
    Defence in depth before a provider response is persisted into
    `threat_intelligence.raw_response`. The APIs below do not echo
    credentials back today, but a stored blob is exactly where a leaked
    key would go unnoticed, so anything key-shaped is stripped on the way
    in rather than trusted not to be there.
    """
    banned = {"apikey", "api_key", "x-apikey", "key", "authorization", "token", "secret"}
    if isinstance(payload, dict):
        return {k: ("[redacted]" if k.lower() in banned else _redact(v)) for k, v in payload.items()}
    if isinstance(payload, list):
        return [_redact(v) for v in payload]
    return payload


class AbuseIPDBProvider(ThreatIntelProvider):
    name = "abuseipdb"
    supported_types = (IOCType.IP.value,)

    def lookup(self, ioc_type: str, value: str) -> ProviderResult:
        key = settings.ABUSEIPDB_API_KEY
        if not key:
            return ProviderResult.failure(self.name, "ABUSEIPDB_API_KEY is not configured")
        try:
            resp = httpx.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": value, "maxAgeInDays": 90},
                headers={"Key": key, "Accept": "application/json"},
                timeout=_TIMEOUT,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
        except Exception as exc:  # noqa: BLE001 - every failure becomes `unknown`, never `clean`
            return ProviderResult.failure(self.name, f"{type(exc).__name__}: {exc}")

        score = int(data.get("abuseConfidenceScore", 0) or 0)
        if score >= ABUSEIPDB_MALICIOUS_AT:
            reputation = "malicious"
        elif score >= ABUSEIPDB_SUSPICIOUS_AT:
            reputation = "suspicious"
        else:
            reputation = "clean"

        return ProviderResult(
            provider=self.name,
            reputation=reputation,
            confidence=min(1.0, score / 100.0) if reputation != "clean" else 0.7,
            raw=_redact(data),
            last_seen=_parse_iso(data.get("lastReportedAt")),
        )


class VirusTotalProvider(ThreatIntelProvider):
    name = "virustotal"
    supported_types = (IOCType.IP.value, IOCType.DOMAIN.value, IOCType.URL.value, IOCType.FILE_HASH.value)

    _PATHS = {
        IOCType.IP.value: "ip_addresses",
        IOCType.DOMAIN.value: "domains",
        IOCType.FILE_HASH.value: "files",
    }

    def lookup(self, ioc_type: str, value: str) -> ProviderResult:
        key = settings.VIRUSTOTAL_API_KEY
        if not key:
            return ProviderResult.failure(self.name, "VIRUSTOTAL_API_KEY is not configured")

        if ioc_type == IOCType.URL.value:
            import base64

            ident = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
            path = f"urls/{ident}"
        else:
            segment = self._PATHS.get(ioc_type)
            if segment is None:
                return ProviderResult.failure(self.name, f"unsupported ioc_type '{ioc_type}'")
            path = f"{segment}/{value}"

        try:
            resp = httpx.get(
                f"https://www.virustotal.com/api/v3/{path}",
                headers={"x-apikey": key, "Accept": "application/json"},
                timeout=_TIMEOUT,
            )
            resp.raise_for_status()
            attributes = resp.json().get("data", {}).get("attributes", {})
        except Exception as exc:  # noqa: BLE001
            return ProviderResult.failure(self.name, f"{type(exc).__name__}: {exc}")

        stats = attributes.get("last_analysis_stats", {}) or {}
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        total = sum(int(v or 0) for v in stats.values()) or 1

        if malicious >= VT_MALICIOUS_AT:
            reputation = "malicious"
        elif malicious >= VT_SUSPICIOUS_AT or suspicious >= VT_SUSPICIOUS_AT:
            reputation = "suspicious"
        else:
            reputation = "clean"

        return ProviderResult(
            provider=self.name,
            reputation=reputation,
            confidence=min(1.0, (malicious + suspicious) / total * 3) if reputation != "clean" else 0.7,
            raw=_redact({"last_analysis_stats": stats, "reputation": attributes.get("reputation")}),
            last_seen=_parse_epoch(attributes.get("last_analysis_date")),
        )


class OTXProvider(ThreatIntelProvider):
    name = "otx"
    supported_types = (IOCType.IP.value, IOCType.DOMAIN.value, IOCType.FILE_HASH.value)

    _SECTIONS = {
        IOCType.IP.value: "IPv4",
        IOCType.DOMAIN.value: "domain",
        IOCType.FILE_HASH.value: "file",
    }

    def lookup(self, ioc_type: str, value: str) -> ProviderResult:
        key = settings.OTX_API_KEY
        if not key:
            return ProviderResult.failure(self.name, "OTX_API_KEY is not configured")
        section = self._SECTIONS.get(ioc_type)
        if section is None:
            return ProviderResult.failure(self.name, f"unsupported ioc_type '{ioc_type}'")

        try:
            resp = httpx.get(
                f"https://otx.alienvault.com/api/v1/indicators/{section}/{value}/general",
                headers={"X-OTX-API-KEY": key, "Accept": "application/json"},
                timeout=_TIMEOUT,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:  # noqa: BLE001
            return ProviderResult.failure(self.name, f"{type(exc).__name__}: {exc}")

        pulses = int((data.get("pulse_info") or {}).get("count", 0) or 0)
        if pulses >= OTX_MALICIOUS_AT:
            reputation = "malicious"
        elif pulses >= OTX_SUSPICIOUS_AT:
            reputation = "suspicious"
        else:
            reputation = "clean"

        return ProviderResult(
            provider=self.name,
            reputation=reputation,
            confidence=min(1.0, pulses / 10.0) if reputation != "clean" else 0.6,
            raw=_redact({"pulse_count": pulses, "reputation": data.get("reputation")}),
        )


def _parse_iso(raw: Any) -> datetime | None:
    if not raw or not isinstance(raw, str):
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


def _parse_epoch(raw: Any) -> datetime | None:
    if not isinstance(raw, (int, float)):
        return None
    try:
        return datetime.fromtimestamp(raw, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None
