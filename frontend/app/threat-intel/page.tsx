"use client";

import { useCallback, useEffect, useState } from "react";

import {
  Badge,
  Button,
  EmptyState,
  ErrorState,
  Loading,
  PageHeader,
  Panel,
  Select,
  StatTile,
  StatusBadge,
  Table,
  Td,
  TextInput,
} from "@/components/ui/primitives";
import { useAuth } from "@/lib/auth";
import { relativeTime } from "@/lib/format";
import { apiGet, apiPost, ApiError, qs } from "@/services/api";

interface Enrichment {
  provider: string;
  reputation: string;
  confidence: number;
  queried_at: string;
  expires_at: string | null;
  lookup_failed: boolean;
  error: string | null;
  raw_response: Record<string, any>;
}

interface IOC {
  id: string;
  ioc_type: string;
  value: string;
  reputation: string;
  threat_score: number;
  is_active: boolean;
  tags: string[];
  last_enriched_at: string | null;
  related_alert_ids: string[];
  related_incident_ids: string[];
}

interface IOCDetail extends IOC {
  enrichments: Enrichment[];
}

export default function ThreatIntelPage() {
  const can = useAuth((s) => s.can);
  const [iocs, setIocs] = useState<IOC[]>([]);
  const [detail, setDetail] = useState<IOCDetail | null>(null);
  const [fromCache, setFromCache] = useState<boolean | null>(null);
  const [reputation, setReputation] = useState("");
  const [search, setSearch] = useState("");
  const [lookupType, setLookupType] = useState("ip");
  const [lookupValue, setLookupValue] = useState("");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setIocs(await apiGet<IOC[]>(`/v1/threat-intel/iocs${qs({ reputation, search, limit: 200 })}`));
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Failed to load indicators.");
    } finally {
      setLoading(false);
    }
  }, [reputation, search]);

  useEffect(() => {
    void load();
  }, [load]);

  async function lookup() {
    if (!lookupValue.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const res = await apiPost<{ ioc: IOCDetail; from_cache: boolean }>("/v1/threat-intel/lookup", {
        ioc_type: lookupType,
        value: lookupValue.trim(),
      });
      setDetail(res.ioc);
      setFromCache(res.from_cache);
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Lookup failed.");
    } finally {
      setBusy(false);
    }
  }

  async function open(id: string) {
    try {
      setDetail(await apiGet<IOCDetail>(`/v1/threat-intel/iocs/${id}`));
      setFromCache(null);
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Could not load that indicator.");
    }
  }

  async function refresh(id: string) {
    setBusy(true);
    try {
      const res = await apiPost<{ ioc: IOCDetail; from_cache: boolean }>(`/v1/threat-intel/iocs/${id}/refresh`, {});
      setDetail(res.ioc);
      setFromCache(res.from_cache);
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Refresh failed.");
    } finally {
      setBusy(false);
    }
  }

  const malicious = iocs.filter((i) => i.reputation === "malicious").length;
  const unknown = iocs.filter((i) => i.reputation === "unknown").length;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Threat Intelligence"
        subtitle="Indicator enrichment across a provider chain. An indicator nobody has scored is recorded as unknown, never as clean — absence of evidence is not evidence of absence."
      />

      {error && <ErrorState message={error} />}

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatTile label="Active indicators" value={iocs.length} />
        <StatTile label="Malicious" value={malicious} tone={malicious ? "danger" : undefined} />
        <StatTile label="Suspicious" value={iocs.filter((i) => i.reputation === "suspicious").length} />
        <StatTile label="Unknown" value={unknown} hint="No provider has an opinion" />
      </div>

      <Panel className="flex flex-wrap items-center gap-3">
        <span className="text-xs text-soc-muted">Look up</span>
        <Select
          value={lookupType}
          onChange={setLookupType}
          options={[
            { value: "ip", label: "IP" },
            { value: "domain", label: "Domain" },
            { value: "url", label: "URL" },
            { value: "file_hash", label: "File hash" },
          ]}
        />
        <TextInput
          value={lookupValue}
          onChange={setLookupValue}
          placeholder="Indicator value"
          className="min-w-64 flex-1"
          onEnter={lookup}
        />
        <Button variant="primary" onClick={lookup} disabled={busy || !lookupValue.trim()}>
          {busy ? "Enriching…" : "Enrich"}
        </Button>
      </Panel>

      {detail && (
        <Panel>
          <div className="mb-3 flex flex-wrap items-center gap-2">
            <h2 className="font-mono text-sm text-soc-text">{detail.value}</h2>
            <Badge>{detail.ioc_type}</Badge>
            <StatusBadge status={detail.reputation} />
            <Badge tone={detail.threat_score >= 70 ? "danger" : "neutral"}>score {detail.threat_score}</Badge>
            {fromCache === true && <Badge>served from cache</Badge>}
            {fromCache === false && <Badge tone="accent">providers queried just now</Badge>}
            {can("threat_intel.manage") && (
              <Button className="ml-auto" onClick={() => refresh(detail.id)} disabled={busy}>
                Force refresh
              </Button>
            )}
          </div>

          {detail.enrichments.length === 0 ? (
            <EmptyState title="No provider results" />
          ) : (
            <Table head={["Provider", "Verdict", "Confidence", "Queried", "Expires", "Detail"]}>
              {detail.enrichments.map((e, i) => (
                <tr key={i}>
                  <Td className="font-mono text-xs">{e.provider}</Td>
                  <Td>
                    {e.lookup_failed ? <Badge tone="danger">lookup failed</Badge> : <StatusBadge status={e.reputation} />}
                  </Td>
                  <Td className="tabular-nums text-xs">{e.confidence.toFixed(2)}</Td>
                  <Td className="whitespace-nowrap text-xs text-soc-muted">{relativeTime(e.queried_at)}</Td>
                  <Td className="whitespace-nowrap text-xs text-soc-muted">{relativeTime(e.expires_at)}</Td>
                  <Td className="max-w-md text-[11px] text-soc-muted">
                    {e.error ?? e.raw_response?.description ?? e.raw_response?.reason ?? "—"}
                  </Td>
                </tr>
              ))}
            </Table>
          )}

          <p className="mt-3 text-[11px] text-soc-muted">
            The worst confident verdict wins across providers — deliberately not a majority vote. Three feeds with
            no data and one confirmed C2 match is &ldquo;malicious&rdquo;, not &ldquo;mostly clean&rdquo;.
          </p>
        </Panel>
      )}

      <Panel className="flex flex-wrap items-center gap-3">
        <Select
          label="Reputation"
          value={reputation}
          onChange={setReputation}
          options={[
            { value: "", label: "All" },
            { value: "malicious", label: "Malicious" },
            { value: "suspicious", label: "Suspicious" },
            { value: "clean", label: "Clean" },
            { value: "unknown", label: "Unknown" },
          ]}
        />
        <TextInput value={search} onChange={setSearch} placeholder="Search value" onEnter={load} />
        <span className="ml-auto text-xs text-soc-muted">{iocs.length} shown</span>
      </Panel>

      {loading && <Panel><Loading /></Panel>}

      {!loading && iocs.length === 0 && (
        <Panel>
          <EmptyState
            title="No indicators tracked yet"
            hint="Indicators are created by looking one up here, or automatically when an alert's cited events are enriched."
          />
        </Panel>
      )}

      {!loading && iocs.length > 0 && (
        <Table head={["Type", "Value", "Reputation", "Score", "Tags", "Linked", "Enriched", ""]}>
          {iocs.map((i) => (
            <tr key={i.id} className="hover:bg-soc-panel2/40">
              <Td className="text-xs uppercase text-soc-muted">{i.ioc_type}</Td>
              <Td className="max-w-xs truncate font-mono text-xs">{i.value}</Td>
              <Td><StatusBadge status={i.reputation} /></Td>
              <Td className="tabular-nums font-semibold">{i.threat_score}</Td>
              <Td className="text-[11px] text-soc-muted">{i.tags.join(", ") || "—"}</Td>
              <Td className="text-xs text-soc-muted">
                {i.related_alert_ids.length}a / {i.related_incident_ids.length}i
              </Td>
              <Td className="whitespace-nowrap text-xs text-soc-muted">{relativeTime(i.last_enriched_at)}</Td>
              <Td>
                <button onClick={() => open(i.id)} className="text-xs text-soc-accent hover:underline">
                  Details
                </button>
              </Td>
            </tr>
          ))}
        </Table>
      )}
    </div>
  );
}
