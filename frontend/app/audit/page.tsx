"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

import {
  Badge,
  EmptyState,
  ErrorState,
  Loading,
  PageHeader,
  Panel,
  Select,
  Table,
  Td,
  TextInput,
} from "@/components/ui/primitives";
import { absoluteTime } from "@/lib/format";
import { apiGet, ApiError, qs } from "@/services/api";

interface AuditEntry {
  id: string;
  timestamp: string;
  actor_id: string | null;
  actor_label: string | null;
  action: string;
  resource_type: string | null;
  resource_id: string | null;
  outcome: string;
  source_ip: string | null;
  details: Record<string, any>;
}

export default function AuditPage() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [outcome, setOutcome] = useState("");
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setEntries(await apiGet<AuditEntry[]>(`/v1/audit${qs({ limit: 500 })}`));
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Failed to load the audit log.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return entries.filter((e) => {
      if (outcome && e.outcome !== outcome) return false;
      if (!needle) return true;
      return (
        e.action.toLowerCase().includes(needle) ||
        (e.actor_label ?? "").toLowerCase().includes(needle) ||
        (e.resource_type ?? "").toLowerCase().includes(needle) ||
        (e.resource_id ?? "").toLowerCase().includes(needle)
      );
    });
  }, [entries, outcome, search]);

  const denials = entries.filter((e) => e.outcome === "denied").length;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Audit Log"
        subtitle="Append-only WHO / WHAT / WHEN / FROM-WHERE / AGAINST-WHAT / RESULT record. Every permission denial and every AI tool dispatch lands here, including the ones that were refused."
      />

      {error && <ErrorState message={error} />}

      <Panel className="flex flex-wrap items-center gap-3">
        <Select
          label="Outcome"
          value={outcome}
          onChange={setOutcome}
          options={[
            { value: "", label: "All" },
            { value: "success", label: "Success" },
            { value: "denied", label: "Denied" },
            { value: "error", label: "Error" },
          ]}
        />
        <TextInput
          value={search}
          onChange={setSearch}
          placeholder="Filter by action, actor, or resource"
          className="min-w-72 flex-1"
        />
        <span className="text-xs text-soc-muted">
          {filtered.length} of {entries.length}
          {denials > 0 && <span className="ml-2 text-soc-critical">· {denials} denied</span>}
        </span>
      </Panel>

      {loading && <Panel><Loading /></Panel>}

      {!loading && filtered.length === 0 && !error && (
        <Panel><EmptyState title="No audit entries match" /></Panel>
      )}

      {!loading && filtered.length > 0 && (
        <Table head={["When", "Actor", "Action", "Resource", "Outcome", "From", "Details"]}>
          {filtered.map((e) => (
            <tr key={e.id} className={e.outcome === "denied" ? "bg-soc-critical/5" : undefined}>
              <Td className="whitespace-nowrap font-mono text-[11px]">{absoluteTime(e.timestamp)}</Td>
              <Td className="max-w-[16rem] truncate font-mono text-xs">
                {e.actor_label ?? <span className="text-soc-muted">system</span>}
              </Td>
              <Td className="font-mono text-xs text-soc-text">{e.action}</Td>
              <Td className="text-xs text-soc-muted">
                {e.resource_type ?? "—"}
                {e.resource_id && (
                  <div className="font-mono text-[10px]">{e.resource_id.slice(0, 12)}</div>
                )}
              </Td>
              <Td>
                <Badge tone={e.outcome === "denied" ? "danger" : e.outcome === "success" ? "success" : "neutral"}>
                  {e.outcome}
                </Badge>
              </Td>
              <Td className="font-mono text-[11px] text-soc-muted">{e.source_ip ?? "—"}</Td>
              <Td className="max-w-md">
                <pre className="overflow-x-auto whitespace-pre-wrap break-words font-mono text-[10px] text-soc-muted">
                  {JSON.stringify(e.details)}
                </pre>
              </Td>
            </tr>
          ))}
        </Table>
      )}
    </div>
  );
}
