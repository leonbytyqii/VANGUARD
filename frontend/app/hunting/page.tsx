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
  Table,
  Td,
  TextInput,
} from "@/components/ui/primitives";
import { useAuth } from "@/lib/auth";
import { relativeTime } from "@/lib/format";
import { apiGet, apiPost, ApiError } from "@/services/api";

interface HuntQuery {
  id: string;
  name: string;
  description: string;
  is_builtin: boolean;
  query_definition: Record<string, unknown>;
  default_lookback_hours: number;
  mitre_technique_ids: string[];
}

interface HuntExecution {
  id: string;
  hunt_query_id: string | null;
  query_definition_snapshot: Record<string, unknown>;
  status: string;
  scanned_event_count: number;
  matched_event_count: number;
  truncated_scan: boolean;
  truncated_results: boolean;
  time_range_start: string;
  time_range_end: string;
  started_at: string;
  completed_at: string | null;
  error: string | null;
}

interface HuntEvent {
  id: string;
  event_timestamp: string;
  host_name_raw: string | null;
  user: string | null;
  category: string;
  process: string | null;
  domain: string | null;
  dst_ip: string | null;
}

function isoRange(hours: number): { time_range_start: string; time_range_end: string } {
  const end = new Date();
  const start = new Date(end.getTime() - hours * 3600 * 1000);
  return { time_range_start: start.toISOString(), time_range_end: end.toISOString() };
}

export default function HuntingPage() {
  const can = useAuth((s) => s.can);
  const [queries, setQueries] = useState<HuntQuery[]>([]);
  const [executions, setExecutions] = useState<HuntExecution[]>([]);
  const [selected, setSelected] = useState<HuntExecution | null>(null);
  const [events, setEvents] = useState<HuntEvent[]>([]);
  const [hours, setHours] = useState("168");
  const [iocType, setIocType] = useState("ip");
  const [iocValue, setIocValue] = useState("");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [q, e] = await Promise.all([
        apiGet<HuntQuery[]>("/v1/hunting/queries"),
        apiGet<HuntExecution[]>("/v1/hunting/executions"),
      ]);
      setQueries(q);
      setExecutions(e);
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Failed to load hunts.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const nameFor = useCallback(
    (exec: HuntExecution) =>
      queries.find((q) => q.id === exec.hunt_query_id)?.name ??
      (exec.hunt_query_id ? "Saved hunt" : "Ad-hoc / IOC pivot"),
    [queries]
  );

  async function showResults(exec: HuntExecution) {
    setSelected(exec);
    try {
      setEvents(await apiGet<HuntEvent[]>(`/v1/hunting/executions/${exec.id}/events`));
    } catch {
      setEvents([]);
    }
  }

  async function runQuery(query: HuntQuery) {
    setBusy(query.id);
    setError(null);
    try {
      const exec = await apiPost<HuntExecution>(`/v1/hunting/queries/${query.id}/run`, isoRange(Number(hours)));
      await showResults(exec);
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Hunt failed.");
    } finally {
      setBusy(null);
    }
  }

  async function pivotOnIoc() {
    if (!iocValue.trim()) return;
    setBusy("ioc");
    setError(null);
    try {
      const exec = await apiPost<HuntExecution>("/v1/hunting/ioc-search", {
        ioc_type: iocType,
        value: iocValue.trim(),
        ...isoRange(Number(hours)),
      });
      await showResults(exec);
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "IOC pivot failed.");
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Threat Hunting"
        subtitle="On-demand, bounded search over historical telemetry — distinct from always-on detections. Every run persists a frozen query snapshot plus explicit truncation bookkeeping, so a partial answer is never presented as a complete one."
        actions={
          <Select
            label="Lookback"
            value={hours}
            onChange={setHours}
            options={[
              { value: "24", label: "24 hours" },
              { value: "168", label: "7 days" },
              { value: "720", label: "30 days" },
            ]}
          />
        }
      />

      {error && <ErrorState message={error} />}
      {loading && <Panel><Loading /></Panel>}

      {can("threat_hunting.execute") && (
        <Panel className="flex flex-wrap items-center gap-3">
          <span className="text-xs text-soc-muted">IOC pivot</span>
          <Select
            value={iocType}
            onChange={setIocType}
            options={[
              { value: "ip", label: "IP" },
              { value: "domain", label: "Domain" },
              { value: "url", label: "URL" },
              { value: "file_hash", label: "File hash" },
            ]}
          />
          <TextInput
            value={iocValue}
            onChange={setIocValue}
            placeholder="Indicator value"
            className="min-w-64 flex-1"
            onEnter={pivotOnIoc}
          />
          <Button variant="primary" onClick={pivotOnIoc} disabled={busy === "ioc" || !iocValue.trim()}>
            {busy === "ioc" ? "Hunting…" : "Has this appeared anywhere?"}
          </Button>
        </Panel>
      )}

      <div>
        <h2 className="mb-2 text-sm font-medium text-soc-text">Hunt library</h2>
        {queries.length === 0 && !loading ? (
          <Panel><EmptyState title="No saved hunts" /></Panel>
        ) : (
          <Table head={["Name", "Description", "ATT&CK", "Origin", ""]}>
            {queries.map((q) => (
              <tr key={q.id}>
                <Td className="font-medium">{q.name}</Td>
                <Td className="max-w-lg text-xs text-soc-muted">{q.description}</Td>
                <Td className="text-xs">
                  {q.mitre_technique_ids.length === 0 ? (
                    <span className="text-soc-muted">untagged</span>
                  ) : (
                    <div className="flex flex-wrap gap-1">
                      {q.mitre_technique_ids.map((t) => (
                        <Badge key={t} tone="accent">{t}</Badge>
                      ))}
                    </div>
                  )}
                </Td>
                <Td>{q.is_builtin ? <Badge>built-in</Badge> : <Badge tone="accent">custom</Badge>}</Td>
                <Td>
                  {can("threat_hunting.execute") && (
                    <Button onClick={() => runQuery(q)} disabled={busy === q.id}>
                      {busy === q.id ? "Running…" : "Run"}
                    </Button>
                  )}
                </Td>
              </tr>
            ))}
          </Table>
        )}
      </div>

      {selected && (
        <Panel>
          <div className="mb-3 flex flex-wrap items-center gap-2">
            <h2 className="text-sm font-medium text-soc-text">{nameFor(selected)}</h2>
            <Badge tone={selected.matched_event_count > 0 ? "accent" : "neutral"}>
              {selected.matched_event_count} match(es)
            </Badge>
            <Badge>{selected.scanned_event_count.toLocaleString()} scanned</Badge>
            {selected.truncated_scan || selected.truncated_results ? (
              <Badge tone="danger">
                {selected.truncated_scan ? "scan bounded" : "results bounded"} — this is a partial answer
              </Badge>
            ) : (
              <Badge tone="success">complete over the window</Badge>
            )}
            <span className="text-[11px] text-soc-muted">{relativeTime(selected.started_at)}</span>
          </div>

          {selected.error && <ErrorState message={selected.error} />}

          {events.length === 0 ? (
            <EmptyState
              title="No matching events"
              hint="The hunt ran and found nothing in the window — a real and useful negative result, not a failure."
            />
          ) : (
            <div className="max-h-96 overflow-auto">
              <Table head={["Time", "Host", "User", "Category", "Process / Domain / Dst"]}>
                {events.map((e) => (
                  <tr key={e.id}>
                    <Td className="whitespace-nowrap font-mono text-[11px]">{e.event_timestamp?.slice(0, 19)}</Td>
                    <Td className="font-mono text-xs">{e.host_name_raw ?? "—"}</Td>
                    <Td className="font-mono text-xs">{e.user ?? "—"}</Td>
                    <Td className="text-xs">{e.category}</Td>
                    <Td className="font-mono text-xs">{e.process ?? e.domain ?? e.dst_ip ?? "—"}</Td>
                  </tr>
                ))}
              </Table>
            </div>
          )}

          <details className="mt-3">
            <summary className="cursor-pointer text-[11px] text-soc-muted hover:text-soc-text">
              Frozen query snapshot
            </summary>
            <pre className="mt-2 overflow-auto rounded-lg bg-soc-bg p-3 font-mono text-[11px] text-soc-muted">
              {JSON.stringify(selected.query_definition_snapshot, null, 2)}
            </pre>
          </details>
        </Panel>
      )}

      <div>
        <h2 className="mb-2 text-sm font-medium text-soc-text">Recent executions</h2>
        {executions.length === 0 ? (
          <Panel><EmptyState title="No hunts have been run yet" /></Panel>
        ) : (
          <Table head={["Query", "Scanned", "Matches", "Bounded", "When", ""]}>
            {executions.slice(0, 20).map((e) => (
              <tr key={e.id}>
                <Td>{nameFor(e)}</Td>
                <Td className="tabular-nums text-xs">{e.scanned_event_count.toLocaleString()}</Td>
                <Td className="tabular-nums text-xs font-semibold">{e.matched_event_count}</Td>
                <Td className="text-xs">
                  {e.truncated_results || e.truncated_scan ? (
                    <Badge tone="danger">partial</Badge>
                  ) : (
                    <Badge tone="success">complete</Badge>
                  )}
                </Td>
                <Td className="whitespace-nowrap text-xs text-soc-muted">{relativeTime(e.started_at)}</Td>
                <Td>
                  <button onClick={() => showResults(e)} className="text-xs text-soc-accent hover:underline">
                    View
                  </button>
                </Td>
              </tr>
            ))}
          </Table>
        )}
      </div>
    </div>
  );
}
