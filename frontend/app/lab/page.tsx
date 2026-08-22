"use client";

import { CheckCircle2, XCircle } from "lucide-react";
import Link from "next/link";
import { useEffect, useState } from "react";

import {
  Badge,
  Button,
  EmptyState,
  ErrorState,
  Loading,
  PageHeader,
  Panel,
  Table,
  Td,
} from "@/components/ui/primitives";
import { relativeTime } from "@/lib/format";
import { apiGet, apiPost, ApiError } from "@/services/api";

interface Scenario {
  scenario_id: string;
  name: string;
  description: string;
  expected_detections: string[];
  mitre_technique_ids: string[];
  step_count: number;
  sources: string[];
  span_minutes: number;
}

interface RunResult {
  scenario_id: string;
  name: string;
  started_at: string;
  events_ingested: number;
  detections_fired: string[];
  expected_detections: string[];
  missing_detections: string[];
  unexpected_detections: string[];
  alerts_created: number;
  alert_ids: string[];
  fully_detected: boolean;
  errors: string[];
}

export default function LabPage() {
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [results, setResults] = useState<Record<string, RunResult>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    apiGet<Scenario[]>("/v1/lab/scenarios")
      .then(setScenarios)
      .catch((err) => setError(err instanceof ApiError ? err.detail : "Failed to load scenarios."))
      .finally(() => setLoading(false));
  }, []);

  async function run(scenario: Scenario) {
    setBusy(scenario.scenario_id);
    setError(null);
    try {
      const res = await apiPost<RunResult>(`/v1/lab/scenarios/${scenario.scenario_id}/run`, {});
      setResults((r) => ({ ...r, [scenario.scenario_id]: res }));
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Scenario run failed.");
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Attack Simulation Lab"
        subtitle="Replays synthetic telemetry through the real ingestion path — the same adapters, detection sweep, risk scoring, and alerting. Nothing writes a detection or an alert directly, so a run is an end-to-end test of the stack you can watch happen."
      />

      <Panel className="text-xs leading-relaxed text-soc-muted">
        Every scenario is <span className="text-soc-text">synthetic telemetry describing an attack</span>, never
        an attack. Nothing here executes a command, drops a file, or touches the network. Addresses come only
        from RFC 5737 documentation ranges and domains from RFC 2606 reserved TLDs, so no real infrastructure is
        ever named. Generated events are tagged <code className="rounded bg-soc-panel2 px-1">simulated: true</code>{" "}
        in their raw payload and stay distinguishable from real telemetry permanently.
      </Panel>

      {error && <ErrorState message={error} />}
      {loading && <Panel><Loading /></Panel>}

      {!loading && scenarios.length === 0 && !error && (
        <Panel><EmptyState title="No scenarios available" /></Panel>
      )}

      <div className="space-y-4">
        {scenarios.map((s) => {
          const result = results[s.scenario_id];
          return (
            <Panel key={s.scenario_id}>
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <h2 className="text-sm font-medium text-soc-text">{s.name}</h2>
                    <Badge>{s.step_count} events</Badge>
                    <Badge>{s.span_minutes} min span</Badge>
                    {s.sources.map((src) => (
                      <Badge key={src}>{src}</Badge>
                    ))}
                  </div>
                  <p className="mt-1.5 max-w-3xl text-xs leading-relaxed text-soc-muted">{s.description}</p>
                  <div className="mt-2 flex flex-wrap gap-1">
                    {s.mitre_technique_ids.map((t) => (
                      <Badge key={t} tone="accent">{t}</Badge>
                    ))}
                  </div>
                </div>
                <Button variant="primary" onClick={() => run(s)} disabled={busy === s.scenario_id}>
                  {busy === s.scenario_id ? "Replaying…" : "Run scenario"}
                </Button>
              </div>

              <div className="mt-3 border-t border-soc-border pt-3">
                <div className="text-[11px] uppercase tracking-widest text-soc-muted">Expected detections</div>
                <div className="mt-1 flex flex-wrap gap-1.5">
                  {s.expected_detections.map((d) => {
                    const fired = result?.detections_fired.includes(d);
                    return (
                      <span
                        key={d}
                        className={
                          result === undefined
                            ? "rounded bg-soc-panel2 px-2 py-0.5 font-mono text-[10px] text-soc-muted"
                            : fired
                              ? "inline-flex items-center gap-1 rounded bg-soc-success/15 px-2 py-0.5 font-mono text-[10px] text-soc-success"
                              : "inline-flex items-center gap-1 rounded bg-soc-critical/15 px-2 py-0.5 font-mono text-[10px] text-soc-critical"
                        }
                      >
                        {result !== undefined &&
                          (fired ? <CheckCircle2 size={11} /> : <XCircle size={11} />)}
                        {d}
                      </span>
                    );
                  })}
                </div>
              </div>

              {result && (
                <div className="mt-3 rounded-lg bg-soc-bg p-3">
                  <div className="flex flex-wrap items-center gap-2">
                    {result.fully_detected ? (
                      <Badge tone="success">every expected detection fired</Badge>
                    ) : (
                      <Badge tone="danger">
                        {result.missing_detections.length} expected detection(s) did not fire
                      </Badge>
                    )}
                    <Badge>{result.events_ingested} events ingested</Badge>
                    <Badge>{result.alerts_created} alert(s) created</Badge>
                    <span className="text-[11px] text-soc-muted">{relativeTime(result.started_at)}</span>
                  </div>

                  {result.unexpected_detections.length > 0 && (
                    <p className="mt-2 text-[11px] text-soc-muted">
                      Also fired (not in this scenario&apos;s expectation):{" "}
                      <span className="font-mono">{result.unexpected_detections.join(", ")}</span>
                    </p>
                  )}

                  {result.errors.length > 0 && (
                    <ul className="mt-2 list-inside list-disc text-[11px] text-soc-critical">
                      {result.errors.map((e, i) => (
                        <li key={i}>{e}</li>
                      ))}
                    </ul>
                  )}

                  {result.alert_ids.length > 0 && (
                    <div className="mt-2 flex flex-wrap gap-2">
                      {result.alert_ids.slice(0, 6).map((id) => (
                        <Link
                          key={id}
                          href={`/alerts/${id}`}
                          className="font-mono text-[11px] text-soc-accent hover:underline"
                        >
                          {id.slice(0, 8)}
                        </Link>
                      ))}
                      <Link href="/alerts" className="text-[11px] text-soc-accent hover:underline">
                        view all alerts →
                      </Link>
                    </div>
                  )}
                </div>
              )}
            </Panel>
          );
        })}
      </div>

      {Object.keys(results).length > 0 && (
        <div>
          <h2 className="mb-2 text-sm font-medium text-soc-text">Run summary</h2>
          <Table head={["Scenario", "Events", "Fired", "Missing", "Alerts", "Result"]}>
            {Object.values(results).map((r) => (
              <tr key={r.scenario_id}>
                <Td className="text-xs">{r.name}</Td>
                <Td className="tabular-nums text-xs">{r.events_ingested}</Td>
                <Td className="tabular-nums text-xs">{r.detections_fired.length}</Td>
                <Td className="tabular-nums text-xs">{r.missing_detections.length}</Td>
                <Td className="tabular-nums text-xs">{r.alerts_created}</Td>
                <Td>
                  {r.fully_detected ? <Badge tone="success">pass</Badge> : <Badge tone="danger">gap</Badge>}
                </Td>
              </tr>
            ))}
          </Table>
        </div>
      )}
    </div>
  );
}
