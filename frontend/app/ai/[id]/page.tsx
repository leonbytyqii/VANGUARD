"use client";

import { ArrowLeft } from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";

import type { Investigation } from "@/app/ai/page";
import {
  Badge,
  EmptyState,
  ErrorState,
  KeyValue,
  Loading,
  PageHeader,
  Panel,
  StatusBadge,
} from "@/components/ui/primitives";
import { absoluteTime, titleCase } from "@/lib/format";
import { apiGet, ApiError } from "@/services/api";

interface Evidence {
  claim: string;
  source_tool: string;
  source_event_id: string | null;
  source_table: string | null;
  confidence: number;
}

interface Step {
  id: string;
  step_number: number;
  agent_type: string;
  action: string;
  tool_input: Record<string, any>;
  tool_output: Record<string, any>;
  reasoning_note: string;
  step_started_at: string;
  evidence: Evidence[];
}

const AGENT_TONE: Record<string, string> = {
  triage: "bg-soc-medium/15 text-soc-medium ring-soc-medium/30",
  investigation: "bg-soc-accent/15 text-soc-accent ring-soc-accent/30",
  threat_hunt: "bg-soc-low/15 text-soc-low ring-soc-low/30",
  cloud_iam: "bg-soc-high/15 text-soc-high ring-soc-high/30",
  response: "bg-soc-critical/15 text-soc-critical ring-soc-critical/30",
};

export default function InvestigationTracePage() {
  const { id } = useParams<{ id: string }>();
  const [investigation, setInvestigation] = useState<Investigation | null>(null);
  const [steps, setSteps] = useState<Step[]>([]);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [inv, st] = await Promise.all([
        apiGet<Investigation>(`/v1/ai/investigations/${id}`),
        apiGet<Step[]>(`/v1/ai/investigations/${id}/steps`),
      ]);
      setInvestigation(inv);
      setSteps(st);
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Failed to load the trace.");
    }
  }, [id]);

  useEffect(() => {
    void load();
  }, [load]);

  if (!investigation && !error) return <Panel><Loading /></Panel>;

  const result = investigation?.result;

  return (
    <div className="space-y-6">
      <Link href="/ai" className="inline-flex items-center gap-1.5 text-xs text-soc-muted hover:text-soc-text">
        <ArrowLeft size={14} /> Back to investigations
      </Link>

      {error && <ErrorState message={error} />}

      {investigation && (
        <>
          <PageHeader
            title="Agent trace"
            subtitle="Every tool call, every piece of evidence, and every intermediate hypothesis — stored and replayable. This is the whole basis of the conclusion."
            actions={
              <div className="flex items-center gap-2">
                <StatusBadge status={investigation.status} />
                <Badge>{investigation.ai_provider} · {investigation.ai_model}</Badge>
              </div>
            }
          />

          {investigation.error && <ErrorState message={investigation.error} />}

          {result && (
            <Panel>
              <h2 className="mb-3 text-sm font-medium text-soc-text">Conclusion</h2>
              <KeyValue
                items={[
                  ["Severity", <Badge key="s" tone="accent">{result.severity}</Badge>],
                  ["Risk score", <span key="r" className="tabular-nums font-semibold">{result.risk_score}</span>],
                  ["Confidence", result.confidence],
                  ["Alert", <Link key="a" href={`/alerts/${investigation.alert_id}`} className="text-soc-accent hover:underline">open alert</Link>],
                ]}
              />
              <p className="mt-4 text-sm leading-relaxed text-soc-text">{result.summary}</p>

              {(result.hypotheses ?? []).length > 0 && (
                <div className="mt-4">
                  <h3 className="mb-1.5 text-[11px] uppercase tracking-widest text-soc-muted">Hypotheses</h3>
                  <ul className="space-y-1.5">
                    {result.hypotheses.map((h: any, i: number) => (
                      <li key={i} className="rounded-lg bg-soc-bg p-2.5 text-xs">
                        <div className="flex items-center gap-2">
                          <Badge>{h.likelihood}</Badge>
                          <span className="text-soc-text">{h.statement}</span>
                        </div>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {(result.false_positive_indicators ?? []).length > 0 && (
                <div className="mt-4">
                  <h3 className="mb-1.5 text-[11px] uppercase tracking-widest text-soc-muted">
                    Reasons this might be benign
                  </h3>
                  <ul className="list-inside list-disc text-xs text-soc-muted">
                    {result.false_positive_indicators.map((f: string, i: number) => (
                      <li key={i}>{f}</li>
                    ))}
                  </ul>
                </div>
              )}
            </Panel>
          )}

          <div>
            <h2 className="mb-2 text-sm font-medium text-soc-text">Step-by-step trace ({steps.length} steps)</h2>
            <Panel>
              {steps.length === 0 ? (
                <EmptyState title="No steps recorded" />
              ) : (
                <ol className="relative space-y-5 border-l border-soc-border pl-5">
                  {steps.map((s) => (
                    <li key={s.id} className="relative">
                      <span className="absolute -left-[23px] top-1.5 h-2 w-2 rounded-full bg-soc-accent" />
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-[11px] text-soc-muted">#{s.step_number}</span>
                        <span
                          className={`inline-flex items-center rounded-md px-2 py-0.5 text-[11px] font-medium ring-1 ring-inset ${
                            AGENT_TONE[s.agent_type] ?? "bg-soc-panel2 text-soc-muted ring-soc-border"
                          }`}
                        >
                          {titleCase(s.agent_type)}
                        </span>
                        <span className="font-mono text-xs text-soc-text">{s.action}</span>
                        {s.action === "conclude_rejected" && (
                          <Badge tone="danger">rejected — citation did not resolve</Badge>
                        )}
                        <span className="text-[11px] text-soc-muted">{absoluteTime(s.step_started_at)}</span>
                      </div>

                      {s.reasoning_note && (
                        <p className="mt-1 text-xs italic leading-relaxed text-soc-muted">{s.reasoning_note}</p>
                      )}

                      {Object.keys(s.tool_input ?? {}).length > 0 && (
                        <pre className="mt-1.5 overflow-x-auto rounded-lg bg-soc-bg p-2 font-mono text-[10px] text-soc-muted">
                          in: {JSON.stringify(s.tool_input)}
                        </pre>
                      )}
                      <pre className="mt-1 max-h-40 overflow-auto rounded-lg bg-soc-bg p-2 font-mono text-[10px] text-soc-muted">
                        out: {JSON.stringify(s.tool_output, null, 2)}
                      </pre>

                      {s.evidence.length > 0 && (
                        <div className="mt-2 space-y-1">
                          {s.evidence.map((e, i) => (
                            <div key={i} className="rounded-lg border border-soc-border/60 p-2 text-[11px]">
                              <div className="text-soc-text">{e.claim}</div>
                              <div className="mt-0.5 font-mono text-[10px] text-soc-muted">
                                {e.source_tool}
                                {e.source_event_id
                                  ? ` · event ${e.source_event_id.slice(0, 8)}`
                                  : ` · ${e.source_table ?? "non-event source"}`}
                                {` · confidence ${e.confidence}`}
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </li>
                  ))}
                </ol>
              )}
            </Panel>
          </div>
        </>
      )}
    </div>
  );
}
