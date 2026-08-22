"use client";

import { ArrowLeft } from "lucide-react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useCallback, useEffect, useState } from "react";

import type { Alert } from "@/app/alerts/page";
import {
  Badge,
  Button,
  EmptyState,
  ErrorState,
  KeyValue,
  Loading,
  PageHeader,
  Panel,
  Select,
  SeverityBadge,
  StatusBadge,
  Table,
  Td,
} from "@/components/ui/primitives";
import { useAuth } from "@/lib/auth";
import { absoluteTime, relativeTime } from "@/lib/format";
import { apiGet, apiPatch, apiPost, ApiError } from "@/services/api";

interface IOC {
  id: string;
  ioc_type: string;
  value: string;
  reputation: string;
  threat_score: number;
}

interface Investigation {
  id: string;
  status: string;
  ai_provider: string;
  ai_model: string;
  result: Record<string, any> | null;
  error: string | null;
}

export default function AlertDetailPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const can = useAuth((s) => s.can);

  const [alert, setAlert] = useState<Alert | null>(null);
  const [iocs, setIocs] = useState<IOC[] | null>(null);
  const [investigation, setInvestigation] = useState<Investigation | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      setAlert(await apiGet<Alert>(`/v1/alerts/${id}`));
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Failed to load this alert.");
    }
  }, [id]);

  useEffect(() => {
    void load();
  }, [load]);

  async function setStatus(status: string) {
    setBusy("status");
    try {
      setAlert(await apiPatch<Alert>(`/v1/alerts/${id}`, { status }));
      setNotice(null);
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Update failed.");
    } finally {
      setBusy(null);
    }
  }

  async function enrich() {
    setBusy("enrich");
    setError(null);
    try {
      const res = await apiPost<{ extracted: number; malicious: number; iocs: IOC[] }>(
        `/v1/threat-intel/alerts/${id}/enrich`,
        {}
      );
      setIocs(res.iocs);
      setNotice(
        res.extracted === 0
          ? "No externally-scoreable indicators were found in this alert's cited events."
          : `Extracted ${res.extracted} indicator(s); ${res.malicious} scored malicious.`
      );
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Enrichment failed.");
    } finally {
      setBusy(null);
    }
  }

  async function investigate() {
    setBusy("investigate");
    setError(null);
    try {
      setInvestigation(await apiPost<Investigation>("/v1/ai/investigations", { alert_id: id }));
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Investigation failed to start.");
    } finally {
      setBusy(null);
    }
  }

  async function promote() {
    if (!investigation) return;
    setBusy("promote");
    setError(null);
    try {
      const res = await apiPost<{ incident: { id: string } }>("/v1/incidents/from-investigation", {
        investigation_id: investigation.id,
      });
      router.push(`/incidents/${res.incident.id}`);
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Promotion failed.");
    } finally {
      setBusy(null);
    }
  }

  if (!alert && !error) return <Panel><Loading /></Panel>;

  return (
    <div className="space-y-6">
      <Link href="/alerts" className="inline-flex items-center gap-1.5 text-xs text-soc-muted hover:text-soc-text">
        <ArrowLeft size={14} /> Back to alerts
      </Link>

      {error && <ErrorState message={error} />}

      {alert && (
        <>
          <PageHeader
            title={alert.title}
            subtitle={alert.description || undefined}
            actions={
              <div className="flex flex-wrap items-center gap-2">
                {can("alerts.update") && (
                  <Select
                    label="Status"
                    value={alert.status}
                    onChange={setStatus}
                    options={[
                      { value: "new", label: "New" },
                      { value: "triaged", label: "Triaged" },
                      { value: "investigating", label: "Investigating" },
                      { value: "escalated", label: "Escalated" },
                      { value: "false_positive", label: "False positive" },
                      { value: "closed", label: "Closed" },
                    ]}
                  />
                )}
                {can("threat_intel.lookup") && (
                  <Button onClick={enrich} disabled={busy === "enrich"}>
                    {busy === "enrich" ? "Enriching…" : "Enrich indicators"}
                  </Button>
                )}
                {can("ai.investigate") && (
                  <Button variant="primary" onClick={investigate} disabled={busy === "investigate"}>
                    {busy === "investigate" ? "Investigating…" : "Investigate with AI"}
                  </Button>
                )}
              </div>
            }
          />

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            <Panel className="lg:col-span-2">
              <h2 className="mb-4 text-sm font-medium text-soc-text">Alert</h2>
              <KeyValue
                items={[
                  ["Severity", <SeverityBadge key="s" severity={alert.severity} />],
                  ["Risk score", <span key="r" className="tabular-nums font-semibold">{alert.risk_score}</span>],
                  ["Status", <StatusBadge key="st" status={alert.status} />],
                  ["Source", <span key="src" className="font-mono text-xs">{alert.source}</span>],
                  ["Host", <span key="h" className="font-mono text-xs">{alert.host_name ?? "—"}</span>],
                  ["User", <span key="u" className="font-mono text-xs">{alert.user ?? "—"}</span>],
                  ["Alert time", <span key="t" className="font-mono text-xs">{absoluteTime(alert.alert_timestamp)}</span>],
                  [
                    "ATT&CK",
                    alert.mitre_technique_ids.length ? (
                      <div key="m" className="flex flex-wrap gap-1">
                        {alert.mitre_technique_ids.map((t) => (
                          <Badge key={t} tone="accent">{t}</Badge>
                        ))}
                      </div>
                    ) : (
                      "—"
                    ),
                  ],
                ]}
              />
            </Panel>

            <Panel>
              <h2 className="mb-3 text-sm font-medium text-soc-text">Evidence</h2>
              <p className="mb-2 text-[11px] text-soc-muted">
                The structured snapshot the detection cited when it fired. {alert.related_event_ids.length} event(s)
                referenced.
              </p>
              <pre className="max-h-72 overflow-auto rounded-lg bg-soc-bg p-3 font-mono text-[11px] leading-relaxed text-soc-muted">
                {JSON.stringify(alert.evidence, null, 2)}
              </pre>
            </Panel>
          </div>

          {notice && (
            <Panel>
              <div className="text-xs text-soc-text">{notice}</div>
            </Panel>
          )}

          {iocs && iocs.length > 0 && (
            <div>
              <h2 className="mb-2 text-sm font-medium text-soc-text">Extracted indicators</h2>
              <Table head={["Type", "Value", "Reputation", "Score"]}>
                {iocs.map((i) => (
                  <tr key={i.id}>
                    <Td className="text-xs uppercase text-soc-muted">{i.ioc_type}</Td>
                    <Td className="font-mono text-xs">{i.value}</Td>
                    <Td><StatusBadge status={i.reputation} /></Td>
                    <Td className="tabular-nums">{i.threat_score}</Td>
                  </tr>
                ))}
              </Table>
            </div>
          )}

          {investigation && (
            <Panel>
              <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
                <h2 className="text-sm font-medium text-soc-text">AI investigation</h2>
                <div className="flex items-center gap-2">
                  <StatusBadge status={investigation.status} />
                  <Badge>{investigation.ai_provider} · {investigation.ai_model}</Badge>
                  <Link href={`/ai/${investigation.id}`} className="text-xs text-soc-accent hover:underline">
                    Full agent trace
                  </Link>
                  {can("incidents.create") && investigation.status === "completed" && (
                    <Button variant="primary" onClick={promote} disabled={busy === "promote"}>
                      {busy === "promote" ? "Promoting…" : "Promote to incident"}
                    </Button>
                  )}
                </div>
              </div>

              {investigation.error && <ErrorState message={investigation.error} />}

              {investigation.result ? (
                <div className="space-y-4">
                  <p className="text-sm leading-relaxed text-soc-text">{investigation.result.summary}</p>

                  <div>
                    <h3 className="mb-1.5 text-[11px] uppercase tracking-widest text-soc-muted">
                      Observed evidence — every claim carries the tool and row it came from
                    </h3>
                    <ul className="space-y-1.5">
                      {(investigation.result.observed_evidence ?? []).map((e: any, i: number) => (
                        <li key={i} className="rounded-lg bg-soc-bg p-2.5 text-xs">
                          <div className="text-soc-text">{e.claim}</div>
                          <div className="mt-1 font-mono text-[10px] text-soc-muted">
                            {e.source_tool}
                            {e.source_event_id ? ` · event ${e.source_event_id.slice(0, 8)}` : ` · ${e.source_table ?? "non-event source"}`}
                            {" · confidence "}
                            {e.confidence}
                          </div>
                        </li>
                      ))}
                    </ul>
                  </div>

                  {(investigation.result.recommended_containment ?? []).length > 0 && (
                    <div>
                      <h3 className="mb-1.5 text-[11px] uppercase tracking-widest text-soc-muted">
                        Recommended containment — proposals only, each needs human approval
                      </h3>
                      <ul className="space-y-1.5">
                        {investigation.result.recommended_containment.map((c: any, i: number) => (
                          <li key={i} className="rounded-lg bg-soc-bg p-2.5 text-xs">
                            <div className="flex items-center gap-2">
                              <Badge tone="danger">{c.action}</Badge>
                              <span className="font-mono text-soc-text">{c.target}</span>
                              <Badge tone="accent">requires approval</Badge>
                            </div>
                            <div className="mt-1 text-soc-muted">{c.reasoning}</div>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              ) : (
                <EmptyState title="No structured result" hint="The investigation did not produce a validated report." />
              )}
            </Panel>
          )}

          <p className="text-[11px] text-soc-muted">Last loaded {relativeTime(new Date().toISOString())}.</p>
        </>
      )}
    </div>
  );
}
