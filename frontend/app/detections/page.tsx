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
  SeverityBadge,
  StatTile,
  Table,
  Td,
  TextInput,
} from "@/components/ui/primitives";
import { relativeTime } from "@/lib/format";
import { apiGet, apiPost, ApiError, qs } from "@/services/api";

interface DetectionRule {
  id: string;
  rule_id: string;
  title: string;
  description: string;
  engine: string;
  level: string;
  status: string;
  enabled: boolean;
  mitre_technique_ids: string[];
  base_risk_score: number;
  source_path: string | null;
}

interface Detection {
  id: string;
  rule_id: string;
  host_name: string | null;
  user: string | null;
  fired_at: string;
  risk_score: number;
  evidence_summary: Record<string, unknown>;
  matched_event_ids: string[];
}

const ENGINE_LABEL: Record<string, string> = {
  sigma: "Sigma",
  custom_python: "Custom",
  behavioral_correlation: "Behavioral",
};

const LEVEL_BADGE: Record<string, "danger" | "accent" | "neutral"> = {
  critical: "danger",
  high: "danger",
  medium: "accent",
  low: "neutral",
  informational: "neutral",
};

export default function DetectionsPage() {
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [recentFirings, setRecentFirings] = useState<Detection[]>([]);
  const [engineFilter, setEngineFilter] = useState("");
  const [host, setHost] = useState("");
  const [runLoading, setRunLoading] = useState(false);
  const [runResult, setRunResult] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [rulesData, firingsData] = await Promise.all([
        apiGet<DetectionRule[]>(`/v1/detections/rules${qs({ engine: engineFilter })}`),
        apiGet<Detection[]>(`/v1/detections${qs({ host, limit: 50 })}`),
      ]);
      setRules(rulesData);
      setRecentFirings(firingsData);
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Failed to load detection data.");
    } finally {
      setLoading(false);
    }
  }, [engineFilter, host]);

  useEffect(() => {
    void load();
  }, [load]);

  async function triggerRun() {
    setRunLoading(true);
    setRunResult(null);
    try {
      const result = await apiPost<{ detections_fired: number }>("/v1/detections/run");
      setRunResult(`Sweep complete — ${result.detections_fired} detection(s) fired.`);
      void load();
    } catch (err) {
      setRunResult(err instanceof ApiError ? `Failed: ${err.detail}` : "Sweep failed.");
    } finally {
      setRunLoading(false);
    }
  }

  const enabledRules = rules.filter((r) => r.enabled).length;
  const sigmaRules = rules.filter((r) => r.engine === "sigma").length;
  const customRules = rules.filter((r) => r.engine !== "sigma").length;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Detection Engineering"
        subtitle="Loaded detection rules, recent firings, and manual sweep controls. Rules are synced from code and YAML on startup — the database reflects exactly what is loaded."
        actions={
          <Button
            variant="primary"
            onClick={triggerRun}
            disabled={runLoading}
          >
            {runLoading ? "Running…" : "Run detection sweep"}
          </Button>
        }
      />

      {runResult && (
        <Panel className="text-sm text-soc-text">
          {runResult}
        </Panel>
      )}

      {error && <ErrorState message={error} />}

      {loading && !rules.length && (
        <Panel>
          <Loading label="Loading detection catalog…" />
        </Panel>
      )}

      {!loading && (
        <>
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            <StatTile label="Total rules" value={rules.length} hint="Loaded from code and YAML" />
            <StatTile
              label="Enabled"
              value={enabledRules}
              hint={`${rules.length - enabledRules} disabled`}
              tone={enabledRules === 0 ? "danger" : undefined}
            />
            <StatTile label="Sigma rules" value={sigmaRules} hint="YAML-defined patterns" />
            <StatTile label="Custom rules" value={customRules} hint="Python behavioral detections" />
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <Select
              label="Engine"
              value={engineFilter}
              onChange={setEngineFilter}
              options={[
                { value: "", label: "All engines" },
                { value: "sigma", label: "Sigma" },
                { value: "custom_python", label: "Custom Python" },
                { value: "behavioral_correlation", label: "Behavioral" },
              ]}
            />
            <TextInput
              value={host}
              onChange={setHost}
              placeholder="Filter firings by host…"
            />
          </div>

          <section>
            <h2 className="mb-3 text-sm font-medium text-soc-text">Detection rules</h2>
            {rules.length === 0 ? (
              <Panel>
                <EmptyState
                  title="No rules loaded"
                  hint="Detection rules are synced from detections/ and app/detections/custom/ on startup. Run the backend and check the logs."
                />
              </Panel>
            ) : (
              <Table head={["Rule", "Engine", "Level", "MITRE", "Base score", "Status"]}>
                {rules.map((rule) => (
                  <tr key={rule.id}>
                    <Td>
                      <div className="font-medium text-soc-text">{rule.title}</div>
                      <div className="mt-0.5 font-mono text-[11px] text-soc-muted">{rule.rule_id}</div>
                      {rule.description && (
                        <div className="mt-1 max-w-md text-[11px] text-soc-muted line-clamp-2">
                          {rule.description}
                        </div>
                      )}
                    </Td>
                    <Td>
                      <Badge tone="neutral">{ENGINE_LABEL[rule.engine] ?? rule.engine}</Badge>
                    </Td>
                    <Td>
                      <Badge tone={LEVEL_BADGE[rule.level] ?? "neutral"}>
                        {rule.level}
                      </Badge>
                    </Td>
                    <Td>
                      {rule.mitre_technique_ids.length === 0 ? (
                        <span className="text-soc-muted">—</span>
                      ) : (
                        <div className="flex flex-wrap gap-1">
                          {rule.mitre_technique_ids.map((t) => (
                            <Badge key={t} tone="neutral">
                              {t}
                            </Badge>
                          ))}
                        </div>
                      )}
                    </Td>
                    <Td>
                      <span className="tabular-nums text-soc-text">{rule.base_risk_score}</span>
                    </Td>
                    <Td>
                      {rule.enabled ? (
                        <Badge tone="success">enabled</Badge>
                      ) : (
                        <Badge tone="neutral">disabled</Badge>
                      )}
                    </Td>
                  </tr>
                ))}
              </Table>
            )}
          </section>

          <section>
            <h2 className="mb-3 text-sm font-medium text-soc-text">
              Recent firings
              <span className="ml-2 text-[11px] font-normal text-soc-muted">
                (last 50 — most recent first)
              </span>
            </h2>
            {recentFirings.length === 0 ? (
              <Panel>
                <EmptyState
                  title="No detections fired yet"
                  hint="Ingest telemetry via the events API or the Simulation Lab, then run a detection sweep."
                />
              </Panel>
            ) : (
              <Table head={["Rule", "Host", "User", "Risk", "Fired at", "Events"]}>
                {recentFirings.map((d) => {
                  const rule = rules.find((r) => r.id === d.rule_id);
                  return (
                    <tr key={d.id}>
                      <Td>
                        <span className="text-soc-text">
                          {rule ? rule.title : <span className="font-mono text-xs text-soc-muted">{d.rule_id.slice(0, 8)}</span>}
                        </span>
                        {rule && (
                          <Badge tone="neutral" className="ml-2">
                            {ENGINE_LABEL[rule.engine] ?? rule.engine}
                          </Badge>
                        )}
                      </Td>
                      <Td>
                        <span className="font-mono text-xs">{d.host_name ?? "—"}</span>
                      </Td>
                      <Td>
                        <span className="font-mono text-xs">{d.user ?? "—"}</span>
                      </Td>
                      <Td>
                        <SeverityBadge
                          severity={
                            d.risk_score >= 85
                              ? "CRITICAL"
                              : d.risk_score >= 65
                                ? "HIGH"
                                : d.risk_score >= 40
                                  ? "MEDIUM"
                                  : d.risk_score >= 20
                                    ? "LOW"
                                    : "INFO"
                          }
                        />
                        <span className="ml-2 tabular-nums text-xs text-soc-muted">{d.risk_score}</span>
                      </Td>
                      <Td>
                        <span className="text-xs text-soc-muted">{relativeTime(d.fired_at)}</span>
                      </Td>
                      <Td>
                        <span className="tabular-nums text-xs text-soc-muted">
                          {d.matched_event_ids.length}
                        </span>
                      </Td>
                    </tr>
                  );
                })}
              </Table>
            )}
          </section>
        </>
      )}
    </div>
  );
}
