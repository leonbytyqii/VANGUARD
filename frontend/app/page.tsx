"use client";

import { useCallback, useEffect, useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import {
  EmptyState,
  ErrorState,
  Loading,
  PageHeader,
  Panel,
  Select,
  StatTile,
  Table,
  Td,
} from "@/components/ui/primitives";
import { duration, relativeTime } from "@/lib/format";
import { apiGet, ApiError, qs } from "@/services/api";

interface Overview {
  generated_at: string;
  window_hours: number;
  events_total: number;
  events_in_window: number;
  alerts_total: number;
  alerts_open: number;
  alerts_in_window: number;
  alerts_by_severity: { info: number; low: number; medium: number; high: number; critical: number };
  incidents_total: number;
  incidents_open: number;
  incidents_by_status: Record<string, number>;
  incidents_closed_in_window: number;
  mean_time_to_triage_seconds: number | null;
  mean_time_to_contain_seconds: number | null;
  mean_time_to_close_seconds: number | null;
  pending_approvals: number;
  ai_investigations_total: number;
  ai_investigations_in_window: number;
  iocs_total: number;
  iocs_malicious: number;
  attack_paths_total: number;
  attack_paths_with_escalation: number;
  alert_timeseries: { bucket: string; count: number }[];
  top_hosts: { name: string; count: number }[];
  top_users: { name: string; count: number }[];
  top_rules: { name: string; count: number }[];
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
  info: "#64748b",
};

export default function DashboardPage() {
  const [windowHours, setWindowHours] = useState("24");
  const [data, setData] = useState<Overview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setData(await apiGet<Overview>(`/v1/dashboard/overview${qs({ window_hours: windowHours })}`));
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Failed to load the SOC overview.");
    } finally {
      setLoading(false);
    }
  }, [windowHours]);

  useEffect(() => {
    void load();
  }, [load]);

  const chart = (data?.alert_timeseries ?? []).map((p) => ({
    hour: new Date(p.bucket).toISOString().slice(11, 16),
    count: p.count,
  }));

  const severityTotal = data
    ? Object.values(data.alerts_by_severity).reduce((a, b) => a + b, 0)
    : 0;

  return (
    <div className="space-y-6">
      <PageHeader
        title="SOC Overview"
        subtitle="Live operational picture across ingestion, detection, response, and the agentic investigation layer. Every figure is a tenant-scoped aggregate computed server-side."
        actions={
          <Select
            label="Window"
            value={windowHours}
            onChange={setWindowHours}
            options={[
              { value: "1", label: "Last hour" },
              { value: "24", label: "Last 24h" },
              { value: "168", label: "Last 7 days" },
              { value: "720", label: "Last 30 days" },
            ]}
          />
        }
      />

      {error && <ErrorState message={error} />}
      {loading && !data && <Panel><Loading label="Building the overview…" /></Panel>}

      {data && (
        <>
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            <StatTile
              label="Open alerts"
              value={data.alerts_open}
              hint={`${data.alerts_total} total · ${data.alerts_in_window} in window`}
              tone={data.alerts_open > 0 ? "warn" : undefined}
            />
            <StatTile
              label="Open incidents"
              value={data.incidents_open}
              hint={`${data.incidents_closed_in_window} closed in window`}
            />
            <StatTile
              label="Pending approvals"
              value={data.pending_approvals}
              hint="Privileged actions awaiting a human decision"
              tone={data.pending_approvals > 0 ? "danger" : undefined}
            />
            <StatTile
              label="Events ingested"
              value={data.events_total.toLocaleString()}
              hint={`${data.events_in_window.toLocaleString()} in window`}
            />
          </div>

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            <StatTile
              label="Mean time to triage"
              value={duration(data.mean_time_to_triage_seconds)}
              hint="Measured from first evidence, not case creation"
            />
            <StatTile
              label="Mean time to contain"
              value={duration(data.mean_time_to_contain_seconds)}
              hint="First containment only; regressions don't reset it"
            />
            <StatTile
              label="Mean time to close"
              value={duration(data.mean_time_to_close_seconds)}
              hint={
                data.incidents_closed_in_window === 0
                  ? "No incidents closed in this window"
                  : `Across ${data.incidents_closed_in_window} closed case(s)`
              }
            />
          </div>

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            <Panel className="lg:col-span-2">
              <h2 className="mb-4 text-sm font-medium text-soc-text">Alert volume by hour</h2>
              {chart.length === 0 ? (
                <EmptyState title="No alerts in this window" hint="Ingest telemetry via the simulation lab or the events API to populate this chart." />
              ) : (
                <div className="h-56">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={chart}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#22304566" vertical={false} />
                      <XAxis dataKey="hour" stroke="#8b98a9" fontSize={11} tickLine={false} axisLine={false} />
                      <YAxis stroke="#8b98a9" fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} />
                      <Tooltip
                        contentStyle={{
                          background: "#111823",
                          border: "1px solid #223045",
                          borderRadius: 8,
                          fontSize: 12,
                          color: "#e6edf3",
                        }}
                      />
                      <Bar dataKey="count" fill="#3ba3ff" radius={[3, 3, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}
            </Panel>

            <Panel>
              <h2 className="mb-4 text-sm font-medium text-soc-text">Alerts by severity</h2>
              {severityTotal === 0 ? (
                <EmptyState title="No alerts yet" />
              ) : (
                <div className="space-y-3">
                  {(["critical", "high", "medium", "low", "info"] as const).map((sev) => {
                    const count = data.alerts_by_severity[sev];
                    const pct = severityTotal ? (count / severityTotal) * 100 : 0;
                    return (
                      <div key={sev}>
                        <div className="mb-1 flex items-center justify-between text-xs">
                          <span className="uppercase tracking-wide text-soc-muted">{sev}</span>
                          <span className="tabular-nums text-soc-text">{count}</span>
                        </div>
                        <div className="h-1.5 overflow-hidden rounded-full bg-soc-panel2">
                          <div
                            className="h-full rounded-full"
                            style={{ width: `${pct}%`, backgroundColor: SEVERITY_COLORS[sev] }}
                          />
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </Panel>
          </div>

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
            <StatTile
              label="AI investigations"
              value={data.ai_investigations_total}
              hint={`${data.ai_investigations_in_window} in window`}
            />
            <StatTile
              label="Active indicators"
              value={data.iocs_total}
              hint={`${data.iocs_malicious} scored malicious`}
              tone={data.iocs_malicious > 0 ? "warn" : undefined}
            />
            <StatTile
              label="IAM attack paths"
              value={data.attack_paths_total}
              hint={`${data.attack_paths_with_escalation} with privilege escalation`}
              tone={data.attack_paths_with_escalation > 0 ? "danger" : undefined}
            />
            <StatTile
              label="Incidents by status"
              value={Object.keys(data.incidents_by_status).length === 0 ? "—" : data.incidents_total}
              hint={
                Object.entries(data.incidents_by_status)
                  .map(([k, v]) => `${k}: ${v}`)
                  .join(" · ") || "No incidents yet"
              }
            />
          </div>

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            <TopList title="Top hosts by alert volume" rows={data.top_hosts} />
            <TopList title="Top users by alert volume" rows={data.top_users} />
            <TopList title="Most active detection rules" rows={data.top_rules} />
          </div>

          <p className="text-[11px] text-soc-muted">
            Generated {relativeTime(data.generated_at)} · {data.window_hours}h window · nothing on this page is
            cached, so a refresh always reflects current state.
          </p>
        </>
      )}
    </div>
  );
}

function TopList({ title, rows }: { title: string; rows: { name: string; count: number }[] }) {
  return (
    <div>
      <h2 className="mb-2 text-sm font-medium text-soc-text">{title}</h2>
      {rows.length === 0 ? (
        <Panel>
          <div className="text-xs text-soc-muted">No data in this window.</div>
        </Panel>
      ) : (
        <Table head={["Name", "Count"]}>
          {rows.map((r) => (
            <tr key={r.name}>
              <Td className="font-mono text-xs">{r.name}</Td>
              <Td className="tabular-nums">{r.count}</Td>
            </tr>
          ))}
        </Table>
      )}
    </div>
  );
}
