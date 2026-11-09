"use client";

import { useCallback, useEffect, useState } from "react";

import {
  Badge,
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
import { apiGet, ApiError, qs } from "@/services/api";

interface Alert {
  id: string;
  title: string;
  severity: string;
  risk_score: number;
  status: string;
  host_name: string | null;
  user: string | null;
  alert_timestamp: string;
  mitre_technique_ids: string[];
}

interface EntityRiskRow {
  name: string;
  kind: "host" | "user";
  maxScore: number;
  alertCount: number;
  openCount: number;
  topSeverity: string;
  techniques: string[];
  lastSeen: string;
}

const OPEN_STATUSES = new Set(["new", "triaged", "investigating", "escalated"]);

function computeEntityRisk(alerts: Alert[], kind: "host" | "user"): EntityRiskRow[] {
  const map = new Map<string, EntityRiskRow>();

  for (const alert of alerts) {
    const name = kind === "host" ? alert.host_name : alert.user;
    if (!name) continue;

    const existing = map.get(name);
    if (!existing) {
      map.set(name, {
        name,
        kind,
        maxScore: alert.risk_score,
        alertCount: 1,
        openCount: OPEN_STATUSES.has(alert.status) ? 1 : 0,
        topSeverity: alert.severity,
        techniques: [...alert.mitre_technique_ids],
        lastSeen: alert.alert_timestamp,
      });
    } else {
      existing.alertCount++;
      if (OPEN_STATUSES.has(alert.status)) existing.openCount++;
      if (alert.risk_score > existing.maxScore) {
        existing.maxScore = alert.risk_score;
        existing.topSeverity = alert.severity;
      }
      for (const t of alert.mitre_technique_ids) {
        if (!existing.techniques.includes(t)) existing.techniques.push(t);
      }
      if (alert.alert_timestamp > existing.lastSeen) {
        existing.lastSeen = alert.alert_timestamp;
      }
    }
  }

  return Array.from(map.values()).sort((a, b) => b.maxScore - a.maxScore || b.alertCount - a.alertCount);
}

export default function EntityRiskPage() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [viewKind, setViewKind] = useState<"host" | "user">("host");
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      // Fetch a broad window of alerts to compute entity risk.
      // We request the max page size and all statuses (open + closed) so
      // the risk picture includes resolved activity, not just the active queue.
      const data = await apiGet<Alert[]>(`/v1/alerts${qs({ limit: 500 })}`);
      setAlerts(data);
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Failed to load alert data.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const entities = computeEntityRisk(alerts, viewKind);
  const filtered = search
    ? entities.filter((e) => e.name.toLowerCase().includes(search.toLowerCase()))
    : entities;

  const highRisk = entities.filter((e) => e.maxScore >= 65).length;
  const criticalRisk = entities.filter((e) => e.maxScore >= 85).length;
  const withOpenAlerts = entities.filter((e) => e.openCount > 0).length;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Entity Risk"
        subtitle="Risk derived from alert history — max risk score, open alert count, MITRE technique exposure. Scores use the same documented formula as individual alerts. Computed client-side from the alert index; a server-side entity-risk table is a future enhancement."
      />

      {error && <ErrorState message={error} />}

      {loading && (
        <Panel>
          <Loading label="Building entity risk picture…" />
        </Panel>
      )}

      {!loading && (
        <>
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            <StatTile
              label={`${viewKind === "host" ? "Hosts" : "Users"} tracked`}
              value={entities.length}
              hint="Entities seen in alert history"
            />
            <StatTile
              label="High or critical risk"
              value={highRisk}
              hint="Max alert score ≥ 65"
              tone={highRisk > 0 ? "warn" : undefined}
            />
            <StatTile
              label="Critical risk"
              value={criticalRisk}
              hint="Max alert score ≥ 85"
              tone={criticalRisk > 0 ? "danger" : undefined}
            />
            <StatTile
              label="With open alerts"
              value={withOpenAlerts}
              hint="At least one unresolved alert"
              tone={withOpenAlerts > 0 ? "warn" : undefined}
            />
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <Select
              label="View"
              value={viewKind}
              onChange={(v) => setViewKind(v as "host" | "user")}
              options={[
                { value: "host", label: "Hosts" },
                { value: "user", label: "Users" },
              ]}
            />
            <TextInput
              value={search}
              onChange={setSearch}
              placeholder={`Filter by ${viewKind} name…`}
            />
          </div>

          {filtered.length === 0 ? (
            <Panel>
              <EmptyState
                title={`No ${viewKind} risk data`}
                hint={
                  alerts.length === 0
                    ? "No alerts have been generated yet. Ingest telemetry and run detections to populate entity risk."
                    : `No ${viewKind} names found in alerts. Try switching to ${viewKind === "host" ? "Users" : "Hosts"}.`
                }
              />
            </Panel>
          ) : (
            <Table head={["Entity", "Max risk", "Open alerts", "Total alerts", "MITRE techniques", "Last alert"]}>
              {filtered.map((entity) => (
                <tr key={entity.name}>
                  <Td>
                    <span className="font-mono text-sm text-soc-text">{entity.name}</span>
                    <Badge tone="neutral" className="ml-2 capitalize">
                      {entity.kind}
                    </Badge>
                  </Td>
                  <Td>
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={entity.topSeverity} />
                      <span className="tabular-nums text-xs text-soc-muted">{entity.maxScore}</span>
                    </div>
                    <div className="mt-1 h-1 w-24 overflow-hidden rounded-full bg-soc-panel2">
                      <div
                        className="h-full rounded-full"
                        style={{
                          width: `${entity.maxScore}%`,
                          backgroundColor:
                            entity.maxScore >= 85
                              ? "#ef4444"
                              : entity.maxScore >= 65
                                ? "#f97316"
                                : entity.maxScore >= 40
                                  ? "#eab308"
                                  : "#3b82f6",
                        }}
                      />
                    </div>
                  </Td>
                  <Td>
                    <span
                      className={
                        entity.openCount > 0
                          ? "font-semibold tabular-nums text-soc-high"
                          : "tabular-nums text-soc-muted"
                      }
                    >
                      {entity.openCount}
                    </span>
                  </Td>
                  <Td>
                    <span className="tabular-nums text-soc-text">{entity.alertCount}</span>
                  </Td>
                  <Td>
                    {entity.techniques.length === 0 ? (
                      <span className="text-soc-muted">—</span>
                    ) : (
                      <div className="flex flex-wrap gap-1">
                        {entity.techniques.slice(0, 4).map((t) => (
                          <Badge key={t} tone="neutral">
                            {t}
                          </Badge>
                        ))}
                        {entity.techniques.length > 4 && (
                          <Badge tone="neutral">+{entity.techniques.length - 4}</Badge>
                        )}
                      </div>
                    )}
                  </Td>
                  <Td>
                    <span className="text-xs text-soc-muted">{relativeTime(entity.lastSeen)}</span>
                  </Td>
                </tr>
              ))}
            </Table>
          )}

          <p className="text-[11px] text-soc-muted">
            Entity risk is derived from up to 500 recent alerts per organization. The score shown is the
            highest single alert score for this entity, not a rolling aggregate — a server-side entity-risk
            engine with decay, temporal weighting, and a dedicated <code>entity_risk</code> table is planned
            as a future enhancement. Unknown/clean is not the same as safe — an entity with no alerts may
            simply not yet have been observed.
          </p>
        </>
      )}
    </div>
  );
}
