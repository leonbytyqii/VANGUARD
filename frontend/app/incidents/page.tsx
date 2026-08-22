"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";

import {
  Button,
  EmptyState,
  ErrorState,
  Loading,
  PageHeader,
  Panel,
  Select,
  SeverityBadge,
  StatusBadge,
  Table,
  Td,
  TextInput,
} from "@/components/ui/primitives";
import { useAuth } from "@/lib/auth";
import { relativeTime } from "@/lib/format";
import { apiGet, apiPost, ApiError, qs } from "@/services/api";

export interface Incident {
  id: string;
  incident_number: number | null;
  reference: string | null;
  title: string;
  summary: string;
  status: string;
  severity: string;
  assigned_to_id: string | null;
  detected_at: string | null;
  closed_at: string | null;
  closure_classification: string | null;
  created_at: string;
  alert_ids: string[];
  mitre_technique_ids: string[];
}

export default function IncidentsPage() {
  const can = useAuth((s) => s.can);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");
  const [openOnly, setOpenOnly] = useState("false");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [creating, setCreating] = useState(false);
  const [title, setTitle] = useState("");
  const [newSeverity, setNewSeverity] = useState("MEDIUM");

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setIncidents(
        await apiGet<Incident[]>(
          `/v1/incidents${qs({ status, severity, open_only: openOnly === "true", limit: 200 })}`
        )
      );
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Failed to load incidents.");
    } finally {
      setLoading(false);
    }
  }, [status, severity, openOnly]);

  useEffect(() => {
    void load();
  }, [load]);

  async function create() {
    if (!title.trim()) return;
    setCreating(true);
    setError(null);
    try {
      await apiPost("/v1/incidents", { title: title.trim(), severity: newSeverity });
      setTitle("");
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Could not create the incident.");
    } finally {
      setCreating(false);
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Incidents"
        subtitle="Case management over the NIST SP 800-61r2 lifecycle. Every case carries an append-only timeline, a response checklist, and IR metrics measured from first evidence."
      />

      <Panel className="flex flex-wrap items-center gap-3">
        <Select
          label="Status"
          value={status}
          onChange={setStatus}
          options={[
            { value: "", label: "All" },
            { value: "new", label: "New" },
            { value: "triaged", label: "Triaged" },
            { value: "investigating", label: "Investigating" },
            { value: "contained", label: "Contained" },
            { value: "eradicated", label: "Eradicated" },
            { value: "recovered", label: "Recovered" },
            { value: "closed", label: "Closed" },
          ]}
        />
        <Select
          label="Severity"
          value={severity}
          onChange={setSeverity}
          options={[
            { value: "", label: "All" },
            { value: "CRITICAL", label: "Critical" },
            { value: "HIGH", label: "High" },
            { value: "MEDIUM", label: "Medium" },
            { value: "LOW", label: "Low" },
            { value: "INFO", label: "Info" },
          ]}
        />
        <Select
          label="Show"
          value={openOnly}
          onChange={setOpenOnly}
          options={[
            { value: "false", label: "All cases" },
            { value: "true", label: "Open only" },
          ]}
        />
        <span className="ml-auto text-xs text-soc-muted">{incidents.length} shown</span>
      </Panel>

      {can("incidents.create") && (
        <Panel className="flex flex-wrap items-center gap-3">
          <span className="text-xs text-soc-muted">New case</span>
          <TextInput value={title} onChange={setTitle} placeholder="Incident title" className="min-w-64 flex-1" onEnter={create} />
          <Select
            value={newSeverity}
            onChange={setNewSeverity}
            options={[
              { value: "CRITICAL", label: "Critical" },
              { value: "HIGH", label: "High" },
              { value: "MEDIUM", label: "Medium" },
              { value: "LOW", label: "Low" },
              { value: "INFO", label: "Info" },
            ]}
          />
          <Button variant="primary" onClick={create} disabled={creating || !title.trim()}>
            {creating ? "Creating…" : "Open case"}
          </Button>
        </Panel>
      )}

      {error && <ErrorState message={error} />}
      {loading && <Panel><Loading /></Panel>}

      {!loading && incidents.length === 0 && !error && (
        <Panel>
          <EmptyState
            title="No incidents match these filters"
            hint="Cases are opened manually, from one or more alerts, or by promoting a completed AI investigation."
          />
        </Panel>
      )}

      {!loading && incidents.length > 0 && (
        <Table head={["Case", "Severity", "Title", "Status", "Alerts", "Detected", ""]}>
          {incidents.map((i) => (
            <tr key={i.id} className="hover:bg-soc-panel2/40">
              <Td className="whitespace-nowrap font-mono text-xs">{i.reference ?? "—"}</Td>
              <Td><SeverityBadge severity={i.severity} /></Td>
              <Td>
                <div className="text-soc-text">{i.title}</div>
                {i.closure_classification && (
                  <div className="mt-0.5 text-[11px] text-soc-muted">
                    closed as {i.closure_classification.replace(/_/g, " ")}
                  </div>
                )}
              </Td>
              <Td><StatusBadge status={i.status} /></Td>
              <Td className="tabular-nums text-xs">{i.alert_ids.length}</Td>
              <Td className="whitespace-nowrap text-xs text-soc-muted">{relativeTime(i.detected_at)}</Td>
              <Td>
                <Link href={`/incidents/${i.id}`} className="text-xs text-soc-accent hover:underline">
                  Open
                </Link>
              </Td>
            </tr>
          ))}
        </Table>
      )}
    </div>
  );
}
