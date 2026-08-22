"use client";

import { ArrowLeft, Bot, CheckCircle2, Circle } from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";

import type { Incident } from "@/app/incidents/page";
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
  StatTile,
  StatusBadge,
  Table,
  Td,
  TextInput,
} from "@/components/ui/primitives";
import { useAuth } from "@/lib/auth";
import { absoluteTime, duration, relativeTime, titleCase } from "@/lib/format";
import { apiDelete, apiGet, apiPatch, apiPost, ApiError } from "@/services/api";

interface Metrics {
  detected_at: string | null;
  triaged_at: string | null;
  contained_at: string | null;
  closed_at: string | null;
  time_to_triage_seconds: number | null;
  time_to_contain_seconds: number | null;
  time_to_close_seconds: number | null;
  open_duration_seconds: number | null;
  is_open: boolean;
  tasks_total: number;
  tasks_completed: number;
  alert_count: number;
}

interface IncidentDetail extends Incident {
  metrics: Metrics;
}

interface Task {
  id: string;
  title: string;
  description: string;
  category: string;
  done: boolean;
  sort_order: number;
  is_from_template: boolean;
  completed_at: string | null;
}

interface Note {
  id: string;
  body: string;
  is_ai_generated: boolean;
  created_at: string;
}

interface TimelineEntry {
  id: string;
  event_timestamp: string;
  kind: string;
  actor: string | null;
  details: Record<string, any>;
}

interface ResponseAction {
  id: string;
  action_type: string;
  target: string;
  status: string;
  justification: string;
  created_at: string;
}

interface IOC {
  id: string;
  ioc_type: string;
  value: string;
  reputation: string;
  threat_score: number;
}

const NEXT_STATUS: Record<string, string[]> = {
  new: ["triaged", "investigating", "closed"],
  triaged: ["investigating", "contained", "closed"],
  investigating: ["contained", "closed"],
  contained: ["eradicated", "investigating", "closed"],
  eradicated: ["recovered", "contained", "closed"],
  recovered: ["closed", "investigating"],
  closed: ["investigating"],
};

export default function IncidentDetailPage() {
  const { id } = useParams<{ id: string }>();
  const can = useAuth((s) => s.can);

  const [incident, setIncident] = useState<IncidentDetail | null>(null);
  const [tasks, setTasks] = useState<Task[]>([]);
  const [notes, setNotes] = useState<Note[]>([]);
  const [timeline, setTimeline] = useState<TimelineEntry[]>([]);
  const [actions, setActions] = useState<ResponseAction[]>([]);
  const [iocs, setIocs] = useState<IOC[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const [noteBody, setNoteBody] = useState("");
  const [newTask, setNewTask] = useState("");
  const [targetStatus, setTargetStatus] = useState("");
  const [classification, setClassification] = useState("true_positive");

  const load = useCallback(async () => {
    setError(null);
    try {
      const [i, t, n, tl, a, io] = await Promise.all([
        apiGet<IncidentDetail>(`/v1/incidents/${id}`),
        apiGet<Task[]>(`/v1/incidents/${id}/tasks`),
        apiGet<Note[]>(`/v1/incidents/${id}/notes`),
        apiGet<TimelineEntry[]>(`/v1/incidents/${id}/timeline`),
        apiGet<ResponseAction[]>(`/v1/incidents/${id}/response-actions`),
        apiGet<IOC[]>(`/v1/incidents/${id}/iocs`),
      ]);
      setIncident(i);
      setTasks(t);
      setNotes(n);
      setTimeline(tl);
      setActions(a);
      setIocs(io);
      setTargetStatus(NEXT_STATUS[i.status]?.[0] ?? "");
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Failed to load this incident.");
    }
  }, [id]);

  useEffect(() => {
    void load();
  }, [load]);

  async function act(fn: () => Promise<unknown>) {
    setBusy(true);
    setError(null);
    try {
      await fn();
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Action failed.");
    } finally {
      setBusy(false);
    }
  }

  if (!incident && !error) return <Panel><Loading /></Panel>;

  const closing = targetStatus === "closed";

  return (
    <div className="space-y-6">
      <Link href="/incidents" className="inline-flex items-center gap-1.5 text-xs text-soc-muted hover:text-soc-text">
        <ArrowLeft size={14} /> Back to incidents
      </Link>

      {error && <ErrorState message={error} />}

      {incident && (
        <>
          <PageHeader
            title={`${incident.reference ?? ""} ${incident.title}`.trim()}
            subtitle={incident.summary || undefined}
            actions={
              <div className="flex items-center gap-2">
                <SeverityBadge severity={incident.severity} />
                <StatusBadge status={incident.status} />
              </div>
            }
          />

          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            <StatTile label="Time to triage" value={duration(incident.metrics.time_to_triage_seconds)} />
            <StatTile label="Time to contain" value={duration(incident.metrics.time_to_contain_seconds)} />
            <StatTile
              label={incident.metrics.is_open ? "Open for" : "Time to close"}
              value={duration(
                incident.metrics.is_open
                  ? incident.metrics.open_duration_seconds
                  : incident.metrics.time_to_close_seconds
              )}
            />
            <StatTile
              label="Checklist"
              value={`${incident.metrics.tasks_completed}/${incident.metrics.tasks_total}`}
              hint="NIST SP 800-61r2 response checklist"
            />
          </div>

          {can("incidents.update") && (
            <Panel className="flex flex-wrap items-end gap-3">
              <Select
                label="Advance to"
                value={targetStatus}
                onChange={setTargetStatus}
                options={(NEXT_STATUS[incident.status] ?? []).map((s) => ({ value: s, label: titleCase(s) }))}
              />
              {closing && (
                <Select
                  label="Verdict"
                  value={classification}
                  onChange={setClassification}
                  options={[
                    { value: "true_positive", label: "True positive" },
                    { value: "false_positive", label: "False positive" },
                    { value: "benign_true_positive", label: "Benign (authorized)" },
                    { value: "duplicate", label: "Duplicate" },
                  ]}
                />
              )}
              <Button
                variant="primary"
                disabled={busy || !targetStatus}
                onClick={() =>
                  act(() =>
                    apiPatch(`/v1/incidents/${id}/status`, {
                      status: targetStatus,
                      ...(closing ? { closure_classification: classification } : {}),
                    })
                  )
                }
              >
                {incident.status === "closed" ? "Reopen case" : "Apply transition"}
              </Button>
              <p className="w-full text-[11px] text-soc-muted">
                Closing requires a verdict so detection precision stays measurable. Reaching{" "}
                <span className="text-soc-text">contained</span> records that containment happened — it does not
                execute anything.
              </p>
            </Panel>
          )}

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            <Panel className="lg:col-span-2">
              <h2 className="mb-4 text-sm font-medium text-soc-text">Case</h2>
              <KeyValue
                items={[
                  ["Reference", <span key="r" className="font-mono text-xs">{incident.reference ?? "—"}</span>],
                  ["Detected", <span key="d" className="font-mono text-xs">{absoluteTime(incident.detected_at)}</span>],
                  ["Linked alerts", incident.alert_ids.length],
                  [
                    "ATT&CK",
                    incident.mitre_technique_ids.length ? (
                      <div key="m" className="flex flex-wrap gap-1">
                        {incident.mitre_technique_ids.map((t) => (
                          <Badge key={t} tone="accent">{t}</Badge>
                        ))}
                      </div>
                    ) : (
                      "—"
                    ),
                  ],
                  ["Closed", <span key="c" className="font-mono text-xs">{absoluteTime(incident.closed_at)}</span>],
                  ["Verdict", incident.closure_classification ? titleCase(incident.closure_classification) : "—"],
                ]}
              />
            </Panel>

            <Panel>
              <h2 className="mb-3 text-sm font-medium text-soc-text">Indicators</h2>
              {iocs.length === 0 ? (
                <div className="text-xs text-soc-muted">No indicators attached to this case.</div>
              ) : (
                <ul className="space-y-2">
                  {iocs.map((i) => (
                    <li key={i.id} className="flex items-center justify-between gap-2 text-xs">
                      <span className="truncate font-mono text-soc-text">{i.value}</span>
                      <StatusBadge status={i.reputation} />
                    </li>
                  ))}
                </ul>
              )}
            </Panel>
          </div>

          {/* -------------------------------------------------- checklist */}
          <div>
            <div className="mb-2 flex items-center justify-between">
              <h2 className="text-sm font-medium text-soc-text">Response checklist</h2>
              {can("incidents.update") && (
                <div className="flex items-center gap-2">
                  <TextInput value={newTask} onChange={setNewTask} placeholder="Add a task" onEnter={() => {
                    if (newTask.trim()) act(() => apiPost(`/v1/incidents/${id}/tasks`, { title: newTask.trim() })).then(() => setNewTask(""));
                  }} />
                  <Button
                    disabled={busy || !newTask.trim()}
                    onClick={() =>
                      act(() => apiPost(`/v1/incidents/${id}/tasks`, { title: newTask.trim() })).then(() => setNewTask(""))
                    }
                  >
                    Add
                  </Button>
                </div>
              )}
            </div>
            <Panel className="space-y-1">
              {tasks.length === 0 && <div className="text-xs text-soc-muted">No tasks on this case.</div>}
              {tasks.map((t) => (
                <div key={t.id} className="group flex items-start gap-3 rounded-lg px-2 py-2 hover:bg-soc-panel2/50">
                  <button
                    disabled={!can("incidents.update") || busy}
                    onClick={() => act(() => apiPatch(`/v1/incidents/${id}/tasks/${t.id}`, { done: !t.done }))}
                    className="mt-0.5 shrink-0 disabled:cursor-not-allowed"
                    aria-label={t.done ? "Mark incomplete" : "Mark complete"}
                  >
                    {t.done ? (
                      <CheckCircle2 size={16} className="text-soc-success" />
                    ) : (
                      <Circle size={16} className="text-soc-muted" />
                    )}
                  </button>
                  <div className="min-w-0 flex-1">
                    <div className={t.done ? "text-sm text-soc-muted line-through" : "text-sm text-soc-text"}>
                      {t.title}
                    </div>
                    {t.description && <div className="mt-0.5 text-[11px] leading-relaxed text-soc-muted">{t.description}</div>}
                  </div>
                  <Badge className="shrink-0">{titleCase(t.category)}</Badge>
                  {can("incidents.update") && !t.is_from_template && (
                    <button
                      onClick={() => act(() => apiDelete(`/v1/incidents/${id}/tasks/${t.id}`))}
                      className="shrink-0 text-[11px] text-soc-muted opacity-0 transition-opacity hover:text-soc-critical group-hover:opacity-100"
                    >
                      remove
                    </button>
                  )}
                </div>
              ))}
            </Panel>
          </div>

          {/* ------------------------------------------------------ notes */}
          <div>
            <h2 className="mb-2 text-sm font-medium text-soc-text">Notes</h2>
            {can("incidents.update") && (
              <Panel className="mb-3 flex items-center gap-2">
                <TextInput
                  value={noteBody}
                  onChange={setNoteBody}
                  placeholder="Add an analyst note…"
                  className="flex-1"
                  onEnter={() => {
                    if (noteBody.trim())
                      act(() => apiPost(`/v1/incidents/${id}/notes`, { body: noteBody.trim() })).then(() => setNoteBody(""));
                  }}
                />
                <Button
                  disabled={busy || !noteBody.trim()}
                  onClick={() =>
                    act(() => apiPost(`/v1/incidents/${id}/notes`, { body: noteBody.trim() })).then(() => setNoteBody(""))
                  }
                >
                  Add note
                </Button>
              </Panel>
            )}
            <Panel className="space-y-3">
              {notes.length === 0 && <div className="text-xs text-soc-muted">No notes yet.</div>}
              {notes.map((n) => (
                <div key={n.id} className="rounded-lg bg-soc-bg p-3">
                  <div className="mb-1 flex items-center gap-2 text-[11px] text-soc-muted">
                    {n.is_ai_generated ? (
                      <span className="inline-flex items-center gap-1 text-soc-accent">
                        <Bot size={12} /> AI-generated
                      </span>
                    ) : (
                      <span>Analyst</span>
                    )}
                    <span>·</span>
                    <span>{relativeTime(n.created_at)}</span>
                  </div>
                  <div className="whitespace-pre-wrap text-sm text-soc-text">{n.body}</div>
                </div>
              ))}
            </Panel>
          </div>

          {/* -------------------------------------------- response actions */}
          {actions.length > 0 && (
            <div>
              <h2 className="mb-2 text-sm font-medium text-soc-text">Containment actions</h2>
              <Table head={["Action", "Target", "Status", "Justification", "Requested"]}>
                {actions.map((a) => (
                  <tr key={a.id}>
                    <Td><Badge tone="danger">{a.action_type}</Badge></Td>
                    <Td className="font-mono text-xs">{a.target}</Td>
                    <Td><StatusBadge status={a.status} /></Td>
                    <Td className="max-w-md text-xs text-soc-muted">{a.justification}</Td>
                    <Td className="whitespace-nowrap text-xs text-soc-muted">{relativeTime(a.created_at)}</Td>
                  </tr>
                ))}
              </Table>
              <p className="mt-2 text-[11px] text-soc-muted">
                Approval and execution live on the Response Actions page, behind{" "}
                <code className="rounded bg-soc-panel2 px-1">response.approve</code>. Reading a case file never
                widens what its reader can cause to happen.
              </p>
            </div>
          )}

          {/* --------------------------------------------------- timeline */}
          <div>
            <h2 className="mb-2 text-sm font-medium text-soc-text">Case timeline</h2>
            <p className="mb-2 text-[11px] text-soc-muted">
              Append-only. Every entry is written server-side by the operation it describes — there is no API to
              author, edit, or back-date one.
            </p>
            <Panel>
              {timeline.length === 0 ? (
                <EmptyState title="No timeline entries" />
              ) : (
                <ol className="relative space-y-4 border-l border-soc-border pl-5">
                  {timeline.map((e) => (
                    <li key={e.id} className="relative">
                      <span className="absolute -left-[23px] top-1.5 h-2 w-2 rounded-full bg-soc-accent" />
                      <div className="flex flex-wrap items-center gap-2">
                        <Badge tone="accent">{titleCase(e.kind)}</Badge>
                        <span className="text-[11px] text-soc-muted">{absoluteTime(e.event_timestamp)}</span>
                        <span className="text-[11px] text-soc-muted">
                          {e.actor ? `· ${e.actor}` : "· platform"}
                        </span>
                      </div>
                      <pre className="mt-1 overflow-x-auto whitespace-pre-wrap break-words font-mono text-[11px] leading-relaxed text-soc-muted">
                        {JSON.stringify(e.details, null, 2)}
                      </pre>
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
