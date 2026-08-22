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
  StatTile,
  StatusBadge,
  Table,
  Td,
  TextInput,
} from "@/components/ui/primitives";
import { useAuth } from "@/lib/auth";
import { relativeTime } from "@/lib/format";
import { apiGet, apiPatch, apiPost, ApiError } from "@/services/api";

interface ResponseAction {
  id: string;
  action_type: string;
  target: string;
  justification: string;
  status: string;
  requested_by_id: string | null;
  requested_by_agent_type: string | null;
  approved_at: string | null;
  rejected_at: string | null;
  rejection_reason: string | null;
  executed_at: string | null;
  result: Record<string, any>;
  incident_id: string | null;
  investigation_id: string | null;
  created_at: string;
}

export default function ResponseActionsPage() {
  const can = useAuth((s) => s.can);
  const [actions, setActions] = useState<ResponseAction[]>([]);
  const [rejectReason, setRejectReason] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setActions(await apiGet<ResponseAction[]>("/v1/response/actions"));
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Failed to load response actions.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function act(id: string, fn: () => Promise<unknown>) {
    setBusy(id);
    setError(null);
    try {
      await fn();
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Action failed.");
    } finally {
      setBusy(null);
    }
  }

  const pending = actions.filter((a) => a.status === "pending");

  return (
    <div className="space-y-6">
      <PageHeader
        title="Response Actions"
        subtitle="The human-in-the-loop approval queue. Nothing here executes without an explicit decision by a person holding response.approve — there is no auto-approve branch anywhere in the platform, regardless of AI confidence."
      />

      {error && <ErrorState message={error} />}

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatTile label="Awaiting decision" value={pending.length} tone={pending.length ? "danger" : undefined} />
        <StatTile label="Approved" value={actions.filter((a) => a.status === "approved").length} />
        <StatTile label="Executed" value={actions.filter((a) => a.status === "executed").length} />
        <StatTile label="Rejected" value={actions.filter((a) => a.status === "rejected").length} />
      </div>

      <Panel className="text-xs leading-relaxed text-soc-muted">
        Execution runs in <span className="text-soc-text">simulated mode</span>: no EDR, IAM, or firewall
        integration is wired up, and <code className="rounded bg-soc-panel2 px-1">result.simulated</code> is
        always true. What is real is the state machine and its audit trail — pretending otherwise about what
        this platform can currently do would be dishonest.
      </Panel>

      {loading && <Panel><Loading /></Panel>}

      {!loading && actions.length === 0 && !error && (
        <Panel>
          <EmptyState
            title="No response actions requested"
            hint="Actions are filed by an analyst, or by the Response Agent during an AI investigation. Either way they start pending."
          />
        </Panel>
      )}

      {!loading && actions.length > 0 && (
        <Table head={["Action", "Target", "Requested by", "Justification", "Status", "When", "Decision"]}>
          {actions.map((a) => (
            <tr key={a.id}>
              <Td><Badge tone="danger">{a.action_type}</Badge></Td>
              <Td className="font-mono text-xs">{a.target}</Td>
              <Td className="text-xs">
                {a.requested_by_agent_type ? (
                  <Badge tone="accent">ai_agent:{a.requested_by_agent_type}</Badge>
                ) : (
                  <span className="text-soc-muted">analyst</span>
                )}
              </Td>
              <Td className="max-w-sm text-xs text-soc-muted">{a.justification}</Td>
              <Td>
                <StatusBadge status={a.status} />
                {a.rejection_reason && (
                  <div className="mt-1 text-[10px] text-soc-muted">{a.rejection_reason}</div>
                )}
              </Td>
              <Td className="whitespace-nowrap text-xs text-soc-muted">{relativeTime(a.created_at)}</Td>
              <Td>
                {a.status === "pending" && can("response.approve") && (
                  <div className="flex flex-col gap-1.5">
                    <div className="flex gap-1.5">
                      <Button
                        variant="primary"
                        disabled={busy === a.id}
                        onClick={() => act(a.id, () => apiPatch(`/v1/response/actions/${a.id}/approve`, {}))}
                      >
                        Approve
                      </Button>
                      <Button
                        variant="danger"
                        disabled={busy === a.id || !(rejectReason[a.id] ?? "").trim()}
                        onClick={() =>
                          act(a.id, () =>
                            apiPatch(`/v1/response/actions/${a.id}/reject`, { reason: rejectReason[a.id] })
                          )
                        }
                      >
                        Reject
                      </Button>
                    </div>
                    <TextInput
                      value={rejectReason[a.id] ?? ""}
                      onChange={(v) => setRejectReason((r) => ({ ...r, [a.id]: v }))}
                      placeholder="Reason (required to reject)"
                    />
                  </div>
                )}
                {a.status === "approved" && can("response.approve") && (
                  <Button
                    disabled={busy === a.id}
                    onClick={() => act(a.id, () => apiPost(`/v1/response/actions/${a.id}/execute`, {}))}
                  >
                    Execute
                  </Button>
                )}
                {a.status === "executed" && <Badge tone="success">simulated</Badge>}
                {a.status === "pending" && !can("response.approve") && (
                  <span className="text-[11px] text-soc-muted">requires a SOC manager</span>
                )}
              </Td>
            </tr>
          ))}
        </Table>
      )}
    </div>
  );
}
