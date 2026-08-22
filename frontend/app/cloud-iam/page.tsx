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
  SeverityBadge,
  StatTile,
  Table,
  Td,
  TextInput,
} from "@/components/ui/primitives";
import { relativeTime } from "@/lib/format";
import { apiGet, apiPost, ApiError, qs } from "@/services/api";

interface Identity {
  id: string;
  account_id: string;
  identity_type: string;
  identity_name: string;
  arn: string | null;
  is_privileged: boolean;
  last_seen_at: string | null;
}

interface CloudEvent {
  id: string;
  event_timestamp: string;
  event_name: string;
  actor_identity: string | null;
  assumed_role_arn: string | null;
  account_id: string;
  source_ip: string | null;
  error_code: string | null;
}

interface AttackPath {
  id: string;
  title: string;
  severity: string;
  path_nodes: { id: string; type: string; label: string; is_seed?: boolean; is_privileged?: boolean }[];
  path_edges: { from: string; to: string; action: string; signal: string; timestamp: string; cloud_event_id: string }[];
  privilege_escalation_detected: boolean;
  explanation: string;
  created_at: string;
}

const SIGNAL_TONE: Record<string, "neutral" | "accent" | "danger"> = {
  role_assumption: "accent",
  privilege_escalation: "danger",
  defense_evasion: "danger",
  access: "neutral",
};

export default function CloudIamPage() {
  const [identities, setIdentities] = useState<Identity[]>([]);
  const [events, setEvents] = useState<CloudEvent[]>([]);
  const [paths, setPaths] = useState<AttackPath[]>([]);
  const [selectedPath, setSelectedPath] = useState<AttackPath | null>(null);
  const [seed, setSeed] = useState("");
  const [account, setAccount] = useState("");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [i, e, p] = await Promise.all([
        apiGet<Identity[]>("/v1/cloud/identities"),
        apiGet<CloudEvent[]>(`/v1/cloud/events${qs({ limit: 50 })}`),
        apiGet<AttackPath[]>("/v1/cloud/attack-paths"),
      ]);
      setIdentities(i);
      setEvents(e);
      setPaths(p);
      if (!account && i.length > 0) setAccount(i[0]!.account_id);
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Failed to load cloud data.");
    } finally {
      setLoading(false);
    }
  }, [account]);

  useEffect(() => {
    void load();
  }, [load]);

  async function build(identityName: string, accountId: string) {
    setBusy(true);
    setError(null);
    try {
      const path = await apiPost<AttackPath>("/v1/cloud/attack-paths", {
        account_id: accountId,
        seed_identity: identityName,
        window_hours: 168,
      });
      setSelectedPath(path);
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Could not reconstruct a path.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Cloud / IAM Security"
        subtitle="Identities derived from observed CloudTrail activity, and reconstructed identity attack paths. These graphs show what was observed — not what was theoretically reachable through IAM policy."
      />

      {error && <ErrorState message={error} />}
      {loading && <Panel><Loading /></Panel>}

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatTile label="Identities observed" value={identities.length} />
        <StatTile label="Privileged (by naming)" value={identities.filter((i) => i.is_privileged).length} />
        <StatTile label="Attack paths" value={paths.length} />
        <StatTile
          label="With escalation"
          value={paths.filter((p) => p.privilege_escalation_detected).length}
          tone={paths.some((p) => p.privilege_escalation_detected) ? "danger" : undefined}
        />
      </div>

      <Panel className="flex flex-wrap items-center gap-3">
        <span className="text-xs text-soc-muted">Reconstruct a path</span>
        <TextInput value={account} onChange={setAccount} placeholder="Account id" />
        <TextInput value={seed} onChange={setSeed} placeholder="Seed identity" onEnter={() => build(seed, account)} />
        <Button variant="primary" onClick={() => build(seed, account)} disabled={busy || !seed || !account}>
          {busy ? "Walking…" : "Build graph"}
        </Button>
      </Panel>

      {selectedPath && (
        <Panel>
          <div className="mb-3 flex flex-wrap items-center gap-2">
            <h2 className="text-sm font-medium text-soc-text">{selectedPath.title}</h2>
            <SeverityBadge severity={selectedPath.severity} />
            {selectedPath.privilege_escalation_detected && <Badge tone="danger">privilege escalation</Badge>}
          </div>

          <p className="mb-4 text-xs leading-relaxed text-soc-muted">{selectedPath.explanation}</p>

          <div className="mb-4 flex flex-wrap gap-2">
            {selectedPath.path_nodes.map((n) => (
              <span
                key={n.id}
                className={
                  n.is_seed
                    ? "rounded-lg bg-soc-accent/15 px-2.5 py-1 text-xs text-soc-accent ring-1 ring-inset ring-soc-accent/40"
                    : n.type === "role"
                      ? "rounded-lg bg-soc-high/10 px-2.5 py-1 text-xs text-soc-high ring-1 ring-inset ring-soc-high/30"
                      : "rounded-lg bg-soc-panel2 px-2.5 py-1 text-xs text-soc-muted ring-1 ring-inset ring-soc-border"
                }
              >
                {n.label}
                <span className="ml-1.5 opacity-60">{n.type}</span>
              </span>
            ))}
          </div>

          <Table head={["From", "Action", "To", "Signal", "When", "Evidence"]}>
            {selectedPath.path_edges.map((e, i) => (
              <tr key={i}>
                <Td className="font-mono text-xs">{e.from}</Td>
                <Td className="font-mono text-xs text-soc-text">{e.action}</Td>
                <Td className="font-mono text-xs">{e.to}</Td>
                <Td><Badge tone={SIGNAL_TONE[e.signal] ?? "neutral"}>{e.signal.replace(/_/g, " ")}</Badge></Td>
                <Td className="whitespace-nowrap font-mono text-[11px] text-soc-muted">{e.timestamp.slice(0, 19)}</Td>
                <Td className="font-mono text-[10px] text-soc-muted">{e.cloud_event_id.slice(0, 8)}</Td>
              </tr>
            ))}
          </Table>
        </Panel>
      )}

      <div>
        <h2 className="mb-2 text-sm font-medium text-soc-text">Cloud identities</h2>
        {identities.length === 0 ? (
          <Panel>
            <EmptyState
              title="No cloud identities observed"
              hint="Identities appear here once CloudTrail-shaped events naming them are ingested. Nothing is imported from an IAM inventory."
            />
          </Panel>
        ) : (
          <Table head={["Identity", "Type", "Account", "ARN", "Last seen", ""]}>
            {identities.map((i) => (
              <tr key={i.id}>
                <Td className="font-mono text-xs">
                  {i.identity_name}
                  {i.is_privileged && <Badge tone="danger" className="ml-2">privileged?</Badge>}
                </Td>
                <Td className="text-xs">{i.identity_type}</Td>
                <Td className="font-mono text-xs">{i.account_id}</Td>
                <Td className="max-w-xs truncate font-mono text-[11px] text-soc-muted">{i.arn ?? "—"}</Td>
                <Td className="whitespace-nowrap text-xs text-soc-muted">{relativeTime(i.last_seen_at)}</Td>
                <Td>
                  <button
                    onClick={() => build(i.identity_name, i.account_id)}
                    className="text-xs text-soc-accent hover:underline"
                  >
                    Trace
                  </button>
                </Td>
              </tr>
            ))}
          </Table>
        )}
        {identities.some((i) => i.is_privileged) && (
          <p className="mt-2 text-[11px] text-soc-muted">
            &ldquo;privileged?&rdquo; is inferred from the identity&apos;s name, not from an IAM policy fetch — treat it as a
            triage hint, not a fact.
          </p>
        )}
      </div>

      <div>
        <h2 className="mb-2 text-sm font-medium text-soc-text">Recent cloud activity</h2>
        {events.length === 0 ? (
          <Panel><EmptyState title="No cloud events ingested" /></Panel>
        ) : (
          <Table head={["Time", "Event", "Actor", "Assumed role", "Source IP", "Error"]}>
            {events.map((e) => (
              <tr key={e.id}>
                <Td className="whitespace-nowrap font-mono text-[11px]">{e.event_timestamp.slice(0, 19)}</Td>
                <Td className="font-mono text-xs text-soc-text">{e.event_name}</Td>
                <Td className="font-mono text-xs">{e.actor_identity ?? "—"}</Td>
                <Td className="max-w-xs truncate font-mono text-[11px] text-soc-muted">{e.assumed_role_arn ?? "—"}</Td>
                <Td className="font-mono text-xs">{e.source_ip ?? "—"}</Td>
                <Td className="text-xs">{e.error_code ? <Badge tone="danger">{e.error_code}</Badge> : "—"}</Td>
              </tr>
            ))}
          </Table>
        )}
      </div>
    </div>
  );
}
