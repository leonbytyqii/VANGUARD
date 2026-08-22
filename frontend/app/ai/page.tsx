"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import {
  Badge,
  EmptyState,
  ErrorState,
  Loading,
  PageHeader,
  Panel,
  StatusBadge,
  Table,
  Td,
} from "@/components/ui/primitives";
import { relativeTime, shortId } from "@/lib/format";
import { apiGet, ApiError } from "@/services/api";

export interface Investigation {
  id: string;
  alert_id: string;
  status: string;
  ai_provider: string;
  ai_model: string;
  started_at: string | null;
  completed_at: string | null;
  result: Record<string, any> | null;
  error: string | null;
  created_at: string;
}

export default function AiInvestigationsPage() {
  const [rows, setRows] = useState<Investigation[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    apiGet<Investigation[]>("/v1/ai/investigations")
      .then(setRows)
      .catch((err) => setError(err instanceof ApiError ? err.detail : "Failed to load investigations."))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="space-y-6">
      <PageHeader
        title="AI Investigations"
        subtitle="Multi-agent investigation runs. Every conclusion is grounded in evidence retrieved through controlled tools — a citation that does not resolve to a real row is rejected, never rendered."
      />

      {error && <ErrorState message={error} />}
      {loading && <Panel><Loading /></Panel>}

      {!loading && rows.length === 0 && !error && (
        <Panel>
          <EmptyState
            title="No investigations yet"
            hint="Open an alert and use 'Investigate with AI' to run the Triage → Investigation → handoff pipeline."
          />
        </Panel>
      )}

      {!loading && rows.length > 0 && (
        <Table head={["Investigation", "Status", "Provider", "Verdict", "Evidence", "Started", ""]}>
          {rows.map((r) => (
            <tr key={r.id} className="hover:bg-soc-panel2/40">
              <Td className="font-mono text-xs">{shortId(r.id)}</Td>
              <Td><StatusBadge status={r.status} /></Td>
              <Td className="text-xs text-soc-muted">{r.ai_provider} · {r.ai_model}</Td>
              <Td className="text-xs">
                {r.result?.severity ? (
                  <span className="flex items-center gap-2">
                    <Badge tone="accent">{r.result.severity}</Badge>
                    <span className="text-soc-muted">conf {r.result.confidence}</span>
                  </span>
                ) : (
                  <span className="text-soc-muted">—</span>
                )}
              </Td>
              <Td className="tabular-nums text-xs">{r.result?.observed_evidence?.length ?? 0}</Td>
              <Td className="whitespace-nowrap text-xs text-soc-muted">{relativeTime(r.started_at ?? r.created_at)}</Td>
              <Td>
                <Link href={`/ai/${r.id}`} className="text-xs text-soc-accent hover:underline">
                  Trace
                </Link>
              </Td>
            </tr>
          ))}
        </Table>
      )}
    </div>
  );
}
