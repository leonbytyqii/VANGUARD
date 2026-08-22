"use client";

import { clsx } from "clsx";
import { useEffect, useState } from "react";

import {
  Badge,
  ErrorState,
  Loading,
  PageHeader,
  Panel,
  StatTile,
} from "@/components/ui/primitives";
import { apiGet, ApiError } from "@/services/api";

interface Cell {
  technique_id: string;
  name: string;
  is_subtechnique: boolean;
  parent_technique_id: string | null;
  detection_rule_ids: string[];
  covered: boolean;
}

interface Column {
  tactic_id: string;
  name: string;
  matrix_order: number;
  techniques: Cell[];
}

interface Matrix {
  tactics: Column[];
  total_techniques: number;
  covered_techniques: number;
  coverage_pct: number;
}

export default function MitrePage() {
  const [matrix, setMatrix] = useState<Matrix | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<Cell | null>(null);

  useEffect(() => {
    apiGet<Matrix>("/v1/mitre/matrix")
      .then(setMatrix)
      .catch((err) => setError(err instanceof ApiError ? err.detail : "Failed to load the ATT&CK matrix."));
  }, []);

  return (
    <div className="space-y-6">
      <PageHeader
        title="MITRE ATT&CK Coverage"
        subtitle="A curated Enterprise catalog mapped to the detections this platform actually ships. Coverage means a shipped rule references the technique — not that the technique is fully mitigated."
      />

      {error && <ErrorState message={error} />}
      {!matrix && !error && <Panel><Loading label="Building the matrix…" /></Panel>}

      {matrix && (
        <>
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            <StatTile label="Tactics" value={matrix.tactics.length} />
            <StatTile label="Techniques" value={matrix.total_techniques} />
            <StatTile label="Covered" value={matrix.covered_techniques} tone="ok" />
            <StatTile
              label="Coverage"
              value={`${matrix.coverage_pct.toFixed(1)}%`}
              hint="Honest figure — a curated catalog, not the full ATT&CK corpus"
            />
          </div>

          <div className="panel overflow-x-auto p-4">
            <div className="flex min-w-max gap-3">
              {matrix.tactics.map((tactic) => (
                <div key={tactic.tactic_id} className="w-52 shrink-0">
                  <div className="mb-2 border-b border-soc-border pb-2">
                    <div className="text-xs font-medium text-soc-text">{tactic.name}</div>
                    <div className="mt-0.5 font-mono text-[10px] text-soc-muted">
                      {tactic.tactic_id} · {tactic.techniques.filter((t) => t.covered).length}/
                      {tactic.techniques.length}
                    </div>
                  </div>
                  <div className="space-y-1">
                    {tactic.techniques.map((t) => (
                      <button
                        key={`${tactic.tactic_id}-${t.technique_id}`}
                        onClick={() => setSelected(t)}
                        className={clsx(
                          "w-full rounded-md px-2 py-1.5 text-left text-[11px] leading-tight transition-colors",
                          t.covered
                            ? "bg-soc-success/15 text-soc-text ring-1 ring-inset ring-soc-success/30 hover:bg-soc-success/25"
                            : "bg-soc-panel2 text-soc-muted hover:bg-soc-border/40",
                          t.is_subtechnique && "ml-2"
                        )}
                      >
                        <div className="font-mono text-[10px] opacity-70">{t.technique_id}</div>
                        <div>{t.name}</div>
                      </button>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {selected && (
            <Panel>
              <div className="mb-3 flex flex-wrap items-center gap-2">
                <h2 className="text-sm font-medium text-soc-text">{selected.name}</h2>
                <Badge tone="accent">{selected.technique_id}</Badge>
                {selected.is_subtechnique && <Badge>sub-technique of {selected.parent_technique_id}</Badge>}
                {selected.covered ? <Badge tone="success">covered</Badge> : <Badge>no detection</Badge>}
              </div>
              {selected.detection_rule_ids.length === 0 ? (
                <p className="text-xs text-soc-muted">
                  No shipped detection references this technique. That is a genuine coverage gap, and an incident
                  that exploits it should produce a new rule in its post-incident review.
                </p>
              ) : (
                <ul className="space-y-1">
                  {selected.detection_rule_ids.map((r) => (
                    <li key={r} className="font-mono text-xs text-soc-text">{r}</li>
                  ))}
                </ul>
              )}
            </Panel>
          )}

          <p className="text-[11px] text-soc-muted">
            Click a technique for the rules behind it. Green = at least one shipped detection references it.
          </p>
        </>
      )}
    </div>
  );
}
