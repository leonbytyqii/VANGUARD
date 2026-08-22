"use client";

import { clsx } from "clsx";
import { AlertTriangle, Inbox, Loader2 } from "lucide-react";
import type { ReactNode } from "react";

/* ---------------------------------------------------------------- panels */

export function Panel({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={clsx("panel p-5", className)}>{children}</div>;
}

export function PageHeader({
  title,
  subtitle,
  actions,
}: {
  title: string;
  subtitle?: string;
  actions?: ReactNode;
}) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-4">
      <div>
        <h1 className="text-xl font-semibold text-soc-text">{title}</h1>
        {subtitle && <p className="mt-1 max-w-3xl text-sm text-soc-muted">{subtitle}</p>}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  );
}

/* ---------------------------------------------------------------- badges */

const SEVERITY_CLASS: Record<string, string> = {
  CRITICAL: "bg-soc-critical/15 text-soc-critical ring-soc-critical/30",
  HIGH: "bg-soc-high/15 text-soc-high ring-soc-high/30",
  MEDIUM: "bg-soc-medium/15 text-soc-medium ring-soc-medium/30",
  LOW: "bg-soc-low/15 text-soc-low ring-soc-low/30",
  INFO: "bg-soc-info/15 text-soc-info ring-soc-info/30",
};

const STATE_CLASS: Record<string, string> = {
  new: "bg-soc-accent/15 text-soc-accent ring-soc-accent/30",
  triaged: "bg-soc-medium/15 text-soc-medium ring-soc-medium/30",
  investigating: "bg-soc-high/15 text-soc-high ring-soc-high/30",
  contained: "bg-soc-low/15 text-soc-low ring-soc-low/30",
  eradicated: "bg-soc-low/15 text-soc-low ring-soc-low/30",
  recovered: "bg-soc-success/15 text-soc-success ring-soc-success/30",
  closed: "bg-soc-info/15 text-soc-info ring-soc-info/30",
  escalated: "bg-soc-critical/15 text-soc-critical ring-soc-critical/30",
  false_positive: "bg-soc-info/15 text-soc-info ring-soc-info/30",
  pending: "bg-soc-medium/15 text-soc-medium ring-soc-medium/30",
  approved: "bg-soc-low/15 text-soc-low ring-soc-low/30",
  rejected: "bg-soc-info/15 text-soc-info ring-soc-info/30",
  executed: "bg-soc-success/15 text-soc-success ring-soc-success/30",
  completed: "bg-soc-success/15 text-soc-success ring-soc-success/30",
  running: "bg-soc-accent/15 text-soc-accent ring-soc-accent/30",
  failed: "bg-soc-critical/15 text-soc-critical ring-soc-critical/30",
  malicious: "bg-soc-critical/15 text-soc-critical ring-soc-critical/30",
  suspicious: "bg-soc-high/15 text-soc-high ring-soc-high/30",
  clean: "bg-soc-success/15 text-soc-success ring-soc-success/30",
  unknown: "bg-soc-info/15 text-soc-info ring-soc-info/30",
};

export function Badge({
  children,
  tone = "neutral",
  className,
}: {
  children: ReactNode;
  tone?: "neutral" | "accent" | "danger" | "success";
  className?: string;
}) {
  const tones = {
    neutral: "bg-soc-panel2 text-soc-muted ring-soc-border",
    accent: "bg-soc-accent/15 text-soc-accent ring-soc-accent/30",
    danger: "bg-soc-critical/15 text-soc-critical ring-soc-critical/30",
    success: "bg-soc-success/15 text-soc-success ring-soc-success/30",
  };
  return (
    <span
      className={clsx(
        "inline-flex items-center rounded-md px-2 py-0.5 text-[11px] font-medium ring-1 ring-inset",
        tones[tone],
        className
      )}
    >
      {children}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span
      className={clsx(
        "inline-flex items-center rounded-md px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ring-1 ring-inset",
        SEVERITY_CLASS[severity?.toUpperCase()] ?? SEVERITY_CLASS.INFO
      )}
    >
      {severity}
    </span>
  );
}

export function StatusBadge({ status }: { status: string }) {
  return (
    <span
      className={clsx(
        "inline-flex items-center rounded-md px-2 py-0.5 text-[11px] font-medium ring-1 ring-inset",
        STATE_CLASS[status] ?? "bg-soc-panel2 text-soc-muted ring-soc-border"
      )}
    >
      {status?.replace(/_/g, " ")}
    </span>
  );
}

/* ------------------------------------------------------------ stat tiles */

export function StatTile({
  label,
  value,
  hint,
  tone,
}: {
  label: string;
  value: ReactNode;
  hint?: string;
  tone?: "danger" | "warn" | "ok";
}) {
  const valueTone =
    tone === "danger"
      ? "text-soc-critical"
      : tone === "warn"
        ? "text-soc-high"
        : tone === "ok"
          ? "text-soc-success"
          : "text-soc-text";
  return (
    <div className="panel p-4">
      <div className="text-[11px] uppercase tracking-widest text-soc-muted">{label}</div>
      <div className={clsx("mt-1 text-2xl font-semibold tabular-nums", valueTone)}>{value}</div>
      {hint && <div className="mt-1 text-[11px] text-soc-muted">{hint}</div>}
    </div>
  );
}

/* ----------------------------------------------------------- table shell */

export function Table({ head, children }: { head: ReactNode[]; children: ReactNode }) {
  return (
    <div className="panel overflow-x-auto">
      <table className="w-full min-w-[720px] text-left text-sm">
        <thead>
          <tr className="border-b border-soc-border text-[11px] uppercase tracking-widest text-soc-muted">
            {head.map((h, i) => (
              <th key={i} className="px-4 py-3 font-medium">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-soc-border/60">{children}</tbody>
      </table>
    </div>
  );
}

export function Td({ children, className }: { children: ReactNode; className?: string }) {
  return <td className={clsx("px-4 py-3 align-top text-soc-text", className)}>{children}</td>;
}

/* -------------------------------------------------------------- feedback */

export function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 p-8 text-sm text-soc-muted">
      <Loader2 className="animate-spin" size={16} />
      {label}
    </div>
  );
}

export function EmptyState({ title, hint }: { title: string; hint?: string }) {
  return (
    <div className="flex flex-col items-center gap-2 p-12 text-center">
      <Inbox className="text-soc-muted" size={24} />
      <div className="text-sm text-soc-text">{title}</div>
      {hint && <div className="max-w-md text-xs text-soc-muted">{hint}</div>}
    </div>
  );
}

export function ErrorState({ message }: { message: string }) {
  return (
    <div className="panel flex items-start gap-3 border-soc-critical/40 p-4 text-sm">
      <AlertTriangle className="mt-0.5 shrink-0 text-soc-critical" size={16} />
      <div className="text-soc-text">{message}</div>
    </div>
  );
}

/* --------------------------------------------------------------- inputs */

export function Button({
  children,
  onClick,
  variant = "default",
  disabled,
  type = "button",
  className,
}: {
  children: ReactNode;
  onClick?: () => void;
  variant?: "default" | "primary" | "danger";
  disabled?: boolean;
  type?: "button" | "submit";
  className?: string;
}) {
  const variants = {
    default: "bg-soc-panel2 text-soc-text hover:bg-soc-border/40 ring-1 ring-inset ring-soc-border",
    primary: "bg-soc-accent/20 text-soc-accent hover:bg-soc-accent/30 ring-1 ring-inset ring-soc-accent/40",
    danger: "bg-soc-critical/15 text-soc-critical hover:bg-soc-critical/25 ring-1 ring-inset ring-soc-critical/40",
  };
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      className={clsx(
        "rounded-lg px-3 py-1.5 text-xs font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-40",
        variants[variant],
        className
      )}
    >
      {children}
    </button>
  );
}

export function Select({
  value,
  onChange,
  options,
  label,
}: {
  value: string;
  onChange: (v: string) => void;
  options: { value: string; label: string }[];
  label?: string;
}) {
  return (
    <label className="flex items-center gap-2 text-xs text-soc-muted">
      {label}
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="rounded-lg border border-soc-border bg-soc-panel2 px-2 py-1.5 text-xs text-soc-text outline-none focus:ring-1 focus:ring-soc-accent"
      >
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </label>
  );
}

export function TextInput({
  value,
  onChange,
  placeholder,
  type = "text",
  className,
  onEnter,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  type?: string;
  className?: string;
  onEnter?: () => void;
}) {
  return (
    <input
      type={type}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      onKeyDown={(e) => {
        if (e.key === "Enter" && onEnter) onEnter();
      }}
      placeholder={placeholder}
      className={clsx(
        "rounded-lg border border-soc-border bg-soc-panel2 px-3 py-1.5 text-xs text-soc-text placeholder:text-soc-muted outline-none focus:ring-1 focus:ring-soc-accent",
        className
      )}
    />
  );
}

export function KeyValue({ items }: { items: [string, ReactNode][] }) {
  return (
    <dl className="grid grid-cols-1 gap-x-6 gap-y-3 sm:grid-cols-2">
      {items.map(([k, v]) => (
        <div key={k}>
          <dt className="text-[11px] uppercase tracking-widest text-soc-muted">{k}</dt>
          <dd className="mt-0.5 break-words text-sm text-soc-text">{v ?? "—"}</dd>
        </div>
      ))}
    </dl>
  );
}
