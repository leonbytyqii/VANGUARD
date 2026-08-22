/** Display helpers shared across views. */

export function relativeTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "—";
  const seconds = Math.round((Date.now() - then) / 1000);
  const future = seconds < 0;
  const s = Math.abs(seconds);

  let label: string;
  if (s < 60) label = `${s}s`;
  else if (s < 3600) label = `${Math.round(s / 60)}m`;
  else if (s < 86400) label = `${Math.round(s / 3600)}h`;
  else if (s < 2592000) label = `${Math.round(s / 86400)}d`;
  else label = `${Math.round(s / 2592000)}mo`;

  return future ? `in ${label}` : `${label} ago`;
}

export function absoluteTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z");
}

/**
 * `null` renders as an em dash, never as "0s".
 *
 * A metric with no data and a metric of zero mean very different things —
 * "0s mean time to contain" reads as flawless performance when it
 * actually means nothing was contained. The backend deliberately returns
 * null for un-reached milestones (see DashboardOverview's docstring) and
 * this preserves that distinction all the way to the pixel.
 */
export function duration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return "—";
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  if (seconds < 86400) return `${(seconds / 3600).toFixed(1)}h`;
  return `${(seconds / 86400).toFixed(1)}d`;
}

export function titleCase(value: string): string {
  return value.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

export function shortId(id: string | null | undefined): string {
  return id ? id.slice(0, 8) : "—";
}
