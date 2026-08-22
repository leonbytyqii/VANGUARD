/**
 * Thin fetch wrapper for talking to the SOC-AI backend.
 *
 * Browser calls go to /api/backend/* which Next.js rewrites (see
 * next.config.mjs) to the backend's /api/* — same-origin, so no CORS and
 * no preflight.
 *
 * A 401 clears the session rather than retrying: the backend rejects an
 * expired access token the same way it rejects a forged one, and silently
 * refreshing in a fetch wrapper would hide a revoked session from the
 * user. `ApiError` carries the status so callers can distinguish "you
 * cannot do this" (403) from "this does not exist" (404) — a distinction
 * the backend is deliberate about and the UI should not flatten.
 */
import { getToken, useAuth } from "@/lib/auth";

const BROWSER_BASE = "/api/backend";

export class ApiError extends Error {
  status: number;
  detail: string;

  constructor(status: number, detail: string) {
    super(detail);
    this.status = status;
    this.detail = detail;
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const token = getToken();
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (token) headers.Authorization = `Bearer ${token}`;

  const res = await fetch(`${BROWSER_BASE}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    cache: "no-store",
    credentials: "include",
  });

  if (res.status === 401) {
    useAuth.getState().clear();
    throw new ApiError(401, "Your session has expired. Sign in again.");
  }

  if (!res.ok) {
    let detail = `${method} ${path} failed (${res.status})`;
    try {
      const payload = await res.json();
      if (typeof payload?.detail === "string") detail = payload.detail;
      else if (Array.isArray(payload?.detail)) detail = payload.detail.map((d: any) => d.msg).join("; ");
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, detail);
  }

  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export const apiGet = <T>(path: string) => request<T>("GET", path);
export const apiPost = <T>(path: string, body?: unknown) => request<T>("POST", path, body);
export const apiPatch = <T>(path: string, body?: unknown) => request<T>("PATCH", path, body);
export const apiDelete = <T>(path: string) => request<T>("DELETE", path);

export function qs(params: Record<string, string | number | boolean | undefined | null>): string {
  const parts = Object.entries(params)
    .filter(([, v]) => v !== undefined && v !== null && v !== "")
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`);
  return parts.length ? `?${parts.join("&")}` : "";
}
