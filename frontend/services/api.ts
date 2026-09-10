/**
 * Thin fetch wrapper for talking to the VANGUARD backend.
 *
 * Browser calls go to /api/backend/* which Next.js rewrites (see
 * next.config.mjs) to the backend's /api/* — same-origin, so no CORS and
 * no preflight.
 *
 * On a 401 the wrapper attempts the refresh token once and replays the
 * request; only if that also fails is the session cleared. An earlier
 * version cleared immediately, on the reasoning that a transparent retry
 * would hide a revoked session. That conflated two different things:
 * hiding a revoked session is bad, but silently renewing a still-valid
 * one is exactly what the rotation-with-reuse-detection scheme in Phase 2
 * exists to make safe. The practical effect of getting it wrong was a
 * hard logout every 30 minutes with no way back.
 *
 * `ApiError` carries the status so callers can distinguish "you cannot do
 * this" (403) from "this does not exist" (404) — a distinction the
 * backend is deliberate about and the UI should not flatten.
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

/**
 * In-flight refresh, shared by every caller.
 *
 * Single-flight is **required for correctness here, not an optimisation.**
 * The backend rotates the refresh token on every use and treats a second
 * presentation of an already-rotated token as theft — it revokes the
 * user's entire session family (see
 * app/services/auth_service.py::rotate_refresh_token and
 * `refresh_token_reuse_detected`). A page like the dashboard fires
 * several requests at once; if each one refreshed independently, the
 * first would rotate and the rest would trip reuse detection and log the
 * user out of everything. So concurrent 401s all await the same refresh.
 */
let refreshInFlight: Promise<boolean> | null = null;

async function refreshSession(): Promise<boolean> {
  if (refreshInFlight) return refreshInFlight;

  refreshInFlight = (async () => {
    try {
      const res = await fetch(`${BROWSER_BASE}/v1/auth/refresh`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        cache: "no-store",
        // The refresh token is an HttpOnly cookie; this is the only reason
        // the request carries credentials.
        credentials: "include",
      });
      if (!res.ok) return false;
      const payload = (await res.json()) as { access_token?: string };
      if (!payload.access_token) return false;
      useAuth.setState({ token: payload.access_token });
      return true;
    } catch {
      return false;
    } finally {
      // Cleared on the next tick so callers awaiting this promise all see
      // the same result before a new attempt can start.
      setTimeout(() => {
        refreshInFlight = null;
      }, 0);
    }
  })();

  return refreshInFlight;
}

async function send(method: string, path: string, body?: unknown): Promise<Response> {
  const token = getToken();
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (token) headers.Authorization = `Bearer ${token}`;

  return fetch(`${BROWSER_BASE}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    cache: "no-store",
    credentials: "include",
  });
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  let res = await send(method, path, body);

  // An access token lives 30 minutes. Rather than dumping the user back
  // to the login form the moment it lapses, try the refresh token once
  // and replay the request. Only a refresh that *also* fails ends the
  // session — that is the case where something really is revoked or
  // expired, and hiding it would be wrong.
  //
  // The refresh endpoint itself is excluded, so a failing refresh cannot
  // recurse.
  if (res.status === 401 && !path.startsWith("/v1/auth/refresh") && !path.startsWith("/v1/auth/login")) {
    const renewed = await refreshSession();
    if (renewed) {
      res = await send(method, path, body);
    }
  }

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
