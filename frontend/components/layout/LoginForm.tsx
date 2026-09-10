"use client";

import { ShieldAlert } from "lucide-react";
import { useState } from "react";

import { Button, ErrorState } from "@/components/ui/primitives";
import { useAuth, type CurrentUser } from "@/lib/auth";
import { apiGet, apiPost, ApiError } from "@/services/api";

interface LoginResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
}

export function LoginForm() {
  const setSession = useAuth((s) => s.setSession);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const login = await apiPost<LoginResponse>("/v1/auth/login", { email, password });
      // Set the token before /me, because /me needs it on the Authorization header.
      useAuth.setState({ token: login.access_token });
      const me = await apiGet<CurrentUser>("/v1/auth/me");
      setSession(login.access_token, me);
    } catch (err) {
      useAuth.getState().clear();
      // The backend deliberately returns an identical 401 for an unknown
      // user and a wrong password (see docs/SECURITY.md on username
      // enumeration). Surfacing its message verbatim preserves that.
      setError(err instanceof ApiError ? err.detail : "Sign-in failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center p-6">
      <div className="w-full max-w-sm space-y-6">
        <div className="flex flex-col items-center gap-2 text-center">
          <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-soc-accent/20 text-soc-accent">
            <ShieldAlert size={22} />
          </div>
          <div>
            <div className="text-lg font-semibold text-soc-text">VANGUARD</div>
            <div className="text-[11px] uppercase tracking-widest text-soc-muted">
              Agentic Security Operations Center
            </div>
          </div>
        </div>

        <form onSubmit={submit} className="panel space-y-4 p-6">
          <div className="space-y-1.5">
            <label className="text-[11px] uppercase tracking-widest text-soc-muted" htmlFor="email">
              Email
            </label>
            <input
              id="email"
              type="email"
              autoComplete="username"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full rounded-lg border border-soc-border bg-soc-panel2 px-3 py-2 text-sm text-soc-text outline-none focus:ring-1 focus:ring-soc-accent"
            />
          </div>

          <div className="space-y-1.5">
            <label className="text-[11px] uppercase tracking-widest text-soc-muted" htmlFor="password">
              Password
            </label>
            <input
              id="password"
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full rounded-lg border border-soc-border bg-soc-panel2 px-3 py-2 text-sm text-soc-text outline-none focus:ring-1 focus:ring-soc-accent"
            />
          </div>

          {error && <ErrorState message={error} />}

          <Button type="submit" variant="primary" disabled={busy} className="w-full py-2 text-sm">
            {busy ? "Signing in…" : "Sign in"}
          </Button>
        </form>

        <p className="text-center text-[11px] leading-relaxed text-soc-muted">
          Accounts are provisioned by an administrator. The bootstrap admin credential is printed once by{" "}
          <code className="rounded bg-soc-panel2 px-1 py-0.5">app/db/seed.py</code> on first run and never
          stored in source.
        </p>
      </div>
    </div>
  );
}
