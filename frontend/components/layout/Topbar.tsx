"use client";

import { LogOut, ShieldCheck } from "lucide-react";
import { usePathname } from "next/navigation";

import { useAuth } from "@/lib/auth";
import { apiPost } from "@/services/api";

const TITLES: Record<string, string> = {
  "/": "Overview",
  "/alerts": "Alerts",
  "/incidents": "Incidents",
  "/hunting": "Threat Hunting",
  "/mitre": "MITRE ATT&CK",
  "/cloud-iam": "Cloud / IAM",
  "/threat-intel": "Threat Intelligence",
  "/ai": "AI Investigations",
  "/automation": "Response Actions",
  "/lab": "Attack Simulation Lab",
  "/audit": "Audit Log",
  "/admin": "Admin",
};

export function Topbar() {
  const pathname = usePathname() ?? "/";
  const { user, clear } = useAuth();

  const match = Object.keys(TITLES)
    .filter((k) => k !== "/" && pathname.startsWith(k))
    .sort((a, b) => b.length - a.length)[0];
  const title = TITLES[match ?? pathname] ?? "Overview";

  async function signOut() {
    try {
      // Best effort: this revokes the refresh-token family server-side.
      // A failure here must still clear the local session, otherwise a
      // network blip would leave the user apparently signed in.
      await apiPost("/v1/auth/logout", {});
    } catch {
      /* ignore */
    } finally {
      clear();
    }
  }

  return (
    <header className="flex h-14 shrink-0 items-center justify-between border-b border-soc-border bg-soc-panel/60 px-6">
      <div className="text-sm text-soc-muted">
        Security Operations Center <span className="mx-2 text-soc-border">/</span>
        <span className="text-soc-text">{title}</span>
      </div>
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2 text-sm">
          <ShieldCheck size={16} className="text-soc-accent" />
          <span className="text-soc-text">{user?.email ?? "—"}</span>
          <span className="rounded-md bg-soc-panel2 px-2 py-0.5 text-[11px] uppercase tracking-wide text-soc-muted">
            {user?.role ?? "—"}
          </span>
        </div>
        <button
          onClick={signOut}
          className="flex items-center gap-1.5 text-xs text-soc-muted transition-colors hover:text-soc-text"
        >
          <LogOut size={14} />
          Sign out
        </button>
      </div>
    </header>
  );
}
