"use client";

/**
 * Renders the app chrome only for an authenticated session, and the login
 * form otherwise.
 *
 * This is a **rendering** decision, not an access control. Every request
 * the app makes is authorized server-side against live database role
 * state (`app/core/deps.py`), so a user who forced this component to
 * render would see empty panels and 401s, not data. Treating client-side
 * routing as a security boundary is the mistake this comment exists to
 * prevent someone making later.
 */
import { useEffect } from "react";

import { LoginForm } from "@/components/layout/LoginForm";
import { Sidebar } from "@/components/layout/Sidebar";
import { Topbar } from "@/components/layout/Topbar";
import { Loading } from "@/components/ui/primitives";
import { useAuth } from "@/lib/auth";

export function AuthGate({ children }: { children: React.ReactNode }) {
  const { token, ready, hydrate } = useAuth();

  useEffect(() => {
    hydrate();
  }, [hydrate]);

  if (!ready) {
    return (
      <div className="flex h-screen items-center justify-center">
        <Loading label="Restoring session…" />
      </div>
    );
  }

  if (!token) {
    return <LoginForm />;
  }

  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar />
      <div className="flex flex-1 flex-col overflow-hidden">
        <Topbar />
        <main className="flex-1 overflow-y-auto p-6">{children}</main>
      </div>
    </div>
  );
}
