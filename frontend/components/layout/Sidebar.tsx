"use client";

import { clsx } from "clsx";
import {
  Bot,
  Cloud,
  Crosshair,
  FlaskConical,
  FolderKanban,
  LayoutDashboard,
  Radar,
  ScrollText,
  Search,
  Settings,
  ShieldAlert,
  Workflow,
} from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";

import { useAuth } from "@/lib/auth";

/**
 * `permission` hides a nav entry the signed-in role cannot use. This is a
 * UX affordance only — the route and its API are both still enforced
 * server-side, so a hidden link is not a locked door.
 */
const NAV = [
  { href: "/", label: "Dashboard", icon: LayoutDashboard, permission: "alerts.read" },
  { href: "/alerts", label: "Alerts", icon: ShieldAlert, permission: "alerts.read" },
  { href: "/incidents", label: "Incidents", icon: FolderKanban, permission: "incidents.read" },
  { href: "/ai", label: "AI Investigations", icon: Bot, permission: "ai.read" },
  { href: "/hunting", label: "Threat Hunting", icon: Search, permission: "threat_hunting.read" },
  { href: "/threat-intel", label: "Threat Intel", icon: Radar, permission: "threat_intel.lookup" },
  { href: "/mitre", label: "MITRE ATT&CK", icon: Crosshair, permission: "mitre.read" },
  { href: "/cloud-iam", label: "Cloud / IAM", icon: Cloud, permission: "iam.read" },
  { href: "/automation", label: "Response Actions", icon: Workflow, permission: "response.request" },
  { href: "/lab", label: "Simulation Lab", icon: FlaskConical, permission: "events.ingest" },
  { href: "/audit", label: "Audit Log", icon: ScrollText, permission: "audit.read" },
  { href: "/admin", label: "Admin", icon: Settings, permission: "admin.users" },
];

export function Sidebar() {
  const pathname = usePathname();
  const can = useAuth((s) => s.can);

  return (
    <aside className="flex w-60 shrink-0 flex-col border-r border-soc-border bg-soc-panel">
      <div className="flex items-center gap-2 border-b border-soc-border px-5 py-4">
        <div className="flex h-8 w-8 items-center justify-center rounded-md bg-soc-accent/20 text-soc-accent">
          <ShieldAlert size={18} />
        </div>
        <div>
          <div className="text-sm font-semibold tracking-wide text-soc-text">VANGUARD</div>
          <div className="text-[10px] uppercase tracking-widest text-soc-muted">Agentic SOC Platform</div>
        </div>
      </div>

      <nav className="flex-1 space-y-1 overflow-y-auto px-3 py-4">
        {NAV.filter((item) => can(item.permission)).map(({ href, label, icon: Icon }) => {
          const active = pathname === href || (href !== "/" && pathname?.startsWith(href));
          return (
            <Link
              key={href}
              href={href}
              className={clsx(
                "flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors",
                active
                  ? "bg-soc-accent/15 text-soc-accent"
                  : "text-soc-muted hover:bg-soc-panel2 hover:text-soc-text"
              )}
            >
              <Icon size={16} />
              {label}
            </Link>
          );
        })}
      </nav>

      <div className="border-t border-soc-border px-4 py-3 text-[11px] leading-relaxed text-soc-muted">
        Navigation reflects your role&apos;s permissions. Every route is re-authorized server-side.
      </div>
    </aside>
  );
}
