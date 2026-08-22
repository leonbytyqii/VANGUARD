"use client";

import { useCallback, useEffect, useState } from "react";

import {
  Badge,
  Button,
  ErrorState,
  Loading,
  PageHeader,
  Panel,
  Select,
  Table,
  Td,
  TextInput,
} from "@/components/ui/primitives";
import { relativeTime } from "@/lib/format";
import { apiGet, apiPatch, apiPost, ApiError } from "@/services/api";

interface AdminUser {
  id: string;
  email: string;
  full_name: string;
  role: string;
  is_active: boolean;
  last_login_at: string | null;
  created_at: string;
}

interface Role {
  id: string;
  name: string;
  description: string;
  permissions: string[];
}

export default function AdminPage() {
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [roles, setRoles] = useState<Role[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [email, setEmail] = useState("");
  const [fullName, setFullName] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("soc_analyst");
  const [created, setCreated] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [u, r] = await Promise.all([apiGet<AdminUser[]>("/v1/admin/users"), apiGet<Role[]>("/v1/admin/roles")]);
      setUsers(u);
      setRoles(r);
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Failed to load administration data.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function createUser() {
    setBusy("create");
    setError(null);
    setCreated(null);
    try {
      const u = await apiPost<AdminUser>("/v1/admin/users", {
        email: email.trim(),
        full_name: fullName.trim() || email.trim(),
        password,
        role,
      });
      setCreated(u.email);
      setEmail("");
      setFullName("");
      setPassword("");
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Could not create the user.");
    } finally {
      setBusy(null);
    }
  }

  async function toggleActive(u: AdminUser) {
    setBusy(u.id);
    setError(null);
    try {
      await apiPatch(`/v1/admin/users/${u.id}`, { is_active: !u.is_active });
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Update failed.");
    } finally {
      setBusy(null);
    }
  }

  async function changeRole(u: AdminUser, next: string) {
    setBusy(u.id);
    setError(null);
    try {
      await apiPatch(`/v1/admin/users/${u.id}`, { role: next });
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Role change failed.");
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Administration"
        subtitle="Users and the RBAC catalog. Permission checks read live database role state on every request, so revoking a permission takes effect on the user's very next call — not when their token expires."
      />

      {error && <ErrorState message={error} />}
      {loading && <Panel><Loading /></Panel>}

      <Panel className="space-y-3">
        <h2 className="text-sm font-medium text-soc-text">Create a user</h2>
        <div className="flex flex-wrap items-center gap-3">
          <TextInput value={email} onChange={setEmail} placeholder="email@example.com" className="min-w-56" />
          <TextInput value={fullName} onChange={setFullName} placeholder="Full name" className="min-w-48" />
          <TextInput value={password} onChange={setPassword} placeholder="Initial password" type="password" className="min-w-48" />
          <Select
            value={role}
            onChange={setRole}
            options={roles.map((r) => ({ value: r.name, label: r.name }))}
          />
          <Button variant="primary" onClick={createUser} disabled={busy === "create" || !email || !password}>
            {busy === "create" ? "Creating…" : "Create"}
          </Button>
        </div>
        {created && <div className="text-xs text-soc-success">Created {created}.</div>}
        <p className="text-[11px] text-soc-muted">
          Passwords are hashed with Argon2id and never stored or logged in plaintext. The policy minimum is
          enforced server-side.
        </p>
      </Panel>

      <div>
        <h2 className="mb-2 text-sm font-medium text-soc-text">Users</h2>
        {users.length > 0 && (
          <Table head={["Email", "Name", "Role", "State", "Last login", ""]}>
            {users.map((u) => (
              <tr key={u.id}>
                <Td className="font-mono text-xs">{u.email}</Td>
                <Td className="text-xs">{u.full_name}</Td>
                <Td>
                  <Select
                    value={u.role}
                    onChange={(next) => changeRole(u, next)}
                    options={roles.map((r) => ({ value: r.name, label: r.name }))}
                  />
                </Td>
                <Td>
                  {u.is_active ? <Badge tone="success">active</Badge> : <Badge tone="danger">disabled</Badge>}
                </Td>
                <Td className="whitespace-nowrap text-xs text-soc-muted">{relativeTime(u.last_login_at)}</Td>
                <Td>
                  <Button disabled={busy === u.id} onClick={() => toggleActive(u)}>
                    {u.is_active ? "Disable" : "Enable"}
                  </Button>
                </Td>
              </tr>
            ))}
          </Table>
        )}
      </div>

      <div>
        <h2 className="mb-2 text-sm font-medium text-soc-text">Roles and permissions</h2>
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          {roles.map((r) => (
            <Panel key={r.id}>
              <div className="mb-2 flex items-center gap-2">
                <h3 className="text-sm font-medium text-soc-text">{r.name}</h3>
                <Badge>{r.permissions.length} permissions</Badge>
              </div>
              <p className="mb-3 text-xs text-soc-muted">{r.description}</p>
              <div className="flex flex-wrap gap-1">
                {r.permissions.map((p) => (
                  <span key={p} className="rounded bg-soc-panel2 px-1.5 py-0.5 font-mono text-[10px] text-soc-muted">
                    {p}
                  </span>
                ))}
              </div>
            </Panel>
          ))}
        </div>
      </div>
    </div>
  );
}
