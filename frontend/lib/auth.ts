"use client";

/**
 * Client-side session state.
 *
 * The access token lives in memory (zustand) and is mirrored into
 * `sessionStorage` — not `localStorage` — so a token does not survive the
 * browser being closed and is not shared across tabs opened from other
 * origins. The refresh token is never touched here at all: the backend
 * sets it as an HttpOnly cookie (see app/services/auth_service.py), which
 * is the entire point of that design and would be defeated by reading it
 * into JavaScript.
 *
 * `perms` is used only to decide what to *render*. Every permission is
 * re-checked server-side on the request itself (app/core/deps.py reads
 * live DB role state, never the token claim), so hiding a button here is
 * a UX affordance, never a security control.
 */
import { create } from "zustand";

const TOKEN_KEY = "soc_ai_access_token";
const USER_KEY = "soc_ai_user";

export interface CurrentUser {
  id: string;
  email: string;
  full_name: string | null;
  role: string;
  organization_id: string;
  permissions: string[];
}

interface AuthState {
  token: string | null;
  user: CurrentUser | null;
  ready: boolean;
  setSession: (token: string, user: CurrentUser) => void;
  clear: () => void;
  hydrate: () => void;
  can: (permission: string) => boolean;
}

export const useAuth = create<AuthState>((set, get) => ({
  token: null,
  user: null,
  ready: false,

  setSession: (token, user) => {
    try {
      sessionStorage.setItem(TOKEN_KEY, token);
      sessionStorage.setItem(USER_KEY, JSON.stringify(user));
    } catch {
      /* storage can be unavailable (private mode); the in-memory session still works */
    }
    set({ token, user, ready: true });
  },

  clear: () => {
    try {
      sessionStorage.removeItem(TOKEN_KEY);
      sessionStorage.removeItem(USER_KEY);
    } catch {
      /* ignore */
    }
    set({ token: null, user: null, ready: true });
  },

  hydrate: () => {
    if (get().ready) return;
    try {
      const token = sessionStorage.getItem(TOKEN_KEY);
      const rawUser = sessionStorage.getItem(USER_KEY);
      set({
        token,
        user: rawUser ? (JSON.parse(rawUser) as CurrentUser) : null,
        ready: true,
      });
    } catch {
      set({ token: null, user: null, ready: true });
    }
  },

  // A superuser's token carries the wildcard `"*"` rather than an
  // enumerated list (see app/services/auth_service.py). Missing that case
  // hides every nav entry from an administrator, which is how this was
  // caught: the whole sidebar disappeared for the one role that can do
  // everything.
  can: (permission) => {
    const granted = get().user?.permissions ?? [];
    return granted.includes("*") || granted.includes(permission);
  },
}));

export function getToken(): string | null {
  return useAuth.getState().token;
}
