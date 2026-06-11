/**
 * App-wide types shared across the application.
 */

// ─── App State ─────────────────────────────────────────────────────

export type AppState = "initializing" | "locked" | "unlocked" | "error";

export type UnlockState = "idle" | "unlocking" | "success" | "failed";

export type LockState = "unlocked" | "locking" | "locked";

// ─── Theme & Language ──────────────────────────────────────────────

export type Theme = "dark" | "light" | "system";

export type Language = "en" | "es" | "fr" | "de" | "ja";

// ─── Navigation ────────────────────────────────────────────────────

export interface NavigationItem {
  id: string;
  label: string;
  icon: string;
  path: string;
  /** Whether this route requires an unlocked vault */
  requiresUnlock: boolean;
  badge?: number;
}

export interface RouteConfig {
  path: string;
  label: string;
  requiresUnlock: boolean;
}

// ─── Toast ─────────────────────────────────────────────────────────

export type ToastVariant = "success" | "error" | "warning" | "info";

export interface Toast {
  id: string;
  variant: ToastVariant;
  title: string;
  description?: string;
  duration?: number;
}

// ─── Async Action ──────────────────────────────────────────────────

export type AsyncStatus = "idle" | "pending" | "success" | "error";

export interface AsyncActionState<T = unknown> {
  status: AsyncStatus;
  data: T | null;
  error: string | null;
}
