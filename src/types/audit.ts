/**
 * Audit types for the audit log system.
 */

// ─── Event Categories ──────────────────────────────────────────────

export type EventCategory =
  | "auth"
  | "vault"
  | "notes"
  | "files"
  | "scanner"
  | "settings"
  | "system";

// ─── Action Types ──────────────────────────────────────────────────

export type ActionType =
  | "create"
  | "read"
  | "update"
  | "delete"
  | "unlock"
  | "lock"
  | "login_failed"
  | "password_reveal"
  | "totp_generate"
  | "export"
  | "import"
  | "scan"
  | "config_change";

// ─── Audit Event ───────────────────────────────────────────────────

export interface AuditEvent {
  id: string;
  category: EventCategory;
  action: ActionType;
  description: string;
  /** ISO timestamp */
  timestamp: string;
  /** Optional metadata — structure depends on category/action */
  metadata: Record<string, unknown> | null;
}

// ─── Query ─────────────────────────────────────────────────────────

export interface AuditQuery {
  category?: EventCategory;
  action?: ActionType;
  from?: string;
  to?: string;
  limit?: number;
  cursor?: string;
}

export interface AuditPage {
  events: AuditEvent[];
  total_count: number;
  has_more: boolean;
  next_cursor: string | null;
}

// ─── Export ────────────────────────────────────────────────────────

export type ExportFormat = "csv" | "json";
