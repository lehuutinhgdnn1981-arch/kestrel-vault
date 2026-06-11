/**
 * Tauri IPC abstraction layer.
 *
 * IMPORTANT: React NEVER calls invoke directly from components.
 * All Tauri API calls are centralized here with type-safe wrappers.
 * React NEVER owns encryption keys — all crypto goes through Rust.
 */

import { invoke } from "@tauri-apps/api/core";

// ─── Error Types ────────────────────────────────────────────────────

export class TauriCommandError extends Error {
  readonly code: string;
  readonly source: string;

  constructor(code: string, message: string, source: string = "tauri") {
    super(message);
    this.name = "TauriCommandError";
    this.code = code;
    this.source = source;
  }
}

// ─── Generic invoke wrapper ─────────────────────────────────────────

/**
 * Type-safe wrapper around Tauri invoke.
 * All component code should use command-specific functions below,
 * never call this directly.
 */
async function safeInvoke<T>(
  command: string,
  args?: Record<string, unknown>,
): Promise<T> {
  try {
    return await invoke<T>(command, args);
  } catch (error) {
    if (error instanceof Error) {
      throw new TauriCommandError(
        "COMMAND_FAILED",
        error.message,
        command,
      );
    }

    const errStr = String(error);
    throw new TauriCommandError("UNKNOWN", errStr, command);
  }
}

// ─── Vault Commands ────────────────────────────────────────────────

export interface VaultEntryView {
  id: string;
  title: string;
  username: string;
  url: string | null;
  folder_id: string | null;
  has_totp: boolean;
  notes_preview: string | null;
  created_at: string;
  updated_at: string;
  /** Password is NEVER included in this type */
}

export interface CreateEntryPayload {
  title: string;
  username: string;
  password: string;
  url: string | null;
  folder_id: string | null;
  notes: string | null;
  totp_secret: string | null;
}

export interface UpdateEntryPayload {
  id: string;
  title?: string;
  username?: string;
  password?: string;
  url?: string | null;
  folder_id?: string | null;
  notes?: string | null;
  totp_secret?: string | null;
}

export const vaultCommands = {
  listEntries: (folderId?: string): Promise<VaultEntryView[]> =>
    safeInvoke("vault_list_entries", { folderId }),

  getEntry: (id: string): Promise<VaultEntryView> =>
    safeInvoke("vault_get_entry", { id }),

  createEntry: (payload: CreateEntryPayload): Promise<VaultEntryView> =>
    safeInvoke("vault_create_entry", { payload }),

  updateEntry: (payload: UpdateEntryPayload): Promise<VaultEntryView> =>
    safeInvoke("vault_update_entry", { payload }),

  deleteEntry: (id: string): Promise<void> =>
    safeInvoke("vault_delete_entry", { id }),

  /** Request password reveal — returns the decrypted password from Rust */
  revealPassword: (id: string): Promise<string> =>
    safeInvoke("vault_reveal_password", { id }),

  /** Request TOTP code — generated in Rust, never stores the secret in JS */
  generateTotp: (id: string): Promise<string> =>
    safeInvoke("vault_generate_totp", { id }),

  searchEntries: (query: string): Promise<VaultEntryView[]> =>
    safeInvoke("vault_search_entries", { query }),
} as const;

// ─── Auth Commands ─────────────────────────────────────────────────

export interface SessionInfo {
  session_id: string;
  expires_at: string;
  is_unlocked: boolean;
}

export const authCommands = {
  unlock: (masterPassword: string): Promise<SessionInfo> =>
    safeInvoke("auth_unlock", { masterPassword }),

  lock: (): Promise<void> =>
    safeInvoke("auth_lock"),

  getSession: (): Promise<SessionInfo | null> =>
    safeInvoke("auth_get_session"),

  isVaultInitialized: (): Promise<boolean> =>
    safeInvoke("auth_is_vault_initialized"),

  initializeVault: (masterPassword: string, hint?: string): Promise<void> =>
    safeInvoke("auth_initialize_vault", { masterPassword, hint }),
} as const;

// ─── Folder Commands ───────────────────────────────────────────────

export interface FolderView {
  id: string;
  name: string;
  parent_id: string | null;
  created_at: string;
}

export const folderCommands = {
  listFolders: (): Promise<FolderView[]> =>
    safeInvoke("folder_list"),

  createFolder: (name: string, parentId?: string): Promise<FolderView> =>
    safeInvoke("folder_create", { name, parentId }),

  deleteFolder: (id: string): Promise<void> =>
    safeInvoke("folder_delete", { id }),
} as const;

// ─── Scanner Commands ──────────────────────────────────────────────

export interface ScanResultView {
  id: string;
  threat_level: string;
  description: string;
  recommendation: string;
  scanned_at: string;
}

export const scannerCommands = {
  runFullScan: (): Promise<ScanResultView[]> =>
    safeInvoke("scanner_run_full_scan"),

  checkBreach: (username: string): Promise<ScanResultView | null> =>
    safeInvoke("scanner_check_breach", { username }),

  getPasswordStrength: (password: string): Promise<unknown> =>
    safeInvoke("scanner_password_strength", { password }),
} as const;

// ─── Audit Commands ────────────────────────────────────────────────

export interface AuditEventView {
  id: string;
  category: string;
  action: string;
  description: string;
  timestamp: string;
}

export interface AuditPage {
  events: AuditEventView[];
  total_count: number;
  has_more: boolean;
}

export const auditCommands = {
  queryEvents: (params: {
    category?: string;
    from?: string;
    to?: string;
    limit?: number;
    cursor?: string;
  }): Promise<AuditPage> =>
    safeInvoke("audit_query_events", { params }),

  exportEvents: (format: string, from?: string, to?: string): Promise<string> =>
    safeInvoke("audit_export_events", { format, from, to }),
} as const;

// ─── Settings Commands ─────────────────────────────────────────────

export interface AppSettings {
  auto_lock_minutes: number;
  theme: string;
  language: string;
  clear_clipboard_seconds: number;
}

export const settingsCommands = {
  getSettings: (): Promise<AppSettings> =>
    safeInvoke("settings_get"),

  updateSettings: (settings: Partial<AppSettings>): Promise<AppSettings> =>
    safeInvoke("settings_update", { settings }),
} as const;
