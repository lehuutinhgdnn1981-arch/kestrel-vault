/**
 * Tauri IPC abstraction layer.
 *
 * IMPORTANT: React NEVER calls invoke directly from components.
 * All Tauri API calls are centralized here with type-safe wrappers.
 * React NEVER owns encryption keys — all crypto goes through Rust.
 *
 * # IPC Contract
 *
 * | Category   | Required State | Notes                            |
 * |------------|---------------|----------------------------------|
 * | Auth       | Varies        | init=Uninitialized, unlock=Locked |
 * | Vault CRUD | Unlocked      | All require unlocked vault        |
 * | Audit      | Any           | Security visibility always        |
 * | Scanner    | Varies        | strength=Any, others=Unlocked     |
 * | Settings   | Varies        | read=Any, write=Unlocked          |
 * | Crypto     | Blocked       | Use domain commands instead       |
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

    // Handle Tauri CommandError objects: { code, message }
    // Rust serializes CommandError as JSON, so JS receives an object.
    // Using String() on it would produce "[object Object]".
    if (typeof error === "object" && error !== null) {
      const errObj = error as Record<string, unknown>;
      const message =
        typeof errObj.message === "string"
          ? errObj.message
          : JSON.stringify(error);
      const code =
        typeof errObj.code === "string"
          ? String(errObj.code)
          : "COMMAND_FAILED";
      throw new TauriCommandError(code, message, command);
    }

    // Fallback for string or other primitive errors
    const errStr = String(error);
    throw new TauriCommandError("UNKNOWN", errStr, command);
  }
}

// ─── Vault Entry Types ────────────────────────────────────────────

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

export interface PasswordRevealResult {
  password: string;
  auto_clear_seconds: number;
}

export const vaultCommands = {
  listEntries: (folderId?: string, limit?: number, offset?: number): Promise<VaultEntryView[]> =>
    safeInvoke("vault_list_entries", { folderId, limit, offset }),

  getEntry: (id: string): Promise<VaultEntryView> =>
    safeInvoke("vault_get_entry", { id }),

  createEntry: (
    title: string,
    username: string,
    password: string,
    url?: string,
    notes?: string,
    folderId?: string,
    tags?: string[],
  ): Promise<VaultEntryView> =>
    safeInvoke("vault_create_entry", {
      title,
      username,
      password,
      url: url ?? null,
      notes: notes ?? null,
      folderId: folderId ?? null,
      tags: tags ?? [],
    }),

  updateEntry: (
    id: string,
    updates: {
      title?: string;
      username?: string;
      password?: string;
      url?: string;
      notes?: string;
      folderId?: string;
      tags?: string[];
    },
  ): Promise<VaultEntryView> =>
    safeInvoke("vault_update_entry", {
      id,
      title: updates.title,
      username: updates.username,
      password: updates.password,
      url: updates.url,
      notes: updates.notes,
      folderId: updates.folderId,
      tags: updates.tags,
    }),

  deleteEntry: (id: string, confirm: boolean): Promise<void> =>
    safeInvoke("vault_delete_entry", { id, confirm }),

  /** Request password reveal — returns the decrypted password from Rust.
   *  Auto-clears after auto_clear_seconds. */
  revealPassword: (id: string): Promise<PasswordRevealResult> =>
    safeInvoke("vault_reveal_password", { id }),

  searchEntries: (query: string, limit?: number): Promise<VaultEntryView[]> =>
    safeInvoke("vault_search_entries", { query, limit }),
} as const;

// ─── Auth Commands ─────────────────────────────────────────────────

export interface SessionInfo {
  session_id: string;
  expires_at: string;
  is_unlocked: boolean;
}

export interface VaultStatus {
  state: string;
  is_initialized: boolean;
  is_unlocked: boolean;
  failed_unlock_attempts: number;
  is_locked_out: boolean;
}

export interface VaultInitResult {
  initialized: boolean;
  state: string;
}

export interface VaultLockResult {
  state: string;
}

export const authCommands = {
  /** Initialize vault for the first time. Requires Uninitialized state. */
  initializeVault: (masterPassword: string, hint?: string): Promise<VaultInitResult> =>
    safeInvoke("auth_initialize_vault", { masterPassword, hint }),

  /** Unlock vault with master password. Requires Locked state. */
  unlock: (masterPassword: string): Promise<SessionInfo> =>
    safeInvoke("auth_unlock", { masterPassword }),

  /** Lock vault immediately. Requires Unlocked state. */
  lock: (): Promise<VaultLockResult> =>
    safeInvoke("auth_lock"),

  /** Get current session info (null if locked). Available in any state. */
  getSession: (): Promise<SessionInfo | null> =>
    safeInvoke("auth_get_session"),

  /** Check if vault has been initialized. Available in any state. */
  isVaultInitialized: (): Promise<boolean> =>
    safeInvoke("auth_is_vault_initialized"),

  /** Get vault status with lockout info. Available in any state. */
  getVaultStatus: (): Promise<VaultStatus> =>
    safeInvoke("auth_get_vault_status"),

  /** Change master password. Requires Unlocked state. */
  changePassword: (currentPassword: string, newPassword: string): Promise<void> =>
    safeInvoke("auth_change_password", { currentPassword, newPassword }),
} as const;

// ─── Folder Commands ───────────────────────────────────────────────

export interface FolderView {
  id: string;
  name: string;
  parent_id: string | null;
  entry_count: number;
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

export interface PasswordStrengthResult {
  score: number;
  label: string;
  entropy_bits: number;
  warnings: string[];
  suggestions: string[];
}

export interface ScanResultView {
  id: string;
  threat_level: string;
  description: string;
  recommendation: string;
  entry_id: string | null;
}

export interface BreachCheckEntryResult {
  is_breached: boolean;
  occurrence_count: number;
  message: string;
  threat_level: string;
}

export const scannerCommands = {
  /** Analyze password strength. Available in any state. */
  getPasswordStrength: (password: string): Promise<PasswordStrengthResult> =>
    safeInvoke("scanner_password_strength", { password }),

  /** Check breach database by username. Requires Unlocked state. */
  checkBreach: (username: string): Promise<ScanResultView | null> =>
    safeInvoke("scanner_check_breach", { username }),

  /** Check if a password has been breached via HIBP API. Takes a raw password string (no vault decryption needed). */
  checkPasswordBreach: (password: string): Promise<BreachCheckEntryResult> =>
    safeInvoke("scanner_check_password_breach", { password }),

  /** Check if a vault entry's password has been breached via HIBP API. Requires Unlocked state. */
  checkEntryBreach: (entryId: string): Promise<BreachCheckEntryResult> =>
    safeInvoke("scanner_check_entry_breach", { entryId }),

  /** Run comprehensive vulnerability scan. Requires Unlocked state. */
  runFullScan: (): Promise<ScanResultView[]> =>
    safeInvoke("scanner_run_full_scan"),

  /** Get computed security score with breakdown. Requires Unlocked state. */
  getSecurityScore: (): Promise<SecurityScore> =>
    safeInvoke("scanner_get_security_score"),
} as const;

// ─── Audit Commands ────────────────────────────────────────────────

export interface AuditEventView {
  id: string;
  category: string;
  action: string;
  subject: string;
  timestamp: string;
}

export interface AuditPage {
  events: AuditEventView[];
  total_count: number;
  has_more: boolean;
}

export const auditCommands = {
  /** Query audit events. Available in any state. */
  queryEvents: (params: {
    category?: string;
    from?: string;
    to?: string;
    limit?: number;
    offset?: number;
  }): Promise<AuditPage> =>
    safeInvoke("audit_query_events", { ...params }),

  /** Export audit events to JSON or CSV. Rate-limited. */
  exportEvents: (format: string, from?: string, to?: string): Promise<string> =>
    safeInvoke("audit_export_events", { format, from, to }),
} as const;

// ─── Settings Commands ─────────────────────────────────────────────

export interface AppSettings {
  auto_lock_minutes: number;
  theme: string;
  language: string;
  clear_clipboard_seconds: number;
  lock_on_sleep: boolean;
  lock_on_blur: boolean;
  auto_backup: boolean;
  backup_frequency: string;
  backup_location: string;
  debug_mode: boolean;
  max_login_attempts: number;
  lockout_duration_seconds: number;
}

export const settingsCommands = {
  /** Get current settings. Available in any state. */
  getSettings: (): Promise<AppSettings> =>
    safeInvoke("settings_get"),

  /** Update settings. Requires Unlocked state.
   *  Tauri v2 commands expect camelCase keys, so we convert
   *  from snake_case (AppSettings) to camelCase before sending. */
  updateSettings: (settings: Partial<AppSettings>): Promise<AppSettings> =>
    safeInvoke("settings_update", {
      autoLockMinutes: settings.auto_lock_minutes,
      theme: settings.theme,
      language: settings.language,
      clearClipboardSeconds: settings.clear_clipboard_seconds,
      lockOnSleep: settings.lock_on_sleep,
      lockOnBlur: settings.lock_on_blur,
      autoBackup: settings.auto_backup,
      backupFrequency: settings.backup_frequency,
      backupLocation: settings.backup_location,
      debugMode: settings.debug_mode,
    }),

  /** Reset all settings to defaults. Requires Unlocked state. */
  resetSettings: (): Promise<AppSettings> =>
    safeInvoke("settings_reset"),
} as const;

// ─── Security Score ────────────────────────────────────────────────

export interface SecurityScore {
  score: number;
  label: string;
  breakdown: {
    password_health: number;
    breach_status: number;
    vault_hygiene: number;
    audit_compliance: number;
  };
}

// ─── Secure Notes ──────────────────────────────────────────────────

export interface SecureNoteView {
  id: string;
  title: string;
  content?: string;
  has_content: boolean;
  folder_id: string | null;
  created_at: string;
  updated_at: string;
}

export interface SecureNoteRevealResult {
  id: string;
  title: string;
  content: string;
  auto_clear_seconds: number;
}

export const noteCommands = {
  /** Create a new secure note. Requires Unlocked state. */
  createNote: (
    title: string,
    content: string,
    folderId?: string,
    tags?: string[],
  ): Promise<SecureNoteView> =>
    safeInvoke("note_create", {
      title,
      content,
      folderId: folderId ?? null,
      tags: tags ?? [],
    }),

  /** List secure notes with decrypted titles. Requires Unlocked state. */
  listNotes: (folderId?: string): Promise<SecureNoteView[]> =>
    safeInvoke("note_list", { folderId: folderId ?? null }),

  /** Get a single note by ID. Content NOT included. */
  getNote: (id: string): Promise<SecureNoteView> =>
    safeInvoke("note_get", { id }),

  /** Update a secure note. Only provided fields are changed. */
  updateNote: (
    id: string,
    updates: {
      title?: string;
      content?: string;
      folderId?: string;
      tags?: string[];
    },
  ): Promise<SecureNoteView> =>
    safeInvoke("note_update", {
      id,
      title: updates.title,
      content: updates.content,
      folderId: updates.folderId,
      tags: updates.tags,
    }),

  /** Delete a secure note. Requires confirmation. */
  deleteNote: (id: string, confirm: boolean): Promise<void> =>
    safeInvoke("note_delete", { id, confirm }),

  /** Reveal decrypted note content. Audit-logged. Auto-clears after timeout. */
  revealNote: (id: string): Promise<SecureNoteRevealResult> =>
    safeInvoke("note_reveal", { id }),
} as const;

// ─── File Entries ──────────────────────────────────────────────────

export interface FileEntryView {
  id: string;
  filename: string;
  mime_type: string;
  size_bytes: number;
  folder_id: string | null;
  created_at: string;
  updated_at: string;
}

export const fileCommands = {
  /** Upload and encrypt a file. Requires Unlocked state. */
  upload: (filePath: string, folderId?: string): Promise<FileEntryView> =>
    safeInvoke("file_upload", { filePath, folderId: folderId ?? null }),

  /** List encrypted files with decrypted metadata. Requires Unlocked state. */
  list: (folderId?: string): Promise<FileEntryView[]> =>
    safeInvoke("file_list", { folderId: folderId ?? null }),

  /** Get file metadata by ID (no content). Requires Unlocked state. */
  get: (id: string): Promise<FileEntryView> =>
    safeInvoke("file_get", { id }),

  /** Decrypt file and save to output path. Requires Unlocked state. */
  decrypt: (id: string, outputPath: string): Promise<string> =>
    safeInvoke("file_decrypt", { id, outputPath }),

  /** Delete an encrypted file (disk + DB). Requires confirmation. */
  delete: (id: string, confirm: boolean): Promise<void> =>
    safeInvoke("file_delete", { id, confirm }),
} as const;

// ─── Vault Data Management ────────────────────────────────────────

export const vaultDataCommands = {
  /** Export all vault data as encrypted JSON. Requires Unlocked state. */
  exportVault: (): Promise<string> =>
    safeInvoke("vault_export"),

  /** Import vault data from encrypted JSON. Requires Unlocked state. */
  importVault: (data: string): Promise<void> =>
    safeInvoke("vault_import", { data }),

  /** Clear all vault data (nuclear option). Requires confirmation. */
  clearVault: (confirm: boolean): Promise<void> =>
    safeInvoke("vault_clear", { confirm }),

  /** Create a backup of the vault database. Returns backup file path. */
  createBackup: (): Promise<string> =>
    safeInvoke("backup_create"),
} as const;
