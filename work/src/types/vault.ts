/**
 * TypeScript types for the password vault.
 *
 * IMPORTANT: These are VIEW types only.
 * Passwords are NEVER included in these types.
 * The Rust backend handles all encryption/decryption.
 * React NEVER sees raw password data except during
 * user-initiated reveal (which comes from tauri.ts invoke).
 */

// ─── Vault Entry ───────────────────────────────────────────────────

export interface VaultEntry {
  id: string;
  title: string;
  username: string;
  /** URL is display-only, not a security boundary */
  url: string | null;
  folder_id: string | null;
  has_totp: boolean;
  /** Truncated preview of notes — never full content */
  notes_preview: string | null;
  created_at: string;
  updated_at: string;
  /**
   * Password is NEVER a field on this type.
   * Use vaultCommands.revealPassword(id) to request
   * a decrypted password from the Rust backend.
   */
}

export interface CreateEntryRequest {
  title: string;
  username: string;
  /** Sent to Rust for encryption — never stored in React state */
  password: string;
  url?: string | null;
  folder_id?: string | null;
  notes?: string | null;
  totp_secret?: string | null;
}

export interface UpdateEntryRequest {
  id: string;
  title?: string;
  username?: string;
  /** Sent to Rust for encryption — never stored in React state */
  password?: string;
  url?: string | null;
  folder_id?: string | null;
  notes?: string | null;
  totp_secret?: string | null;
}

// ─── Folders ───────────────────────────────────────────────────────

export interface Folder {
  id: string;
  name: string;
  parent_id: string | null;
  created_at: string;
}

export interface FolderTree {
  folder: Folder;
  children: FolderTree[];
}

// ─── Sort & Filter ─────────────────────────────────────────────────

export type SortField = "title" | "username" | "updated_at" | "created_at";
export type SortDirection = "asc" | "desc";

export interface VaultSortOptions {
  field: SortField;
  direction: SortDirection;
}

export interface VaultFilterOptions {
  search: string;
  folder_id: string | null;
  has_totp: boolean | null;
  has_url: boolean | null;
}
