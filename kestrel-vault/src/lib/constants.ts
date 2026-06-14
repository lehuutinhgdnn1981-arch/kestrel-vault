/**
 * Application constants.
 *
 * IMPORTANT: These are UI-facing constants only.
 * Security thresholds (key derivation iterations, lockout counts, etc.)
 * are defined in the Rust backend and are NOT duplicated here.
 */

// ─── Route Paths ───────────────────────────────────────────────────

export const ROUTES = {
  HOME: "/",
  VAULT: "/",
  NOTES: "/notes",
  FILES: "/files",
  SCANNER: "/scanner",
  AUDIT: "/audit",
  SECURITY_CENTER: "/security-center",
  SETTINGS: "/settings",
} as const;

export type RoutePath = (typeof ROUTES)[keyof typeof ROUTES];

// ─── Default Settings ──────────────────────────────────────────────

export const DEFAULT_SETTINGS = {
  autoLockMinutes: 15,
  clearClipboardSeconds: 30,
  theme: "dark" as const,
  language: "en",
} as const;

// ─── Timeout Values ────────────────────────────────────────────────

export const TIMEOUTS = {
  /** How long before clipboard is cleared (ms) */
  clipboardClear: 30_000,
  /** Toast notification display duration (ms) */
  toastDisplay: 5_000,
  /** Toast duration for errors (ms) */
  toastErrorDisplay: 8_000,
  /** Debounce for search input (ms) */
  searchDebounce: 300,
  /** Auto-save delay for form fields (ms) */
  autoSaveDelay: 1_000,
  /** Activity check interval for auto-lock (ms) */
  activityCheckInterval: 10_000,
  /** Maximum time to wait for Tauri command (ms) */
  commandTimeout: 30_000,
} as const;

// ─── Rate Limits (UI only — backend enforces real limits) ──────────

export const UI_RATE_LIMITS = {
  /** Minimum interval between password reveal clicks (ms) */
  passwordRevealCooldown: 2_000,
  /** Minimum interval between TOTP generation clicks (ms) */
  totpCooldown: 1_000,
  /** Minimum interval between scan requests (ms) */
  scanCooldown: 10_000,
} as const;

// ─── UI Thresholds ─────────────────────────────────────────────────

export const UI_THRESHOLDS = {
  /** Number of entries before enabling virtual scrolling */
  virtualScrollThreshold: 200,
  /** Maximum search query length */
  maxSearchQueryLength: 256,
  /** Maximum notes preview length */
  notesPreviewLength: 120,
  /** Sidebar width in pixels */
  sidebarWidth: 224,
  /** Collapsed sidebar width in pixels */
  sidebarCollapsedWidth: 56,
  /** Top bar height in pixels */
  topBarHeight: 48,
  /** Default page size for lists */
  defaultPageSize: 50,
} as const;

// ─── App Metadata ──────────────────────────────────────────────────

export const APP_META = {
  name: "KESTREL Vault",
  version: "0.1.0",
  copyright: "© 2024 KESTREL Security",
} as const;
