/**
 * Auth store (Zustand).
 *
 * CRITICAL SECURITY RULES:
 * - This store NEVER holds the master password
 * - This store NEVER holds derived keys
 * - Only a session reference/token is stored, which the
 *   Rust backend validates on every command
 * - Auto-lock is tracked here but the actual lock
 *   operation goes through Tauri to Rust
 */

import { create } from "zustand";
import { authCommands, type SessionInfo } from "@/lib/tauri";
import type { AppState, UnlockState } from "@/types/app";
import { DEFAULT_SETTINGS, TIMEOUTS } from "@/lib/constants";

interface AuthState {
  /** Overall app state */
  appState: AppState;
  /** Unlock operation state */
  unlockState: UnlockState;
  /** Session info from Rust backend (NO secrets) */
  session: SessionInfo | null;
  /** Whether the vault has been initialized (first-run) */
  isInitialized: boolean | null;
  /** Lockout countdown in seconds (0 = not locked out) */
  lockoutSeconds: number;
  /** Last activity timestamp */
  lastActivity: number;
  /** Auto-lock timeout in minutes */
  autoLockMinutes: number;
  /** Error message from last auth operation */
  error: string | null;
}

interface AuthActions {
  /** Check if vault is initialized and if there's an active session */
  initialize: () => Promise<void>;

  /** Attempt to unlock the vault */
  unlock: (masterPassword: string) => Promise<void>;

  /** Lock the vault */
  lock: () => Promise<void>;

  /** Record user activity for auto-lock tracking */
  recordActivity: () => void;

  /** Set the auto-lock timeout */
  setAutoLockMinutes: (minutes: number) => void;

  /** Clear any error */
  clearError: () => void;

  /** Reset state on lock */
  resetOnLock: () => void;
}

export const useAuthStore = create<AuthState & AuthActions>((set, get) => ({
  appState: "initializing",
  unlockState: "idle",
  session: null,
  isInitialized: null,
  lockoutSeconds: 0,
  lastActivity: Date.now(),
  autoLockMinutes: DEFAULT_SETTINGS.autoLockMinutes,
  error: null,

  initialize: async () => {
    try {
      set({ appState: "initializing" });

      const [isInitialized, session] = await Promise.all([
        authCommands.isVaultInitialized(),
        authCommands.getSession(),
      ]);

      if (session?.is_unlocked) {
        set({
          appState: "unlocked",
          session,
          isInitialized: true,
          lastActivity: Date.now(),
        });
      } else {
        set({
          appState: isInitialized ? "locked" : "locked",
          isInitialized,
        });
      }
    } catch (error) {
      set({
        appState: "error",
        error: error instanceof Error ? error.message : "Initialization failed",
      });
    }
  },

  unlock: async (masterPassword: string) => {
    set({ unlockState: "unlocking", error: null });

    try {
      const session = await authCommands.unlock(masterPassword);

      set({
        appState: "unlocked",
        unlockState: "success",
        session,
        lastActivity: Date.now(),
      });

      // Reset unlock state after animation
      setTimeout(() => {
        set({ unlockState: "idle" });
      }, 500);
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Unlock failed";

      set({
        unlockState: "failed",
        error: message,
      });

      // Reset unlock state
      setTimeout(() => {
        set({ unlockState: "idle" });
      }, TIMEOUTS.toastDisplay);
    }
  },

  lock: async () => {
    try {
      await authCommands.lock();
    } catch {
      // Lock the frontend even if backend command fails
    }

    get().resetOnLock();
  },

  recordActivity: () => {
    set({ lastActivity: Date.now() });
  },

  setAutoLockMinutes: (minutes: number) => {
    set({ autoLockMinutes: minutes });
  },

  clearError: () => {
    set({ error: null });
  },

  resetOnLock: () => {
    set({
      appState: "locked",
      unlockState: "idle",
      session: null,
      lastActivity: 0,
      error: null,
    });
  },
}));
