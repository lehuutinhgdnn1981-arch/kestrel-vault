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
 * - Vault status is polled from Rust VaultStateMachine
 */

import { create } from "zustand";
import { authCommands, type SessionInfo } from "@/lib/tauri";
import type { AppState, UnlockState, VaultLifecycleState } from "@/types/app";
import { DEFAULT_SETTINGS, TIMEOUTS } from "@/lib/constants";
import { useVaultStore } from "@/stores/vault-store";
import { useNoteStore } from "@/stores/note-store";

interface AuthState {
  /** Overall app state */
  appState: AppState;
  /** Unlock operation state */
  unlockState: UnlockState;
  /** Session info from Rust backend (NO secrets) */
  session: SessionInfo | null;
  /** Whether the vault has been initialized (first-run) */
  isInitialized: boolean | null;
  /** Vault lifecycle state from Rust VaultStateMachine */
  vaultState: VaultLifecycleState | null;
  /** Number of failed unlock attempts in current locked period */
  failedUnlockAttempts: number;
  /** Whether the user is currently locked out */
  isLockedOut: boolean;
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

  /** Create a new vault (first-time initialization) */
  createVault: (masterPassword: string, hint?: string) => Promise<void>;

  /** Attempt to unlock the vault */
  unlock: (masterPassword: string) => Promise<void>;

  /** Lock the vault */
  lock: () => Promise<void>;

  /** Fetch vault status from Rust backend */
  refreshVaultStatus: () => Promise<void>;

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
  vaultState: null,
  failedUnlockAttempts: 0,
  isLockedOut: false,
  lockoutSeconds: 0,
  lastActivity: Date.now(),
  autoLockMinutes: DEFAULT_SETTINGS.autoLockMinutes,
  error: null,

  initialize: async () => {
    try {
      set({ appState: "initializing" });

      const [isInitialized, session, vaultStatus] = await Promise.all([
        authCommands.isVaultInitialized(),
        authCommands.getSession(),
        authCommands.getVaultStatus(),
      ]);

      if (session?.is_unlocked) {
        set({
          appState: "unlocked",
          session,
          isInitialized: true,
          vaultState: vaultStatus.state as VaultLifecycleState,
          failedUnlockAttempts: vaultStatus.failed_unlock_attempts,
          isLockedOut: vaultStatus.is_locked_out,
          lastActivity: Date.now(),
        });
      } else {
        set({
          appState: isInitialized ? "locked" : "locked",
          isInitialized,
          vaultState: vaultStatus.state as VaultLifecycleState,
          failedUnlockAttempts: vaultStatus.failed_unlock_attempts,
          isLockedOut: vaultStatus.is_locked_out,
        });
      }
    } catch (error) {
      set({
        appState: "error",
        error: error instanceof Error ? error.message : "Initialization failed",
      });
    }
  },

  createVault: async (masterPassword: string, hint?: string) => {
    set({ unlockState: "unlocking", error: null });

    try {
      const result = await authCommands.initializeVault(masterPassword, hint);

      set({
        appState: "locked",
        unlockState: "success",
        isInitialized: result.initialized,
        vaultState: result.state as VaultLifecycleState,
        lastActivity: Date.now(),
      });

      // After creation, the vault is in Locked state.
      // Now auto-unlock so the user can start using it immediately.
      await get().unlock(masterPassword);

      // Reset unlock state after animation
      setTimeout(() => {
        set({ unlockState: "idle" });
      }, 500);
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Vault creation failed";

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

  unlock: async (masterPassword: string) => {
    set({ unlockState: "unlocking", error: null });

    try {
      const session = await authCommands.unlock(masterPassword);

      set({
        appState: "unlocked",
        unlockState: "success",
        session,
        vaultState: "Unlocked",
        failedUnlockAttempts: 0,
        isLockedOut: false,
        lastActivity: Date.now(),
      });

      // Reset unlock state after animation
      setTimeout(() => {
        set({ unlockState: "idle" });
      }, 500);
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Unlock failed";

      // Refresh vault status to get updated failed attempt count
      try {
        const vaultStatus = await authCommands.getVaultStatus();
        set({
          unlockState: "failed",
          error: message,
          failedUnlockAttempts: vaultStatus.failed_unlock_attempts,
          isLockedOut: vaultStatus.is_locked_out,
        });
      } catch {
        set({
          unlockState: "failed",
          error: message,
        });
      }

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

  refreshVaultStatus: async () => {
    try {
      const vaultStatus = await authCommands.getVaultStatus();
      set({
        vaultState: vaultStatus.state,
        isInitialized: vaultStatus.is_initialized,
        failedUnlockAttempts: vaultStatus.failed_unlock_attempts,
        isLockedOut: vaultStatus.is_locked_out,
        appState: vaultStatus.is_unlocked ? "unlocked" : "locked",
      });
    } catch {
      // Silently fail — don't disrupt the UI for status check failures
    }
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
      vaultState: "Locked",
      failedUnlockAttempts: 0,
      isLockedOut: false,
      lastActivity: 0,
      error: null,
    });
    // Clear vault and note stores on lock to prevent data leakage
    useVaultStore.getState().clearState();
    useNoteStore.getState().clearState();
  },
}));
