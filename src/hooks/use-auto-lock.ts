/**
 * Auto-lock hook.
 *
 * Monitors user activity and locks the vault after
 * a configurable timeout of inactivity.
 *
 * - The actual lock command is sent to the Rust backend
 * - Frontend state is cleared via the auth store
 * - Activity is tracked via mouse, keyboard, and touch events
 */

import { useEffect, useRef, useCallback } from "react";
import { useAuthStore } from "@/stores/auth-store";
import { useVaultStore } from "@/stores/vault-store";
import { TIMEOUTS } from "@/lib/constants";

export function useAutoLock(): void {
  const appState = useAuthStore((s) => s.appState);
  const lock = useAuthStore((s) => s.lock);
  const recordActivity = useAuthStore((s) => s.recordActivity);
  const autoLockMinutes = useAuthStore((s) => s.autoLockMinutes);
  const lastActivity = useAuthStore((s) => s.lastActivity);
  const clearVaultState = useVaultStore((s) => s.clearState);

  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const handleActivity = useCallback(() => {
    if (appState === "unlocked") {
      recordActivity();
    }
  }, [appState, recordActivity]);

  const performLock = useCallback(async () => {
    await lock();
    clearVaultState();
  }, [lock, clearVaultState]);

  // Set up activity listeners
  useEffect(() => {
    if (appState !== "unlocked") return;

    const events = ["mousedown", "keydown", "touchstart", "scroll"] as const;

    events.forEach((event) => {
      document.addEventListener(event, handleActivity, { passive: true });
    });

    return () => {
      events.forEach((event) => {
        document.removeEventListener(event, handleActivity);
      });
    };
  }, [appState, handleActivity]);

  // Set up auto-lock check interval
  // autoLockMinutes = 0 means "Never" (auto-lock disabled)
  useEffect(() => {
    if (appState !== "unlocked" || autoLockMinutes === 0) {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
        intervalRef.current = null;
      }
      return;
    }

    intervalRef.current = setInterval(() => {
      const timeoutMs = autoLockMinutes * 60 * 1000;
      const elapsed = Date.now() - lastActivity;

      if (elapsed >= timeoutMs) {
        performLock();
      }
    }, TIMEOUTS.activityCheckInterval);

    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
        intervalRef.current = null;
      }
    };
  }, [appState, autoLockMinutes, lastActivity, performLock]);
}
