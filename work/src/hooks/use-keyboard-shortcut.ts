/**
 * Keyboard shortcut hook.
 *
 * Registers global keyboard shortcuts:
 * - Cmd/Ctrl+L: Lock vault
 * - Cmd/Ctrl+F: Focus search
 * - Escape: Close active dialog (handled by Dialog component)
 */

import { useEffect, useCallback } from "react";
import { useAuthStore } from "@/stores/auth-store";
import { useVaultStore } from "@/stores/vault-store";

interface ShortcutConfig {
  key: string;
  ctrlOrMeta: boolean;
  action: () => void;
  description: string;
}

export function useKeyboardShortcuts(): void {
  const appState = useAuthStore((s) => s.appState);
  const lock = useAuthStore((s) => s.lock);
  const clearVaultState = useVaultStore((s) => s.clearState);

  const handleLock = useCallback(async () => {
    await lock();
    clearVaultState();
  }, [lock, clearVaultState]);

  const handleSearch = useCallback(() => {
    const searchInput = document.querySelector<HTMLInputElement>(
      'input[type="search"], input[aria-label*="earch"]',
    );
    searchInput?.focus();
  }, []);

  useEffect(() => {
    const shortcuts: ShortcutConfig[] = [
      {
        key: "l",
        ctrlOrMeta: true,
        action: handleLock,
        description: "Lock vault",
      },
      {
        key: "f",
        ctrlOrMeta: true,
        action: handleSearch,
        description: "Focus search",
      },
    ];

    const handleKeyDown = (e: KeyboardEvent) => {
      // Don't trigger shortcuts when typing in input fields
      // (except for the search shortcut)
      const target = e.target as HTMLElement;
      const isInputField =
        target.tagName === "INPUT" ||
        target.tagName === "TEXTAREA" ||
        target.tagName === "SELECT" ||
        target.isContentEditable;

      for (const shortcut of shortcuts) {
        const matchesKey = e.key.toLowerCase() === shortcut.key;
        const matchesModifier = shortcut.ctrlOrMeta
          ? e.ctrlKey || e.metaKey
          : true;

        if (matchesKey && matchesModifier) {
          // Allow search shortcut even in input fields
          if (isInputField && shortcut.key !== "f") continue;

          // Only allow lock when unlocked
          if (shortcut.key === "l" && appState !== "unlocked") continue;

          e.preventDefault();
          shortcut.action();
          return;
        }
      }
    };

    document.addEventListener("keydown", handleKeyDown);

    return () => {
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [appState, handleLock, handleSearch]);
}
