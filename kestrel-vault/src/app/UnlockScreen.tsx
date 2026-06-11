/**
 * Vault unlock screen.
 *
 * Clean, professional design — NOT a hero section.
 * No decorative gradients, no floating cards, no neon.
 * Inspired by Bitwarden/1Password lock screens.
 */

import React, { useState, useCallback, useRef, useEffect } from "react";
import { Shield, Loader2 } from "lucide-react";
import { useAuthStore } from "@/stores/auth-store";
import { PasswordInput } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export const UnlockScreen: React.FC = () => {
  const [masterPassword, setMasterPassword] = useState("");
  const unlockState = useAuthStore((s) => s.unlockState);
  const error = useAuthStore((s) => s.error);
  const unlock = useAuthStore((s) => s.unlock);
  const isInitialized = useAuthStore((s) => s.isInitialized);
  const clearError = useAuthStore((s) => s.clearError);
  const inputRef = useRef<HTMLInputElement>(null);

  // Focus password input on mount
  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  const handleSubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      if (!masterPassword.trim()) return;
      await unlock(masterPassword);
    },
    [masterPassword, unlock],
  );

  const handlePasswordChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      setMasterPassword(e.target.value);
      if (error) clearError();
    },
    [error, clearError],
  );

  const isUnlocking = unlockState === "unlocking";

  return (
    <div className="flex h-screen w-screen items-center justify-center bg-background">
      <div className="w-full max-w-sm space-y-8 px-6">
        {/* Logo / Branding — subtle, not neon */}
        <div className="flex flex-col items-center space-y-3">
          <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-primary/10">
            <Shield className="h-6 w-6 text-primary" aria-hidden="true" />
          </div>
          <div className="text-center">
            <h1 className="text-lg font-semibold text-foreground">
              KESTREL Vault
            </h1>
            <p className="mt-1 text-sm text-muted-foreground">
              {isInitialized ? "Enter your master password to unlock" : "Create a master password to get started"}
            </p>
          </div>
        </div>

        {/* Unlock form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          <PasswordInput
            ref={inputRef}
            label="Master Password"
            placeholder="Enter master password"
            value={masterPassword}
            onChange={handlePasswordChange}
            error={unlockState === "failed" ? error ?? "Invalid master password" : undefined}
            disabled={isUnlocking}
            autoComplete={isInitialized ? "current-password" : "new-password"}
          />

          <Button
            type="submit"
            className="w-full"
            isLoading={isUnlocking}
            disabled={!masterPassword.trim()}
          >
            {isInitialized ? "Unlock" : "Create Vault"}
          </Button>
        </form>

        {/* Status text */}
        {isUnlocking && (
          <p className="text-center text-xs text-muted-foreground">
            Verifying master password…
          </p>
        )}

        {/* Keyboard shortcut hint */}
        <p className="text-center text-2xs text-muted-foreground">
          Press Enter to unlock · Ctrl+L to lock from anywhere
        </p>
      </div>
    </div>
  );
};
