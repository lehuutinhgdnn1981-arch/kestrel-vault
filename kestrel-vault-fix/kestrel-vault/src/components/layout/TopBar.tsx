import React from "react";
import { useLocation } from "react-router-dom";
import { Search, Lock } from "lucide-react";
import { useAuthStore } from "@/stores/auth-store";
import { useAppStore } from "@/stores/app-store";
import { cn } from "@/lib/utils";

/** Map route paths to human-readable labels */
const ROUTE_LABELS: Record<string, string> = {
  "/": "Password Vault",
  "/notes": "Secure Notes",
  "/files": "File Vault",
  "/scanner": "Threat Scanner",
  "/audit": "Audit Logs",
  "/security-center": "Security Center",
  "/settings": "Settings",
};

export const TopBar: React.FC = () => {
  const location = useLocation();
  const appState = useAuthStore((s) => s.appState);
  const lock = useAuthStore((s) => s.lock);
  const searchQuery = useAppStore((s) => s.searchQuery);
  const setSearchQuery = useAppStore((s) => s.setSearchQuery);
  const isUnlocked = appState === "unlocked";

  const currentLabel = ROUTE_LABELS[location.pathname] ?? "KESTREL Vault";

  return (
    <div className="flex h-full items-center gap-4 px-4">
      {/* Breadcrumb / Page title */}
      <div className="flex items-center gap-2 text-sm">
        <span className="font-medium text-foreground">{currentLabel}</span>
      </div>

      {/* Spacer */}
      <div className="flex-1" />

      {/* Search bar */}
      {isUnlocked && (
        <div className="relative max-w-xs flex-1">
          <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          <input
            type="search"
            placeholder="Search vault…"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className={cn(
              "h-8 w-full rounded-md border border-input bg-background pl-8 pr-3",
              "text-sm text-foreground placeholder:text-muted-foreground",
              "focus:border-ring focus:outline-none focus:ring-1 focus:ring-ring",
              "transition-colors duration-150",
            )}
            aria-label="Search vault entries"
          />
        </div>
      )}

      {/* Vault status indicator */}
      <div className="flex items-center gap-2">
        <div
          className={cn(
            "h-2 w-2 rounded-full",
            isUnlocked ? "bg-success" : "bg-muted-foreground",
          )}
          aria-label={isUnlocked ? "Vault unlocked" : "Vault locked"}
        />
        <span className="text-xs text-muted-foreground">
          {isUnlocked ? "Unlocked" : "Locked"}
        </span>
      </div>

      {/* Quick-lock button */}
      {isUnlocked && (
        <button
          type="button"
          onClick={() => lock()}
          className="flex h-7 w-7 items-center justify-center rounded-md text-muted-foreground transition-colors duration-150 hover:bg-accent hover:text-foreground"
          aria-label="Lock vault"
          title="Lock vault (Ctrl+L)"
        >
          <Lock className="h-4 w-4" aria-hidden="true" />
        </button>
      )}
    </div>
  );
};
