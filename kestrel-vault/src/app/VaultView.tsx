/**
 * Password vault view (skeleton).
 *
 * Entry list panel + Entry detail panel.
 * Placeholder content for Phase 04.
 */

import React, { useEffect } from "react";
import { Plus, Search, Shield, ChevronRight } from "lucide-react";
import { useVaultStore } from "@/stores/vault-store";
import { useAuthStore } from "@/stores/auth-store";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import { formatRelativeTime, truncate } from "@/lib/utils";

export const VaultView: React.FC = () => {
  const entries = useVaultStore((s) => s.entries);
  const selectedEntryId = useVaultStore((s) => s.selectedEntryId);
  const selectEntry = useVaultStore((s) => s.selectEntry);
  const fetchEntries = useVaultStore((s) => s.fetchEntries);
  const isLoading = useVaultStore((s) => s.isLoadingEntries);
  const appState = useAuthStore((s) => s.appState);

  useEffect(() => {
    if (appState === "unlocked") {
      fetchEntries();
    }
  }, [appState, fetchEntries]);

  const selectedEntry = entries.find((e) => e.id === selectedEntryId) ?? null;

  return (
    <div className="flex h-full gap-4">
      {/* Entry list panel */}
      <div className="w-80 flex-shrink-0 space-y-3">
        {/* Search & Add */}
        <div className="flex items-center gap-2">
          <div className="relative flex-1">
            <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
            <input
              type="search"
              placeholder="Filter entries…"
              className="h-8 w-full rounded-md border border-input bg-background pl-8 pr-3 text-sm text-foreground placeholder:text-muted-foreground focus:border-ring focus:outline-none focus:ring-1 focus:ring-ring"
              aria-label="Filter vault entries"
            />
          </div>
          <Button size="icon" variant="outline" aria-label="Add new entry">
            <Plus className="h-4 w-4" />
          </Button>
        </div>

        {/* Entry list */}
        <div className="space-y-1 overflow-y-auto" style={{ maxHeight: "calc(100vh - 12rem)" }}>
          {isLoading && (
            <p className="py-8 text-center text-sm text-muted-foreground">
              Loading entries…
            </p>
          )}

          {!isLoading && entries.length === 0 && (
            <div className="py-8 text-center">
              <Shield className="mx-auto h-8 w-8 text-muted-foreground/50" />
              <p className="mt-2 text-sm text-muted-foreground">
                No entries yet
              </p>
              <p className="text-xs text-muted-foreground">
                Add your first password to get started
              </p>
            </div>
          )}

          {entries.map((entry) => (
            <button
              key={entry.id}
              type="button"
              onClick={() => selectEntry(entry.id)}
              className={cn(
                "flex w-full items-center gap-3 rounded-md px-3 py-2.5 text-left transition-colors",
                selectedEntryId === entry.id
                  ? "bg-accent text-accent-foreground"
                  : "text-foreground hover:bg-accent/50",
              )}
            >
              <div className="flex h-8 w-8 items-center justify-center rounded bg-secondary text-xs font-medium text-secondary-foreground">
                {entry.title.charAt(0).toUpperCase()}
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium truncate">{entry.title}</p>
                <p className="text-xs text-muted-foreground truncate">
                  {entry.username}
                </p>
              </div>
              <ChevronRight className="h-3.5 w-3.5 flex-shrink-0 text-muted-foreground" />
            </button>
          ))}
        </div>
      </div>

      {/* Entry detail panel */}
      <div className="flex-1">
        {selectedEntry ? (
          <Card>
            <CardHeader>
              <CardTitle>{selectedEntry.title}</CardTitle>
              <p className="text-sm text-muted-foreground">
                {selectedEntry.username}
              </p>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {/* URL */}
                {selectedEntry.url && (
                  <div>
                    <label className="text-xs font-medium text-muted-foreground">
                      Website
                    </label>
                    <p className="mt-0.5 text-sm text-foreground">
                      {selectedEntry.url}
                    </p>
                  </div>
                )}

                {/* Password — reveal button only, never stored in state */}
                <div>
                  <label className="text-xs font-medium text-muted-foreground">
                    Password
                  </label>
                  <div className="mt-0.5 flex items-center gap-2">
                    <p className="text-sm text-foreground">••••••••</p>
                    <Button variant="ghost" size="sm">
                      Reveal
                    </Button>
                  </div>
                </div>

                {/* TOTP */}
                {selectedEntry.has_totp && (
                  <div>
                    <label className="text-xs font-medium text-muted-foreground">
                      Verification Code
                    </label>
                    <div className="mt-0.5 flex items-center gap-2">
                      <p className="font-mono text-sm text-foreground">------</p>
                      <Button variant="ghost" size="sm">
                        Generate
                      </Button>
                    </div>
                  </div>
                )}

                {/* Notes preview */}
                {selectedEntry.notes_preview && (
                  <div>
                    <label className="text-xs font-medium text-muted-foreground">
                      Notes
                    </label>
                    <p className="mt-0.5 text-sm text-foreground">
                      {truncate(selectedEntry.notes_preview, 200)}
                    </p>
                  </div>
                )}

                {/* Timestamps */}
                <div className="flex gap-6 border-t border-border pt-4">
                  <div>
                    <label className="text-xs font-medium text-muted-foreground">
                      Created
                    </label>
                    <p className="text-xs text-muted-foreground">
                      {formatRelativeTime(selectedEntry.created_at)}
                    </p>
                  </div>
                  <div>
                    <label className="text-xs font-medium text-muted-foreground">
                      Modified
                    </label>
                    <p className="text-xs text-muted-foreground">
                      {formatRelativeTime(selectedEntry.updated_at)}
                    </p>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        ) : (
          <div className="flex h-full items-center justify-center">
            <div className="text-center">
              <Shield className="mx-auto h-10 w-10 text-muted-foreground/30" />
              <p className="mt-3 text-sm text-muted-foreground">
                Select an entry to view details
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
