/**
 * Audit Log view.
 *
 * Displays all vault activity and security events with
 * filtering, pagination, and export capabilities.
 * All event data comes from the Rust backend.
 */

import React, { useEffect, useState, useCallback } from "react";
import {
  ScrollText,
  Download,
  Filter,
  ChevronLeft,
  ChevronRight,
  Shield,
  Eye,
  Lock,
  Unlock,
  FileText,
  Trash2,
  AlertTriangle,
  Loader2,
} from "lucide-react";
import { auditCommands, type AuditEventView } from "@/lib/tauri";
import { useAuthStore } from "@/stores/auth-store";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn, formatRelativeTime } from "@/lib/utils";

// ─── Category icon mapping ────────────────────────────────────────

const CATEGORY_ICONS: Record<string, React.FC<{ className?: string }>> = {
  Vault: FileText,
  Auth: Lock,
  Notes: FileText,
  Scanner: Shield,
  Audit: ScrollText,
  Security: Shield,
};

const CATEGORY_COLORS: Record<string, string> = {
  Vault: "text-blue-500 bg-blue-500/10",
  Auth: "text-purple-500 bg-purple-500/10",
  Notes: "text-teal-500 bg-teal-500/10",
  Scanner: "text-yellow-500 bg-yellow-500/10",
  Audit: "text-muted-foreground bg-muted/20",
  Security: "text-red-500 bg-red-500/10",
};

const PAGE_SIZE = 25;

// ─── Main AuditView ───────────────────────────────────────────────

export const AuditView: React.FC = () => {
  const appState = useAuthStore((s) => s.appState);

  const [events, setEvents] = useState<AuditEventView[]>([]);
  const [totalCount, setTotalCount] = useState(0);
  const [hasMore, setHasMore] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [isExporting, setIsExporting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [categoryFilter, setCategoryFilter] = useState<string | undefined>(undefined);
  const [offset, setOffset] = useState(0);

  const fetchEvents = useCallback(
    async (cat?: string, off?: number) => {
      setIsLoading(true);
      setError(null);
      try {
        const page = await auditCommands.queryEvents({
          category: cat,
          limit: PAGE_SIZE,
          offset: off ?? 0,
        });
        setEvents(page.events);
        setTotalCount(page.total_count);
        setHasMore(page.has_more);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load events");
      } finally {
        setIsLoading(false);
      }
    },
    [],
  );

  // Load events on mount and when filters change
  useEffect(() => {
    if (appState === "unlocked" || appState === "locked") {
      fetchEvents(categoryFilter, offset);
    }
  }, [appState, categoryFilter, offset, fetchEvents]);

  const handleExport = useCallback(async (format: string) => {
    setIsExporting(true);
    try {
      const data = await auditCommands.exportEvents(format);
      // Create a download blob
      const blob = new Blob([data], {
        type: format === "csv" ? "text/csv" : "application/json",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `kestrel-audit-${new Date().toISOString().slice(0, 10)}.${format}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Export failed");
    } finally {
      setIsExporting(false);
    }
  }, []);

  const categories = ["Vault", "Auth", "Notes", "Scanner", "Audit", "Security"];
  const currentPage = Math.floor(offset / PAGE_SIZE) + 1;
  const totalPages = Math.max(1, Math.ceil(totalCount / PAGE_SIZE));

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-foreground">Audit Logs</h2>
          <p className="text-sm text-muted-foreground">
            Track all vault activity and security events
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => handleExport("json")}
            disabled={isExporting || totalCount === 0}
            isLoading={isExporting}
          >
            <Download className="mr-1 h-3.5 w-3.5" />
            Export
          </Button>
        </div>
      </div>

      {/* Category filters */}
      <div className="flex items-center gap-2">
        <Filter className="h-3.5 w-3.5 text-muted-foreground" />
        <button
          type="button"
          onClick={() => {
            setCategoryFilter(undefined);
            setOffset(0);
          }}
          className={cn(
            "rounded-full px-3 py-1 text-xs font-medium transition-colors",
            !categoryFilter
              ? "bg-primary text-primary-foreground"
              : "bg-muted/50 text-muted-foreground hover:bg-muted",
          )}
        >
          All
        </button>
        {categories.map((cat) => (
          <button
            key={cat}
            type="button"
            onClick={() => {
              setCategoryFilter(cat);
              setOffset(0);
            }}
            className={cn(
              "rounded-full px-3 py-1 text-xs font-medium transition-colors",
              categoryFilter === cat
                ? "bg-primary text-primary-foreground"
                : "bg-muted/50 text-muted-foreground hover:bg-muted",
            )}
          >
            {cat}
          </button>
        ))}
      </div>

      {/* Events table */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm">
            {totalCount.toLocaleString()} {totalCount === 1 ? "event" : "events"}
          </CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading && (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          )}

          {error && (
            <p className="py-4 text-center text-sm text-destructive">{error}</p>
          )}

          {!isLoading && events.length === 0 && (
            <div className="flex flex-col items-center gap-2 py-8">
              <ScrollText className="h-8 w-8 text-muted-foreground/30" />
              <p className="text-sm text-muted-foreground">No audit events found</p>
            </div>
          )}

          {!isLoading && events.length > 0 && (
            <div className="space-y-1">
              {events.map((event) => {
                const Icon = CATEGORY_ICONS[event.category] || ScrollText;
                const color = CATEGORY_COLORS[event.category] || "text-muted-foreground bg-muted/20";

                return (
                  <div
                    key={event.id}
                    className="flex items-center gap-3 rounded-md px-3 py-2 hover:bg-muted/30"
                  >
                    <div className={cn("flex h-7 w-7 items-center justify-center rounded", color)}>
                      <Icon className="h-3.5 w-3.5" />
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-medium">{event.action}</span>
                        <span className="rounded bg-muted/50 px-1.5 py-0.5 text-xs text-muted-foreground">
                          {event.category}
                        </span>
                      </div>
                      <p className="truncate text-xs text-muted-foreground">
                        {event.subject}
                      </p>
                    </div>
                    <span className="flex-shrink-0 text-xs text-muted-foreground">
                      {formatRelativeTime(event.timestamp)}
                    </span>
                  </div>
                );
              })}
            </div>
          )}

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="mt-4 flex items-center justify-between border-t border-border pt-3">
              <p className="text-xs text-muted-foreground">
                Page {currentPage} of {totalPages}
              </p>
              <div className="flex items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={offset === 0}
                  onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
                >
                  <ChevronLeft className="h-3.5 w-3.5" />
                  Previous
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={!hasMore}
                  onClick={() => setOffset(offset + PAGE_SIZE)}
                >
                  Next
                  <ChevronRight className="h-3.5 w-3.5" />
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
};
