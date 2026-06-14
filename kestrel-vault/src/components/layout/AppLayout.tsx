import React from "react";
import { Outlet } from "react-router-dom";
import { Sidebar } from "@/components/layout/Sidebar";
import { TopBar } from "@/components/layout/TopBar";
import { useAppStore } from "@/stores/app-store";
import { cn } from "@/lib/utils";
import { UI_THRESHOLDS } from "@/lib/constants";

export const AppLayout: React.FC = () => {
  const sidebarCollapsed = useAppStore((s) => s.sidebarCollapsed);

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-background text-foreground">
      {/* Sidebar */}
      <aside
        className={cn(
          "flex-shrink-0 border-r border-border transition-[width] duration-200 ease-in-out",
        )}
        style={{
          width: sidebarCollapsed
            ? UI_THRESHOLDS.sidebarCollapsedWidth
            : UI_THRESHOLDS.sidebarWidth,
        }}
      >
        <Sidebar />
      </aside>

      {/* Main content area */}
      <div className="flex flex-1 flex-col overflow-hidden">
        {/* Top bar */}
        <header
          className="flex-shrink-0 border-b border-border bg-background"
          style={{ height: UI_THRESHOLDS.topBarHeight }}
        >
          <TopBar />
        </header>

        {/* Page content */}
        <main className="flex-1 overflow-y-auto p-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
};
