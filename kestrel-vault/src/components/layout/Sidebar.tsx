import React from "react";
import { useNavigate, useLocation } from "react-router-dom";
import {
  Shield,
  FileText,
  FolderLock,
  ScanSearch,
  ScrollText,
  ShieldCheck,
  Settings,
  Lock,
  Unlock,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";
import { useAuthStore } from "@/stores/auth-store";
import { useAppStore } from "@/stores/app-store";
import { cn } from "@/lib/utils";
import { ROUTES } from "@/lib/constants";

interface NavItem {
  id: string;
  label: string;
  icon: React.ElementType;
  path: string;
}

const NAV_ITEMS: NavItem[] = [
  { id: "vault", label: "Password Vault", icon: Shield, path: ROUTES.VAULT },
  { id: "notes", label: "Secure Notes", icon: FileText, path: ROUTES.NOTES },
  { id: "files", label: "File Vault", icon: FolderLock, path: ROUTES.FILES },
  { id: "scanner", label: "Threat Scanner", icon: ScanSearch, path: ROUTES.SCANNER },
  { id: "audit", label: "Audit Logs", icon: ScrollText, path: ROUTES.AUDIT },
  { id: "security-center", label: "Security Center", icon: ShieldCheck, path: ROUTES.SECURITY_CENTER },
  { id: "settings", label: "Settings", icon: Settings, path: ROUTES.SETTINGS },
];

export const Sidebar: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const appState = useAuthStore((s) => s.appState);
  const lock = useAuthStore((s) => s.lock);
  const sidebarCollapsed = useAppStore((s) => s.sidebarCollapsed);
  const toggleSidebar = useAppStore((s) => s.toggleSidebar);
  const isUnlocked = appState === "unlocked";

  const isActive = (path: string): boolean => {
    if (path === "/") return location.pathname === "/";
    return location.pathname.startsWith(path);
  };

  return (
    <div className="flex h-full flex-col bg-card">
      {/* Brand header */}
      <div className="flex h-12 items-center border-b border-border px-4">
        {!sidebarCollapsed && (
          <span className="text-sm font-semibold tracking-wide text-foreground">
            KESTREL
          </span>
        )}
        {sidebarCollapsed && (
          <span className="mx-auto text-xs font-bold text-muted-foreground">
            K
          </span>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-2" aria-label="Main navigation">
        <ul className="space-y-0.5 px-2" role="list">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const active = isActive(item.path);
            const disabled = !isUnlocked && item.id !== "settings";

            return (
              <li key={item.id}>
                <button
                  type="button"
                  onClick={() => {
                    if (!disabled) navigate(item.path);
                  }}
                  disabled={disabled}
                  className={cn(
                    "flex w-full items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors duration-150",
                    active
                      ? "bg-accent text-accent-foreground font-medium"
                      : "text-muted-foreground hover:bg-accent/50 hover:text-foreground",
                    disabled && "cursor-not-allowed opacity-40",
                    sidebarCollapsed && "justify-center px-0",
                  )}
                  title={sidebarCollapsed ? item.label : undefined}
                  aria-current={active ? "page" : undefined}
                >
                  <Icon className="h-4 w-4 flex-shrink-0" aria-hidden="true" />
                  {!sidebarCollapsed && <span>{item.label}</span>}
                </button>
              </li>
            );
          })}
        </ul>
      </nav>

      {/* Bottom section */}
      <div className="border-t border-border p-2">
        {/* Lock/Unlock button */}
        <button
          type="button"
          onClick={() => {
            if (isUnlocked) lock();
          }}
          className={cn(
            "flex w-full items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors duration-150",
            isUnlocked
              ? "text-warning hover:bg-accent/50"
              : "text-success hover:bg-accent/50",
            sidebarCollapsed && "justify-center px-0",
          )}
          title={isUnlocked ? "Lock Vault" : "Vault Locked"}
        >
          {isUnlocked ? (
            <Lock className="h-4 w-4 flex-shrink-0" aria-hidden="true" />
          ) : (
            <Unlock className="h-4 w-4 flex-shrink-0" aria-hidden="true" />
          )}
          {!sidebarCollapsed && (
            <span>{isUnlocked ? "Lock Vault" : "Locked"}</span>
          )}
        </button>

        {/* Collapse toggle */}
        <button
          type="button"
          onClick={toggleSidebar}
          className="flex w-full items-center gap-3 rounded-md px-3 py-1.5 text-xs text-muted-foreground transition-colors duration-150 hover:bg-accent/50 hover:text-foreground"
          aria-label={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          {sidebarCollapsed ? (
            <ChevronRight className="h-3.5 w-3.5 flex-shrink-0" aria-hidden="true" />
          ) : (
            <>
              <ChevronLeft className="h-3.5 w-3.5 flex-shrink-0" aria-hidden="true" />
              <span>Collapse</span>
            </>
          )}
        </button>
      </div>
    </div>
  );
};
