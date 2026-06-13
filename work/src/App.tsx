import React, { useEffect } from "react";
import { Routes, Route, Navigate } from "react-router-dom";
import { useAuthStore } from "@/stores/auth-store";
import { useAutoLock } from "@/hooks/use-auto-lock";
import { useKeyboardShortcuts } from "@/hooks/use-keyboard-shortcut";
import { ToastContainer } from "@/components/ui/toast";
import { AppLayout } from "@/components/layout/AppLayout";
import { UnlockScreen } from "@/app/UnlockScreen";
import { VaultView } from "@/app/VaultView";
import { NotesView } from "@/app/NotesView";
import { FilesView } from "@/app/FilesView";
import { ScannerView } from "@/app/ScannerView";
import { AuditView } from "@/app/AuditView";
import { SecurityCenterView } from "@/app/SecurityCenterView";
import { SettingsView } from "@/app/SettingsView";
import { ROUTES } from "@/lib/constants";

// ─── Protected Route ───────────────────────────────────────────────

interface ProtectedRouteProps {
  children: React.ReactNode;
}

const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ children }) => {
  const appState = useAuthStore((s) => s.appState);

  if (appState === "locked") {
    return <Navigate to={ROUTES.VAULT} replace />;
  }

  if (appState === "initializing") {
    return (
      <div className="flex h-screen items-center justify-center bg-background">
        <div className="text-center">
          <div className="mx-auto h-6 w-6 animate-spin rounded-full border-2 border-muted-foreground border-t-transparent" />
          <p className="mt-3 text-sm text-muted-foreground">Loading vault…</p>
        </div>
      </div>
    );
  }

  return <>{children}</>;
};

// ─── App Component ─────────────────────────────────────────────────

export const App: React.FC = () => {
  const appState = useAuthStore((s) => s.appState);
  const initialize = useAuthStore((s) => s.initialize);

  // Initialize auth state on mount
  useEffect(() => {
    initialize();
  }, [initialize]);

  // Enable auto-lock and keyboard shortcuts
  useAutoLock();
  useKeyboardShortcuts();

  // Show unlock screen when vault is locked
  if (appState === "locked") {
    return (
      <>
        <UnlockScreen />
        <ToastContainer />
      </>
    );
  }

  // Show error state
  if (appState === "error") {
    return (
      <div className="flex h-screen items-center justify-center bg-background">
        <div className="text-center">
          <p className="text-sm text-destructive">
            Failed to initialize vault. Please restart the application.
          </p>
        </div>
      </div>
    );
  }

  return (
    <>
      <Routes>
        <Route
          element={
            <ProtectedRoute>
              <AppLayout />
            </ProtectedRoute>
          }
        >
          <Route path={ROUTES.VAULT} element={<VaultView />} />
          <Route path={ROUTES.NOTES} element={<NotesView />} />
          <Route path={ROUTES.FILES} element={<FilesView />} />
          <Route path={ROUTES.SCANNER} element={<ScannerView />} />
          <Route path={ROUTES.AUDIT} element={<AuditView />} />
          <Route path={ROUTES.SECURITY_CENTER} element={<SecurityCenterView />} />
          <Route path={ROUTES.SETTINGS} element={<SettingsView />} />
        </Route>
        <Route path="*" element={<Navigate to={ROUTES.VAULT} replace />} />
      </Routes>
      <ToastContainer />
    </>
  );
};
