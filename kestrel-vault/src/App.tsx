import React, { useEffect } from "react";
import { Routes, Route, Navigate } from "react-router-dom";
import { useAuthStore } from "@/stores/auth-store";
import { useAutoLock } from "@/hooks/use-auto-lock";
import { useKeyboardShortcuts } from "@/hooks/use-keyboard-shortcut";
import Layout from "@/pages/Layout";
import UnlockScreen from "@/pages/UnlockScreen";
import Dashboard from "@/pages/Dashboard";
import PasswordVault from "@/pages/PasswordVault";
import FileVault from "@/pages/FileVault";
import SecureNotes from "@/pages/SecureNotes";
import SecurityCenter from "@/pages/SecurityCenter";
import ThreatScanner from "@/pages/ThreatScanner";
import AuditLogs from "@/pages/AuditLogs";
import Settings from "@/pages/Settings";

export const App: React.FC = () => {
  const appState = useAuthStore((s) => s.appState);
  const initialize = useAuthStore((s) => s.initialize);

  useEffect(() => {
    initialize();
  }, [initialize]);

  useAutoLock();
  useKeyboardShortcuts();

  if (appState === "locked" || appState === "initializing") {
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
    return <UnlockScreen />;
  }

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
    <Layout>
      <Routes>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/vault" element={<PasswordVault />} />
        <Route path="/files" element={<FileVault />} />
        <Route path="/notes" element={<SecureNotes />} />
        <Route path="/security" element={<SecurityCenter />} />
        <Route path="/scanner" element={<ThreatScanner />} />
        <Route path="/audit" element={<AuditLogs />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </Layout>
  );
};
