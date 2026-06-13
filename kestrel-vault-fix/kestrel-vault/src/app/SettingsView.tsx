/**
 * Settings view.
 *
 * Provides configuration for auto-lock, appearance, security,
 * and vault maintenance. All settings changes go through the
 * Rust backend via settingsCommands.
 */

import React, { useEffect, useState, useCallback } from "react";
import {
  Settings,
  Palette,
  Clock,
  Globe,
  Shield,
  Moon,
  Sun,
  Monitor,
  Save,
  RotateCcw,
  Lock,
  Clipboard,
  Loader2,
} from "lucide-react";
import { settingsCommands, type AppSettings } from "@/lib/tauri";
import { authCommands } from "@/lib/tauri";
import { useAuthStore } from "@/stores/auth-store";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";

// ─── Theme toggle ─────────────────────────────────────────────────

const THEME_OPTIONS = [
  { value: "dark", label: "Dark", icon: Moon },
  { value: "light", label: "Light", icon: Sun },
  { value: "system", label: "System", icon: Monitor },
] as const;

const LANGUAGE_OPTIONS = [
  { value: "en", label: "English" },
  { value: "vi", label: "Tiếng Việt" },
] as const;

const AUTO_LOCK_OPTIONS = [
  { value: 1, label: "1 minute" },
  { value: 5, label: "5 minutes" },
  { value: 10, label: "10 minutes" },
  { value: 15, label: "15 minutes" },
  { value: 30, label: "30 minutes" },
  { value: 60, label: "1 hour" },
  { value: 0, label: "Never (not recommended)" },
] as const;

const CLIPBOARD_OPTIONS = [
  { value: 10, label: "10 seconds" },
  { value: 30, label: "30 seconds" },
  { value: 60, label: "60 seconds" },
  { value: 120, label: "2 minutes" },
] as const;

// ─── Main SettingsView ────────────────────────────────────────────

export const SettingsView: React.FC = () => {
  const appState = useAuthStore((s) => s.appState);
  const lock = useAuthStore((s) => s.lock);

  const [settings, setSettings] = useState<AppSettings | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [hasChanges, setHasChanges] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  // Local editing state
  const [autoLockMinutes, setAutoLockMinutes] = useState(5);
  const [theme, setTheme] = useState("dark");
  const [language, setLanguage] = useState("en");
  const [clearClipboardSeconds, setClearClipboardSeconds] = useState(30);

  // Load settings
  useEffect(() => {
    const loadSettings = async () => {
      setIsLoading(true);
      try {
        const s = await settingsCommands.getSettings();
        setSettings(s);
        setAutoLockMinutes(s.auto_lock_minutes);
        setTheme(s.theme);
        setLanguage(s.language);
        setClearClipboardSeconds(s.clear_clipboard_seconds);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load settings");
      } finally {
        setIsLoading(false);
      }
    };
    loadSettings();
  }, []);

  // Track changes
  useEffect(() => {
    if (!settings) return;
    const changed =
      autoLockMinutes !== settings.auto_lock_minutes ||
      theme !== settings.theme ||
      language !== settings.language ||
      clearClipboardSeconds !== settings.clear_clipboard_seconds;
    setHasChanges(changed);
  }, [settings, autoLockMinutes, theme, language, clearClipboardSeconds]);

  const saveSettings = useCallback(async () => {
    setIsSaving(true);
    setError(null);
    setSuccessMessage(null);
    try {
      const updated = await settingsCommands.updateSettings({
        auto_lock_minutes: autoLockMinutes,
        theme,
        language,
        clear_clipboard_seconds: clearClipboardSeconds,
      });
      setSettings(updated);
      setHasChanges(false);
      setSuccessMessage("Settings saved successfully");
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save settings");
    } finally {
      setIsSaving(false);
    }
  }, [autoLockMinutes, theme, language, clearClipboardSeconds]);

  const resetToDefaults = useCallback(() => {
    setAutoLockMinutes(5);
    setTheme("dark");
    setLanguage("en");
    setClearClipboardSeconds(30);
  }, []);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-16">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-foreground">Settings</h2>
          <p className="text-sm text-muted-foreground">
            Configure your vault preferences
          </p>
        </div>
        <div className="flex items-center gap-2">
          {hasChanges && (
            <Button variant="outline" size="sm" onClick={resetToDefaults}>
              <RotateCcw className="mr-1 h-3.5 w-3.5" />
              Reset
            </Button>
          )}
          <Button
            size="sm"
            onClick={saveSettings}
            disabled={!hasChanges || isSaving}
            isLoading={isSaving}
          >
            <Save className="mr-1 h-3.5 w-3.5" />
            Save Changes
          </Button>
        </div>
      </div>

      {/* Status messages */}
      {error && (
        <div className="rounded-md border border-red-500/20 bg-red-500/5 px-3 py-2 text-sm text-red-600 dark:text-red-400">
          {error}
        </div>
      )}
      {successMessage && (
        <div className="rounded-md border border-green-500/20 bg-green-500/5 px-3 py-2 text-sm text-green-600 dark:text-green-400">
          {successMessage}
        </div>
      )}

      {/* Auto-Lock Settings */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-sm">
            <Clock className="h-4 w-4 text-muted-foreground" />
            Auto-Lock
          </CardTitle>
          <CardDescription>
            Configure inactivity timeout before vault locks automatically
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 md:grid-cols-4">
            {AUTO_LOCK_OPTIONS.map((opt) => (
              <button
                key={opt.value}
                type="button"
                onClick={() => setAutoLockMinutes(opt.value)}
                className={`rounded-md border px-3 py-2 text-xs font-medium transition-colors ${
                  autoLockMinutes === opt.value
                    ? "border-primary bg-primary/10 text-primary"
                    : "border-border bg-muted/30 text-muted-foreground hover:bg-muted/50"
                }`}
              >
                {opt.label}
              </button>
            ))}
          </div>
          {autoLockMinutes === 0 && (
            <p className="mt-2 flex items-center gap-1.5 text-xs text-yellow-600 dark:text-yellow-400">
              <Shield className="h-3 w-3" />
              Disabling auto-lock reduces security. Your vault stays unlocked until you manually lock it.
            </p>
          )}
        </CardContent>
      </Card>

      {/* Appearance */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-sm">
            <Palette className="h-4 w-4 text-muted-foreground" />
            Appearance
          </CardTitle>
          <CardDescription>
            Theme and display preferences
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex gap-3">
            {THEME_OPTIONS.map((opt) => {
              const Icon = opt.icon;
              return (
                <button
                  key={opt.value}
                  type="button"
                  onClick={() => setTheme(opt.value)}
                  className={`flex flex-col items-center gap-2 rounded-md border px-4 py-3 transition-colors ${
                    theme === opt.value
                      ? "border-primary bg-primary/10 text-primary"
                      : "border-border bg-muted/30 text-muted-foreground hover:bg-muted/50"
                  }`}
                >
                  <Icon className="h-5 w-5" />
                  <span className="text-xs font-medium">{opt.label}</span>
                </button>
              );
            })}
          </div>
        </CardContent>
      </Card>

      {/* Language */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-sm">
            <Globe className="h-4 w-4 text-muted-foreground" />
            Language
          </CardTitle>
          <CardDescription>
            Interface language selection
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex gap-2">
            {LANGUAGE_OPTIONS.map((opt) => (
              <button
                key={opt.value}
                type="button"
                onClick={() => setLanguage(opt.value)}
                className={`rounded-md border px-4 py-2 text-sm font-medium transition-colors ${
                  language === opt.value
                    ? "border-primary bg-primary/10 text-primary"
                    : "border-border bg-muted/30 text-muted-foreground hover:bg-muted/50"
                }`}
              >
                {opt.label}
              </button>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Security */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-sm">
            <Shield className="h-4 w-4 text-muted-foreground" />
            Security
          </CardTitle>
          <CardDescription>
            Clipboard clear timeout, session management, vault maintenance
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Clipboard clear timeout */}
          <div>
            <label className="mb-2 block text-xs font-medium text-muted-foreground">
              <Clipboard className="mr-1 inline h-3 w-3" />
              Clipboard auto-clear timeout
            </label>
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              {CLIPBOARD_OPTIONS.map((opt) => (
                <button
                  key={opt.value}
                  type="button"
                  onClick={() => setClearClipboardSeconds(opt.value)}
                  className={`rounded-md border px-3 py-2 text-xs font-medium transition-colors ${
                    clearClipboardSeconds === opt.value
                      ? "border-primary bg-primary/10 text-primary"
                      : "border-border bg-muted/30 text-muted-foreground hover:bg-muted/50"
                  }`}
                >
                  {opt.label}
                </button>
              ))}
            </div>
          </div>

          {/* Manual lock */}
          <div className="flex items-center justify-between rounded-md border border-border bg-muted/20 px-4 py-3">
            <div>
              <p className="text-sm font-medium">Lock Vault Now</p>
              <p className="text-xs text-muted-foreground">
                Immediately lock the vault and zeroize all keys
              </p>
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={lock}
              disabled={appState !== "unlocked"}
            >
              <Lock className="mr-1 h-3.5 w-3.5" />
              Lock
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Version info */}
      <div className="border-t border-border pt-4">
        <div className="flex items-center gap-2">
          <Settings className="h-3.5 w-3.5 text-muted-foreground" />
          <p className="text-xs text-muted-foreground">
            KESTREL Vault v0.1.0 · All cryptographic operations are handled by the Rust backend
          </p>
        </div>
      </div>
    </div>
  );
};
