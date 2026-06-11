/**
 * Threat Scanner view.
 *
 * Provides password strength analysis, breach checking,
 * and comprehensive vulnerability scanning. All analysis
 * is performed by the Rust backend.
 */

import React, { useState, useCallback } from "react";
import {
  ScanSearch,
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
  Loader2,
  Search,
  FileKey2,
} from "lucide-react";
import { useAuthStore } from "@/stores/auth-store";
import { scannerCommands, type PasswordStrengthResult, type ScanResultView } from "@/lib/tauri";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { cn } from "@/lib/utils";

// ─── Password Strength Card ───────────────────────────────────────

const PasswordStrengthCard: React.FC = () => {
  const [password, setPassword] = useState("");
  const [result, setResult] = useState<PasswordStrengthResult | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const analyze = useCallback(async () => {
    if (!password) return;
    setIsAnalyzing(true);
    setError(null);
    try {
      const strength = await scannerCommands.getPasswordStrength(password);
      setResult(strength);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Analysis failed");
    } finally {
      setIsAnalyzing(false);
    }
  }, [password]);

  const scoreColor = (score: number) => {
    if (score >= 4) return "text-green-500";
    if (score >= 3) return "text-yellow-500";
    if (score >= 2) return "text-orange-500";
    return "text-red-500";
  };

  const scoreBg = (score: number) => {
    if (score >= 4) return "bg-green-500/10 border-green-500/20";
    if (score >= 3) return "bg-yellow-500/10 border-yellow-500/20";
    if (score >= 2) return "bg-orange-500/10 border-orange-500/20";
    return "bg-red-500/10 border-red-500/20";
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <FileKey2 className="h-5 w-5 text-muted-foreground" />
          Password Strength Analyzer
        </CardTitle>
        <CardDescription>
          Analyze password strength locally. No data is sent to external services.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          <div className="flex gap-2">
            <div className="relative flex-1">
              <input
                type="password"
                value={password}
                onChange={(e) => {
                  setPassword(e.target.value);
                  setResult(null);
                }}
                placeholder="Enter a password to analyze…"
                className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground placeholder:text-muted-foreground focus:border-ring focus:outline-none focus:ring-1 focus:ring-ring"
                aria-label="Password to analyze"
              />
            </div>
            <Button
              onClick={analyze}
              disabled={!password || isAnalyzing}
              isLoading={isAnalyzing}
            >
              Analyze
            </Button>
          </div>

          {error && (
            <p className="text-sm text-destructive">{error}</p>
          )}

          {result && (
            <div className={cn("rounded-md border p-4", scoreBg(result.score))}>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  {result.score >= 4 ? (
                    <ShieldCheck className={cn("h-5 w-5", scoreColor(result.score))} />
                  ) : result.score >= 2 ? (
                    <ShieldAlert className={cn("h-5 w-5", scoreColor(result.score))} />
                  ) : (
                    <AlertTriangle className={cn("h-5 w-5", scoreColor(result.score))} />
                  )}
                  <span className={cn("text-lg font-semibold", scoreColor(result.score))}>
                    {result.label}
                  </span>
                </div>
                <div className="text-right">
                  <span className={cn("text-2xl font-bold", scoreColor(result.score))}>
                    {result.score}
                  </span>
                  <span className="text-sm text-muted-foreground">/5</span>
                </div>
              </div>

              <div className="mt-2 flex items-center gap-2">
                <span className="text-xs text-muted-foreground">Entropy:</span>
                <span className="text-xs font-medium">
                  {result.entropy_bits.toFixed(1)} bits
                </span>
              </div>

              {/* Strength bar */}
              <div className="mt-3 h-2 w-full rounded-full bg-muted">
                <div
                  className={cn(
                    "h-2 rounded-full transition-all",
                    result.score >= 4
                      ? "bg-green-500"
                      : result.score >= 3
                        ? "bg-yellow-500"
                        : result.score >= 2
                          ? "bg-orange-500"
                          : "bg-red-500",
                  )}
                  style={{ width: `${(result.score / 5) * 100}%` }}
                />
              </div>

              {result.warnings.length > 0 && (
                <div className="mt-3 space-y-1">
                  {result.warnings.map((w, i) => (
                    <p key={i} className="flex items-start gap-1.5 text-xs text-yellow-600 dark:text-yellow-400">
                      <AlertTriangle className="mt-0.5 h-3 w-3 flex-shrink-0" />
                      {w}
                    </p>
                  ))}
                </div>
              )}

              {result.suggestions.length > 0 && (
                <div className="mt-2 space-y-1">
                  {result.suggestions.map((s, i) => (
                    <p key={i} className="text-xs text-muted-foreground">
                      • {s}
                    </p>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
};

// ─── Breach Check Card ────────────────────────────────────────────

const BreachCheckCard: React.FC = () => {
  const [username, setUsername] = useState("");
  const [result, setResult] = useState<ScanResultView | null>(null);
  const [isChecking, setIsChecking] = useState(false);
  const [notFound, setNotFound] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const check = useCallback(async () => {
    if (!username.trim()) return;
    setIsChecking(true);
    setError(null);
    setNotFound(false);
    setResult(null);
    try {
      const breach = await scannerCommands.checkBreach(username.trim());
      if (breach) {
        setResult(breach);
      } else {
        setNotFound(true);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Breach check failed");
    } finally {
      setIsChecking(false);
    }
  }, [username]);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Search className="h-5 w-5 text-muted-foreground" />
          Breach Database Check
        </CardTitle>
        <CardDescription>
          Check if a username has appeared in known data breaches.
          All checks are performed against a local database.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          <div className="flex gap-2">
            <input
              type="text"
              value={username}
              onChange={(e) => {
                setUsername(e.target.value);
                setResult(null);
                setNotFound(false);
              }}
              placeholder="Enter username to check…"
              className="h-9 flex-1 rounded-md border border-input bg-background px-3 text-sm text-foreground placeholder:text-muted-foreground focus:border-ring focus:outline-none focus:ring-1 focus:ring-ring"
              aria-label="Username to check"
            />
            <Button
              onClick={check}
              disabled={!username.trim() || isChecking}
              isLoading={isChecking}
            >
              Check
            </Button>
          </div>

          {error && <p className="text-sm text-destructive">{error}</p>}

          {notFound && (
            <div className="flex items-center gap-2 rounded-md border border-green-500/20 bg-green-500/5 p-3">
              <CheckCircle2 className="h-4 w-4 text-green-500" />
              <span className="text-sm text-green-600 dark:text-green-400">
                No breaches found for &ldquo;{username}&rdquo;. This username appears to be safe.
              </span>
            </div>
          )}

          {result && (
            <div className="rounded-md border border-red-500/20 bg-red-500/5 p-4">
              <div className="flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-red-500" />
                <span className="font-medium text-red-600 dark:text-red-400">
                  Breach Detected
                </span>
                <span className={cn(
                  "ml-auto rounded-full px-2 py-0.5 text-xs font-medium",
                  result.threat_level === "critical"
                    ? "bg-red-500/10 text-red-500"
                    : result.threat_level === "high"
                      ? "bg-orange-500/10 text-orange-500"
                      : "bg-yellow-500/10 text-yellow-500",
                )}>
                  {result.threat_level}
                </span>
              </div>
              <p className="mt-2 text-sm text-foreground">{result.description}</p>
              {result.recommendation && (
                <p className="mt-1 text-xs text-muted-foreground">
                  Recommendation: {result.recommendation}
                </p>
              )}
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
};

// ─── Full Scan Card ───────────────────────────────────────────────

const FullScanCard: React.FC = () => {
  const [results, setResults] = useState<ScanResultView[]>([]);
  const [isScanning, setIsScanning] = useState(false);
  const [hasScanned, setHasScanned] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const appState = useAuthStore((s) => s.appState);

  const runScan = useCallback(async () => {
    setIsScanning(true);
    setError(null);
    setResults([]);
    try {
      const scanResults = await scannerCommands.runFullScan();
      setResults(scanResults);
      setHasScanned(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Scan failed");
    } finally {
      setIsScanning(false);
    }
  }, []);

  const threatLevelColor = (level: string) => {
    switch (level) {
      case "critical":
        return "text-red-500 border-red-500/20 bg-red-500/5";
      case "high":
        return "text-orange-500 border-orange-500/20 bg-orange-500/5";
      case "medium":
        return "text-yellow-500 border-yellow-500/20 bg-yellow-500/5";
      case "low":
        return "text-blue-500 border-blue-500/20 bg-blue-500/5";
      default:
        return "text-muted-foreground border-border bg-muted/5";
    }
  };

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="flex items-center gap-2">
              <ScanSearch className="h-5 w-5 text-muted-foreground" />
              Full Vulnerability Scan
            </CardTitle>
            <CardDescription className="mt-1">
              Scan all vault entries for weak passwords, reuse, and vulnerabilities.
            </CardDescription>
          </div>
          <Button
            onClick={runScan}
            disabled={isScanning || appState !== "unlocked"}
            isLoading={isScanning}
          >
            {isScanning ? "Scanning…" : "Run Full Scan"}
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        {error && <p className="text-sm text-destructive">{error}</p>}

        {isScanning && (
          <div className="flex flex-col items-center gap-3 py-8">
            <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
            <p className="text-sm text-muted-foreground">
              Scanning vault entries for vulnerabilities…
            </p>
          </div>
        )}

        {!isScanning && hasScanned && results.length === 0 && (
          <div className="flex flex-col items-center gap-2 py-8">
            <ShieldCheck className="h-8 w-8 text-green-500" />
            <p className="text-sm text-green-600 dark:text-green-400">
              No vulnerabilities found. Your vault looks secure!
            </p>
          </div>
        )}

        {!isScanning && hasScanned && results.length > 0 && (
          <div className="space-y-3">
            <p className="text-sm text-muted-foreground">
              Found {results.length} {results.length === 1 ? "issue" : "issues"}:
            </p>
            {results.map((r) => (
              <div
                key={r.id}
                className={cn("rounded-md border p-3", threatLevelColor(r.threat_level))}
              >
                <div className="flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4" />
                  <span className="font-medium text-sm">{r.description}</span>
                  <span className="ml-auto rounded-full bg-muted/50 px-2 py-0.5 text-xs font-medium capitalize">
                    {r.threat_level}
                  </span>
                </div>
                {r.recommendation && (
                  <p className="mt-1.5 pl-6 text-xs text-muted-foreground">
                    {r.recommendation}
                  </p>
                )}
              </div>
            ))}
          </div>
        )}

        {!isScanning && !hasScanned && (
          <div className="flex flex-col items-center gap-2 py-8">
            <Shield className="h-8 w-8 text-muted-foreground/30" />
            <p className="text-sm text-muted-foreground">
              Run a scan to check for vulnerabilities
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  );
};

// ─── Main ScannerView ─────────────────────────────────────────────

export const ScannerView: React.FC = () => {
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold text-foreground">Threat Scanner</h2>
        <p className="text-sm text-muted-foreground">
          Scan for vulnerabilities and compromised credentials
        </p>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <PasswordStrengthCard />
        <BreachCheckCard />
      </div>

      <FullScanCard />
    </div>
  );
};
