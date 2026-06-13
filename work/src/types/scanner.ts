/**
 * Scanner types for the threat scanner system.
 *
 * All scanning and security analysis is performed by the Rust backend.
 * React only displays the results.
 */

// ─── Threat Levels ─────────────────────────────────────────────────

export type ThreatLevel = "none" | "low" | "medium" | "high" | "critical";

// ─── Password Strength ─────────────────────────────────────────────

export type StrengthScore = 0 | 1 | 2 | 3 | 4;

export interface PasswordStrength {
  score: StrengthScore;
  label: string;
  feedback: string[];
  /** Estimated crack time — calculated in Rust */
  crack_time: string;
}

// ─── Scan Results ──────────────────────────────────────────────────

export interface ScanResult {
  id: string;
  threat_level: ThreatLevel;
  description: string;
  recommendation: string;
  /** ISO timestamp */
  scanned_at: string;
  affected_entry_ids: string[];
}

// ─── Vulnerability ─────────────────────────────────────────────────

export interface VulnerabilityItem {
  entry_id: string;
  entry_title: string;
  threat_level: ThreatLevel;
  issue: string;
  recommendation: string;
}

export interface VulnerabilityReport {
  id: string;
  scanned_at: string;
  total_entries: number;
  vulnerable_count: number;
  items: VulnerabilityItem[];
  summary: Record<ThreatLevel, number>;
}

// ─── Breach Check ──────────────────────────────────────────────────

export interface BreachCheckResult {
  email: string;
  breached: boolean;
  breach_count: number;
  /** Names of breaches — never full breach data */
  breach_names: string[];
  checked_at: string;
}
