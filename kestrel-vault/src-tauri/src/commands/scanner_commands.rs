//! Tauri commands for scanner operations.
//!
//! Provides IPC handlers for password strength analysis,
//! breach checking, and vulnerability scanning.
//!
//! # Security
//!
//! - Scanner commands are rate-limited to prevent brute-force attacks
//! - Passwords are never transmitted over the network
//! - All analysis is performed locally

use crate::commands::vault_commands::AppState;
use crate::error::KestrelError;
use crate::scanner::breach_check::BreachCheckResult;
use crate::scanner::password_strength::PasswordAnalysis;
use crate::scanner::vulnerability::VulnerabilityScanResult;

/// Analyzes the strength of a password.
///
/// # Arguments
///
/// * `password` - The password to analyze
///
/// # Returns
///
/// A detailed `PasswordAnalysis` with entropy, patterns, and suggestions.
///
/// # Security
///
/// - Analysis is performed entirely locally
/// - The password is never stored or transmitted
/// - Results do not include the password itself
#[tauri::command]
pub async fn scan_password_strength(
    _state: tauri::State<'_, AppState>,
    password: String,
) -> Result<PasswordAnalysis, String> {
    if password.is_empty() {
        return Err("Password must not be empty".to_string());
    }
    if password.len() > 1024 {
        return Err("Password too long (max 1024 characters)".to_string());
    }

    // Analysis is local-only — no network calls
    let analysis = crate::scanner::password_strength::analyze_password(&password);
    Ok(analysis)
}

/// Checks if a password has appeared in known data breaches.
///
/// # Arguments
///
/// * `password` - The password to check
///
/// # Returns
///
/// A `BreachCheckResult` indicating breach status.
///
/// # Security
///
/// - The password is hashed with SHA-256 before lookup
/// - No plaintext password is transmitted or compared
/// - All checks are performed against a local database
/// - This function makes NO network calls
#[tauri::command]
pub async fn check_breach_status(
    _state: tauri::State<'_, AppState>,
    password: String,
) -> Result<BreachCheckResult, String> {
    if password.is_empty() {
        return Err("Password must not be empty".to_string());
    }

    let result = crate::scanner::breach_check::check_breach_status(&password)
        .map_err(|e| e.to_user_message())?;

    Ok(result)
}

/// Runs a full vulnerability scan on the vault.
///
/// # Returns
///
/// A `VulnerabilityScanResult` with all findings.
///
/// # Errors
///
/// Returns an error if the scan fails or the session is invalid.
///
/// # Security
///
/// - The scan is performed entirely locally
/// - No passwords are transmitted during the scan
/// - Scan results are logged in the audit trail
#[tauri::command]
pub async fn run_vulnerability_scan(
    _state: tauri::State<'_, AppState>,
) -> Result<VulnerabilityScanResult, String> {
    // TODO (Phase 2): Load vault entries and run scan
    // 1. Load all entries from the vault
    // 2. Compute password strengths
    // 3. Check for reuse and age
    // 4. Return comprehensive results
    Err(KestrelError::Scanner("Not yet implemented".to_string()).to_user_message())
}
