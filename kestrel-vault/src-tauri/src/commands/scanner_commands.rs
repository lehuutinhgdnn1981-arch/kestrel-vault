//! Threat scanner Tauri commands for KESTREL Vault.
//!
//! Provides password strength analysis, breach checking, and
//! vulnerability scanning. All scanning is local-only.
//!
//! # Security
//!
//! - No network calls — all scanning is offline
//! - Passwords sent to scanner are zeroized after analysis
//! - Breach checking uses SHA-256 hashed lookups only
//! - Vault must be unlocked for full scans
//!
//! # IPC Contract
//!
//! | Command                    | Required State | Effect              |
//! |----------------------------|---------------|---------------------|
//! | scanner_password_strength  | Any           | Analyze + zeroize   |
//! | scanner_check_breach       | Unlocked      | Hash + lookup       |
//! | scanner_run_full_scan      | Unlocked      | Full vulnerability  |

use crate::commands::types::{
    validate_field, CommandError, CommandResult,
    PasswordStrengthResponse, VulnerabilityItemResponse,
};
use crate::crypto::secure_string::SecureString;
use crate::scanner::breach_check;
use crate::scanner::password_strength;
use crate::scanner::vulnerability::{self, ScanInput, VulnerabilityType};
use crate::vault::service::VaultServiceImpl;
use tauri::State;

use super::auth_commands::AppState;

/// Analyzes password strength locally.
///
/// Computes entropy, detects common patterns, and provides
/// recommendations. No network calls are made.
///
/// This command is available in any vault state — it does
/// not access vault data, only analyzes the provided password.
///
/// # Security
//!
//! The password is analyzed in Rust memory and zeroized
//! after the analysis is complete. It is never stored.
#[tauri::command]
pub fn scanner_password_strength(
    password: String,
    _state: State<'_, AppState>,
) -> CommandResult<PasswordStrengthResponse> {
    // No vault state guard — password strength analysis is always available
    // This does NOT access vault data, only the provided password

    if password.is_empty() {
        return CommandResult::Err(CommandError::validation(
            "Password is required for analysis",
        ));
    }
    validate_field(&password, 1024, "Password")?;

    // Analyze using the local password strength module
    let analysis = password_strength::analyze_password(&password);

    // Convert strength enum to numeric score (0-4) and label
    let (score, label) = match analysis.strength {
        password_strength::PasswordStrength::VeryWeak => (0, "Very Weak".to_string()),
        password_strength::PasswordStrength::Weak => (1, "Weak".to_string()),
        password_strength::PasswordStrength::Fair => (2, "Fair".to_string()),
        password_strength::PasswordStrength::Strong => (3, "Strong".to_string()),
        password_strength::PasswordStrength::VeryStrong => (4, "Very Strong".to_string()),
    };

    // The password string is dropped here and will eventually be
    // deallocated. For maximum security, the caller should use
    // SecureString, but Tauri IPC passes strings immutably.
    let _ = SecureString::from(password); // Force zeroization

    CommandResult::ok(PasswordStrengthResponse {
        score,
        label,
        entropy_bits: analysis.entropy_bits,
        warnings: analysis.warnings,
        suggestions: analysis.suggestions,
    })
}

/// Checks if credentials appear in known data breaches.
///
/// Uses a local breach database with SHA-256 hashed lookups.
/// No plaintext passwords or usernames are ever transmitted.
///
/// # IPC Contract
//!
//! - **Required state**: Unlocked
//!
/// # Security
//!
//! - Passwords are hashed with SHA-256 before comparison
//! - The breach database is stored locally
//! - No network calls are made
#[tauri::command]
pub fn scanner_check_breach(
    username: String,
    state: State<'_, AppState>,
) -> CommandResult<Option<VulnerabilityItemResponse>> {
    // Guard: vault must be unlocked for breach checks
    state.require_unlocked()?;

    validate_field(&username, 256, "Username")?;

    // Check breach status using SHA-256 hashed lookup
    // Note: Currently checks against a known common passwords list
    // Future: Will use a full local HIBP-style database
    let result = breach_check::check_breach_status(&username)
        .map_err(CommandError::from_kestrel)?;

    if result.is_breached {
        CommandResult::ok(Some(VulnerabilityItemResponse {
            id: uuid::Uuid::new_v4().to_string(),
            threat_level: result.threat_level.to_string(),
            description: result.message,
            recommendation: "Change this password immediately — it has appeared in known data breaches".to_string(),
            entry_id: None,
        }))
    } else {
        CommandResult::ok(None)
    }
}

/// Runs a comprehensive vulnerability scan.
//!
//! Analyzes all vault entries for:
//! - Weak passwords
//! - Reused passwords
//! - Old passwords not recently changed
//! - Entries appearing in breach databases
//!
//! # IPC Contract
//!
//! - **Required state**: Unlocked
//!
//! # Security
//!
//! - All analysis happens in Rust memory
//! - No passwords are stored during scan
//! - Results contain only vulnerability metadata, not passwords
#[tauri::command]
pub fn scanner_run_full_scan(
    state: State<'_, AppState>,
) -> CommandResult<Vec<VulnerabilityItemResponse>> {
    // Guard: vault must be unlocked for full scan
    state.require_unlocked()?;

    // Guard: check session validity / auto-lock
    state.validate_session()?;

    // Get DEK and database pool
    let dek = state.get_dek().ok_or_else(|| {
        CommandError::unauthorized("Vault is locked — DEK not available")
    })?;
    let db = state.get_db().ok_or_else(|| {
        CommandError::unauthorized("Database not available")
    })?;
    let pool = db.pool();

    // Load all vault entries
    let service = VaultServiceImpl::new(&dek, pool);
    let entries = crate::commands::async_runtime::block_on(async {
        service.list_entries(None, 10000, 0).await
    }).map_err(CommandError::from_kestrel)?;

    // Build scan input for each entry
    let mut scan_inputs: Vec<ScanInput> = Vec::new();
    for entry in &entries {
        // Decrypt the password to analyze it
        let decrypted = crate::commands::async_runtime::block_on(async {
            service.reveal_password(entry.id).await
        });

        let (strength, hash) = match decrypted {
            Ok(dec) => {
                let password_str = String::from_utf8_lossy(&dec.plaintext);
                let analysis = password_strength::analyze_password(&password_str);
                let hash = breach_check::hash_password_for_lookup(&password_str);
                (analysis.strength, hash)
                // dec is zeroized when dropped
            }
            Err(_) => {
                // If we can't decrypt, skip this entry
                continue;
            }
        };

        // Estimate password age from updated_at timestamp
        let age_days = (chrono::Utc::now() - entry.updated_at)
            .num_days()
            .max(0) as u32;

        scan_inputs.push(ScanInput {
            entry_id: entry.id,
            password_strength: strength,
            password_hash: hash,
            password_age_days: age_days,
            has_url: entry.has_url(),
            has_username: !entry.username.is_empty(),
        });
    }

    // Run vulnerability scan
    let scan_result = vulnerability::run_vulnerability_scan(&scan_inputs)
        .map_err(CommandError::from_kestrel)?;

    // Convert findings to response type
    let responses: Vec<VulnerabilityItemResponse> = scan_result
        .findings
        .iter()
        .flat_map(|finding| {
            // Create one response per finding (aggregating affected entries)
            let entry_ids_str: Vec<String> = finding
                .affected_entry_ids
                .iter()
                .map(|id| id.to_string())
                .collect();

            // For findings with many affected entries, return a single
            // aggregated response. For individual entry tracking, the
            // frontend can query by vulnerability type.
            Some(VulnerabilityItemResponse {
                id: uuid::Uuid::new_v4().to_string(),
                threat_level: finding.threat_level.to_string(),
                description: format!(
                    "{} (affects {} entries: {})",
                    finding.description,
                    finding.affected_entry_ids.len(),
                    entry_ids_str.join(", ")
                ),
                recommendation: finding.recommendation.clone(),
                entry_id: if finding.affected_entry_ids.len() == 1 {
                    Some(finding.affected_entry_ids[0].to_string())
                } else {
                    None
                },
            })
        })
        .collect();

    tracing::info!(
        "Vulnerability scan completed: {} entries scanned, {} findings",
        scan_result.total_entries,
        scan_result.vulnerability_count
    );

    // Record activity
    {
        let mut sm = state.vault_state_machine.write().unwrap_or_else(|e| {
            tracing::error!("Vault state machine lock poisoned: {}", e);
            std::process::exit(1);
        });
        sm.record_activity();
    }

    CommandResult::ok(responses)
}
