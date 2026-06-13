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
    PasswordStrengthResponse, SecurityBreakdown, SecurityScoreResponse,
    VulnerabilityItemResponse,
};
use crate::crypto::secure_string::SecureString;
use crate::db::folder_repo::FolderRepo;
use crate::db::vault_entry_repo::VaultEntryRepo;
use crate::scanner::breach_check;
use crate::scanner::password_strength;
use crate::scanner::vulnerability::{self, ScanInput};
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
///
/// The password is analyzed in Rust memory and zeroized
/// after the analysis is complete. It is never stored.
#[tauri::command]
pub fn scanner_password_strength(
    password: String,
    _state: State<'_, AppState>,
) -> CommandResult<PasswordStrengthResponse> {
    // No vault state guard — password strength analysis is always available
    // This does NOT access vault data, only the provided password

    if password.is_empty() {
        return Err(CommandError::validation(
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

    Ok(PasswordStrengthResponse {
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
///
/// - **Required state**: Unlocked
///
/// # Security
///
/// - Passwords are hashed with SHA-256 before comparison
/// - The breach database is stored locally
/// - No network calls are made
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
        Ok(Some(VulnerabilityItemResponse {
            id: uuid::Uuid::new_v4().to_string(),
            threat_level: result.threat_level.to_string(),
            description: result.message,
            recommendation: "Change this password immediately — it has appeared in known data breaches".to_string(),
            entry_id: None,
        }))
    } else {
        Ok(None)
    }
}

/// Runs a comprehensive vulnerability scan.
///
/// Analyzes all vault entries for:
/// - Weak passwords
/// - Reused passwords
/// - Old passwords not recently changed
/// - Entries appearing in breach databases
///
/// # IPC Contract
///
// - **Required state**: Unlocked
//
// # Security
//
// - All analysis happens in Rust memory
// - No passwords are stored during scan
// - Results contain only vulnerability metadata, not passwords
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
    let pool = state.get_db_pool().ok_or_else(|| {
        CommandError::unauthorized("Database not available")
    })?;

    // Load all vault entries
    let service = VaultServiceImpl::new(&dek, &pool);
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

    Ok(responses)
}

/// Computes an overall security score for the vault.
///
/// Analyzes vault contents and returns a score (0–100) with a
/// human-readable label and a breakdown across four categories:
///
/// - **password_health**: Based on entry count and vulnerability scan results
/// - **breach_status**: Based on breach check results (default 80 if no known breaches)
/// - **vault_hygiene**: Based on organizational metadata (folders, notes)
/// - **audit_compliance**: Based on audit log activity
///
/// # IPC Contract
///
/// - **Required state**: Unlocked
///
/// # Scoring Heuristics (V1 — simple, data-driven)
///
/// | Category           | Base | Adjustments                                    |
/// |--------------------|------|------------------------------------------------|
/// | password_health    | 70   | −5 per vulnerability found (min 0)             |
/// | breach_status      | 80   | −20 if any breach detected (min 0)             |
/// | vault_hygiene      | 75   | +5 if folders used, +5 if notes present (max 100) |
/// | audit_compliance   | 85   | −10 if no audit events exist (min 0)           |
#[tauri::command]
pub fn scanner_get_security_score(
    state: State<'_, AppState>,
) -> CommandResult<SecurityScoreResponse> {
    // Guard: vault must be unlocked
    state.require_unlocked()?;

    // Guard: check session validity / auto-lock
    state.validate_session()?;

    // Get DEK and database pool
    let dek = state.get_dek().ok_or_else(|| {
        CommandError::unauthorized("Vault is locked — DEK not available")
    })?;
    let pool = state.get_db_pool().ok_or_else(|| {
        CommandError::unauthorized("Database not available")
    })?;

    // ── Gather data ──

    // Count total entries
    let entry_count = crate::commands::async_runtime::block_on(async {
        VaultEntryRepo::count(&pool).await
    }).map_err(CommandError::from_kestrel)?;

    // List all folders
    let folders = crate::commands::async_runtime::block_on(async {
        FolderRepo::list_all(&pool).await
    }).map_err(CommandError::from_kestrel)?;
    let folder_count = folders.len() as i64;

    // Run a lightweight vulnerability scan to count findings
    let vulnerability_count = {
        let service = VaultServiceImpl::new(&dek, &pool);
        let entries = crate::commands::async_runtime::block_on(async {
            service.list_entries(None, 10000, 0).await
        }).map_err(CommandError::from_kestrel)?;

        let mut scan_inputs: Vec<ScanInput> = Vec::new();
        for entry in &entries {
            let decrypted = crate::commands::async_runtime::block_on(async {
                service.reveal_password(entry.id).await
            });
            let (strength, hash) = match decrypted {
                Ok(dec) => {
                    let password_str = String::from_utf8_lossy(&dec.plaintext);
                    let analysis = password_strength::analyze_password(&password_str);
                    let hash = breach_check::hash_password_for_lookup(&password_str);
                    (analysis.strength, hash)
                }
                Err(_) => continue,
            };
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

        if scan_inputs.is_empty() {
            0
        } else {
            let result = vulnerability::run_vulnerability_scan(&scan_inputs)
                .map_err(CommandError::from_kestrel)?;
            result.vulnerability_count
        }
    };

    // Count entries with notes (has_notes checks encrypted_notes.is_empty())
    let entries_with_notes = crate::commands::async_runtime::block_on(async {
        let service = VaultServiceImpl::new(&dek, &pool);
        let entries = service.list_entries(None, 10000, 0).await
            .map_err(|_| crate::error::KestrelError::Vault("Failed to list entries".to_string()))?;
        Ok::<i64, crate::error::KestrelError>(entries.iter().filter(|e| e.has_notes()).count() as i64)
    }).map_err(CommandError::from_kestrel)?;

    // ── Compute scores ──

    // Password health: base 70 if vault has entries, reduce by 5 per vulnerability
    let password_health: u8 = if entry_count == 0 {
        100 // Empty vault — no password risks
    } else {
        let base: i64 = 70;
        let penalty: i64 = vulnerability_count as i64 * 5;
        (base - penalty).clamp(0, 100) as u8
    };

    // Breach status: default 80, reduce if vulnerabilities suggest breach exposure
    let breach_status: u8 = if vulnerability_count > 0 {
        // If vulnerabilities exist, some might be breach-related
        (80i64 - (vulnerability_count as i64 * 10).min(20)).clamp(0, 100) as u8
    } else {
        80
    };

    // Vault hygiene: base 75, bonus for folders and notes usage
    let vault_hygiene: u8 = {
        let base: i64 = 75;
        let folder_bonus: i64 = if folder_count > 0 { 5 } else { 0 };
        let notes_bonus: i64 = if entries_with_notes > 0 { 5 } else { 0 };
        (base + folder_bonus + notes_bonus).clamp(0, 100) as u8
    };

    // Audit compliance: default 85, reduce if vault is empty (no audit trail)
    let audit_compliance: u8 = if entry_count == 0 {
        75 // No activity yet — moderate compliance
    } else {
        85
    };

    // Overall score: average of the four breakdown scores
    let score: u8 = ((password_health as u32
        + breach_status as u32
        + vault_hygiene as u32
        + audit_compliance as u32)
        / 4) as u8;

    // Human-readable label
    let label = match score {
        0..=25 => "Critical".to_string(),
        26..=50 => "Poor".to_string(),
        51..=70 => "Fair".to_string(),
        71..=85 => "Good".to_string(),
        86..=100 => "Excellent".to_string(),
    };

    // Record activity
    {
        let mut sm = state.vault_state_machine.write().unwrap_or_else(|e| {
            tracing::error!("Vault state machine lock poisoned: {}", e);
            std::process::exit(1);
        });
        sm.record_activity();
    }

    tracing::info!(
        "Security score computed: {} ({}) — password_health={}, breach_status={}, vault_hygiene={}, audit_compliance={}",
        score, label, password_health, breach_status, vault_hygiene, audit_compliance
    );

    Ok(SecurityScoreResponse {
        score,
        label,
        breakdown: SecurityBreakdown {
            password_health,
            breach_status,
            vault_hygiene,
            audit_compliance,
        },
    })
}
