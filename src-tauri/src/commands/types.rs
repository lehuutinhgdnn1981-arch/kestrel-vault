//! Shared types for Tauri command interfaces.
//!
//! Defines request/response types, validation rules, and error
//! mapping for the IPC boundary between React and Rust.
//!
//! # Security Principles
//!
//! - Passwords are NEVER included in response types
//! - All input is validated before processing
//! - Errors are sanitized before sending to frontend
//! - The `CommandResult` type alias ensures consistent error handling
//!
//! # IPC Type Contracts
//!
//! Every Tauri command follows this contract:
//! 1. Request: Flat parameters (no nested JSON objects) for Tauri IPC
//! 2. Validation: All inputs validated before processing
//! 3. Authorization: Vault state checked (Locked/Unlocked)
//! 4. Processing: Business logic in domain modules
//! 5. Response: Typed struct with no secrets

use crate::error::KestrelError;
use crate::security::vault_state::VaultState;
use serde::{Deserialize, Serialize};

// ─── Validation Constants ─────────────────────────────────────────

/// Maximum length for entry titles.
pub const MAX_TITLE_LEN: usize = 256;

/// Maximum length for usernames.
pub const MAX_USERNAME_LEN: usize = 256;

/// Maximum length for passwords.
pub const MAX_PASSWORD_LEN: usize = 1024;

/// Maximum length for notes fields.
pub const MAX_NOTES_LEN: usize = 10_000;

/// Maximum length for URLs.
pub const MAX_URL_LEN: usize = 2048;

/// Maximum length for folder names.
pub const MAX_FOLDER_NAME_LEN: usize = 128;

/// Minimum length for master password.
pub const MIN_MASTER_PASSWORD_LEN: usize = 8;

/// Maximum length for password hints.
pub const MAX_HINT_LEN: usize = 100;

/// Maximum length for search queries.
pub const MAX_QUERY_LEN: usize = 256;

// ─── Command Result ───────────────────────────────────────────────

/// A result type for Tauri command handlers.
///
/// Uses `Result<T, CommandError>` so the `?` operator works
/// naturally. Tauri serializes `Ok` values directly and sends
/// `Err` values through the error channel.
pub type CommandResult<T> = Result<T, CommandError>;

/// A user-safe error for the frontend.
///
/// Error messages are sanitized to never expose:
/// - File paths
/// - SQL queries
/// - Cryptographic details
/// - Stack traces
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandError {
    /// Machine-readable error code (e.g., "VAULT_LOCKED").
    pub code: String,
    /// Human-readable error message (user-safe).
    pub message: String,
}

impl CommandError {
    /// Creates a CommandError from a KestrelError.
    ///
    /// Maps internal errors to user-safe messages.
    pub fn from_kestrel(err: KestrelError) -> Self {
        let (code, message) = match &err {
            KestrelError::Crypto(msg) => ("CRYPTO_ERROR", msg.as_str()),
            KestrelError::Database(_) => ("DATABASE_ERROR", "A database operation failed"),
            KestrelError::Vault(_) => ("VAULT_ERROR", "A vault operation failed"),
            KestrelError::Audit(_) => ("AUDIT_ERROR", "An audit operation failed"),
            KestrelError::Scanner(_) => ("SCANNER_ERROR", "A scan operation failed"),
            KestrelError::Config(_) => ("CONFIG_ERROR", "A configuration error occurred"),
            KestrelError::Serialization(_) => {
                ("SERIALIZATION_ERROR", "A data processing error occurred")
            }
            KestrelError::Validation(msg) => ("VALIDATION_ERROR", msg.as_str()),
            KestrelError::Io(_) => ("IO_ERROR", "An I/O operation failed"),
            KestrelError::Unauthorized(msg) => ("UNAUTHORIZED", msg.as_str()),
            KestrelError::Internal(_) => ("INTERNAL_ERROR", "An internal error occurred"),
        };
        CommandError {
            code: code.to_string(),
            message: message.to_string(),
        }
    }

    /// Creates a validation error with a specific message.
    pub fn validation(msg: impl Into<String>) -> Self {
        CommandError {
            code: "VALIDATION_ERROR".to_string(),
            message: msg.into(),
        }
    }

    /// Creates an unauthorized error.
    pub fn unauthorized(msg: impl Into<String>) -> Self {
        CommandError {
            code: "UNAUTHORIZED".to_string(),
            message: msg.into(),
        }
    }
}

/// Allow `?` on `KestrelError` in functions returning `CommandResult<T>`.
impl From<KestrelError> for CommandError {
    fn from(err: KestrelError) -> Self {
        CommandError::from_kestrel(err)
    }
}

// ─── Response Types ───────────────────────────────────────────────

/// Response for vault entry queries — NO PASSWORD field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntryResponse {
    pub id: String,
    pub title: String,
    pub username: String,
    pub url: Option<String>,
    pub folder_id: Option<String>,
    pub has_totp: bool,
    pub notes_preview: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Temporary password reveal response.
///
/// The frontend should display this briefly and auto-clear.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordRevealResponse {
    /// The decrypted password — auto-cleared after display.
    pub password: String,
    /// Seconds until the frontend should auto-clear.
    pub auto_clear_seconds: u32,
}

/// Session info for the frontend.
///
/// Contains NO secrets — only state metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionResponse {
    pub session_id: String,
    pub expires_at: String,
    pub is_unlocked: bool,
}

/// Password strength analysis response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordStrengthResponse {
    pub score: u8,
    pub label: String,
    pub entropy_bits: f64,
    pub warnings: Vec<String>,
    pub suggestions: Vec<String>,
}

/// Vulnerability scan result response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityItemResponse {
    pub id: String,
    pub threat_level: String,
    pub description: String,
    pub recommendation: String,
    pub entry_id: Option<String>,
}

/// Response for entry-specific breach check (HIBP Password API).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreachCheckEntryResponse {
    /// Whether the password was found in the HIBP breach database.
    pub is_breached: bool,
    /// Number of times the password appeared in breaches.
    pub occurrence_count: u64,
    /// Human-readable message about the result.
    pub message: String,
    /// Threat level string (e.g., "critical", "none").
    pub threat_level: String,
}

/// Audit event response for the frontend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEventResponse {
    pub id: String,
    pub category: String,
    pub action: String,
    pub subject: String,
    pub timestamp: String,
}

/// Paginated audit query response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditPageResponse {
    pub events: Vec<AuditEventResponse>,
    pub total_count: i64,
    pub has_more: bool,
}

/// Application settings response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettingsResponse {
    pub auto_lock_minutes: u32,
    pub theme: String,
    pub language: String,
    pub clear_clipboard_seconds: u32,
    pub lock_on_sleep: bool,
    pub lock_on_blur: bool,
    pub auto_backup: bool,
    pub backup_frequency: String,
    pub backup_location: String,
    pub debug_mode: bool,
    pub max_login_attempts: u32,
    pub lockout_duration_seconds: u32,
}

// ─── Vault State Responses ────────────────────────────────────────

/// Response for vault status queries.
/// Contains NO secrets — only lifecycle state metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultStatusResponse {
    /// Current lifecycle state of the vault.
    pub state: String,
    /// Whether the vault has been initialized.
    pub is_initialized: bool,
    /// Whether the vault is currently unlocked.
    pub is_unlocked: bool,
    /// Number of failed unlock attempts in current locked period.
    pub failed_unlock_attempts: u32,
    /// Whether the user is currently locked out.
    pub is_locked_out: bool,
}

impl VaultStatusResponse {
    /// Creates a VaultStatusResponse from the current vault state.
    pub fn from_state(state: VaultState, failed_attempts: u32, is_locked_out: bool) -> Self {
        Self {
            state: state.to_string(),
            is_initialized: state != VaultState::Uninitialized,
            is_unlocked: state == VaultState::Unlocked,
            failed_unlock_attempts: failed_attempts,
            is_locked_out,
        }
    }
}

/// Response for vault initialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultInitResponse {
    /// Confirmation that the vault was initialized.
    pub initialized: bool,
    /// The vault is now in Locked state.
    pub state: String,
}

/// Response for vault lock/unlock operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultLockResponse {
    /// The new vault state after the operation.
    pub state: String,
}

// ─── Auth Request Types ──────────────────────────────────────────

/// Request to initialize the vault for the first time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitializeVaultRequest {
    /// The master password (min 8 characters).
    pub master_password: String,
    /// Optional password hint (NOT a security feature).
    pub hint: Option<String>,
}

/// Request to unlock the vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnlockVaultRequest {
    /// The master password.
    pub master_password: String,
}

/// Request to change the master password.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangePasswordRequest {
    /// The current master password (must be verified).
    pub current_password: String,
    /// The new master password (min 8 characters).
    pub new_password: String,
}

// ─── Folder Types ────────────────────────────────────────────────

/// Response for folder queries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FolderResponse {
    pub id: String,
    pub name: String,
    pub parent_id: Option<String>,
    pub entry_count: i64,
    pub created_at: String,
}

/// Request to create a folder.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateFolderRequest {
    pub name: String,
    pub parent_id: Option<String>,
}

// ─── Secure Note Types ───────────────────────────────────────────

/// Response for secure note queries — encrypted content NOT included.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureNoteResponse {
    pub id: String,
    pub title: String,
    pub has_content: bool,
    pub folder_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Response for secure note reveal — content included temporarily.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureNoteRevealResponse {
    pub id: String,
    pub title: String,
    /// Decrypted note content — auto-cleared after display.
    pub content: String,
    /// Seconds until the frontend should auto-clear.
    pub auto_clear_seconds: u32,
}

// ─── File Entry Types ────────────────────────────────────────────

/// Response for file vault entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntryResponse {
    pub id: String,
    pub filename: String,
    pub mime_type: String,
    pub size_bytes: i64,
    pub folder_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

// ─── Security Center Types ───────────────────────────────────────

/// Overall security score response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityScoreResponse {
    /// Score from 0-100.
    pub score: u8,
    /// Human-readable label.
    pub label: String,
    /// Breakdown by category.
    pub breakdown: SecurityBreakdown,
}

/// Breakdown of security score by category.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityBreakdown {
    pub password_health: u8,
    pub breach_status: u8,
    pub vault_hygiene: u8,
    pub audit_compliance: u8,
}

// ─── Validation Helpers ───────────────────────────────────────────

/// Validates a string field against length constraints.
pub fn validate_field(
    value: &str,
    max_len: usize,
    field_name: &str,
) -> Result<(), CommandError> {
    if value.len() > max_len {
        return Err(CommandError::validation(format!(
            "{field_name} must be at most {max_len} characters"
        )));
    }
    if value.contains('\0') {
        return Err(CommandError::validation(format!(
            "{field_name} must not contain null bytes"
        )));
    }
    Ok(())
}

/// Validates a master password meets minimum requirements.
pub fn validate_master_password(password: &str) -> Result<(), CommandError> {
    if password.len() < MIN_MASTER_PASSWORD_LEN {
        return Err(CommandError::validation(format!(
            "Master password must be at least {MIN_MASTER_PASSWORD_LEN} characters"
        )));
    }
    if password.len() > MAX_PASSWORD_LEN {
        return Err(CommandError::validation(format!(
            "Master password must be at most {MAX_PASSWORD_LEN} characters"
        )));
    }
    if password.contains('\0') {
        return Err(CommandError::validation(
            "Master password must not contain null bytes",
        ));
    }
    Ok(())
}

/// Validates a UUID string.
pub fn validate_uuid(id: &str, field_name: &str) -> Result<(), CommandError> {
    uuid::Uuid::parse_str(id).map_err(|_| {
        CommandError::validation(format!("{field_name} is not a valid UUID"))
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_result_ok() {
        let result: CommandResult<String> = Ok("hello".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn command_result_err_from_kestrel() {
        let result: CommandResult<String> =
            Err(CommandError::from_kestrel(KestrelError::Unauthorized("test".to_string())));
        assert!(result.is_err());
    }

    #[test]
    fn error_sanitizes_crypto() {
        let err = CommandError::from_kestrel(KestrelError::Crypto("secret details".to_string()));
        assert_eq!(err.code, "CRYPTO_ERROR");
        assert_eq!(err.message, "A cryptographic operation failed");
        assert!(!err.message.contains("secret"));
    }

    #[test]
    fn error_preserves_validation() {
        let err = CommandError::from_kestrel(KestrelError::Validation(
            "Title too long".to_string(),
        ));
        assert_eq!(err.code, "VALIDATION_ERROR");
        assert_eq!(err.message, "Title too long");
    }

    #[test]
    fn validate_field_ok() {
        assert!(validate_field("hello", 10, "test").is_ok());
    }

    #[test]
    fn validate_field_too_long() {
        assert!(validate_field("hello world", 5, "test").is_err());
    }

    #[test]
    fn validate_field_null_bytes() {
        assert!(validate_field("hel\0lo", 10, "test").is_err());
    }

    #[test]
    fn validate_master_password_ok() {
        assert!(validate_master_password("secure-password-123").is_ok());
    }

    #[test]
    fn validate_master_password_too_short() {
        assert!(validate_master_password("short").is_err());
    }

    #[test]
    fn validate_uuid_ok() {
        assert!(validate_uuid("550e8400-e29b-41d4-a716-446655440000", "id").is_ok());
    }

    #[test]
    fn validate_uuid_invalid() {
        assert!(validate_uuid("not-a-uuid", "id").is_err());
    }
}
