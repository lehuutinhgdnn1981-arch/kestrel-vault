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
//! - The `CommandResult` wrapper ensures consistent error handling

use crate::error::KestrelError;
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

/// A result type that serializes cleanly for Tauri IPC.
///
/// All Tauri commands return `CommandResult<T>` to ensure
/// consistent error handling and frontend-friendly messages.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", content = "data")]
pub enum CommandResult<T: Serialize> {
    /// Operation succeeded with the given data.
    Ok(T),
    /// Operation failed with a user-safe error message.
    Err(CommandError),
}

impl<T: Serialize> CommandResult<T> {
    /// Creates a successful result.
    pub fn ok(data: T) -> Self {
        CommandResult::Ok(data)
    }

    /// Creates an error result from a KestrelError.
    pub fn err(error: KestrelError) -> Self {
        CommandResult::Err(CommandError::from_kestrel(error))
    }

    /// Creates an error result from a code and message.
    pub fn err_msg(code: &str, message: &str) -> Self {
        CommandResult::Err(CommandError {
            code: code.to_string(),
            message: message.to_string(),
        })
    }
}

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
            KestrelError::Crypto(_) => ("CRYPTO_ERROR", "A cryptographic operation failed"),
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

impl<T: Serialize> From<KestrelError> for CommandResult<T> {
    fn from(err: KestrelError) -> Self {
        CommandResult::err(err)
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
        let result: CommandResult<String> = CommandResult::ok("hello".to_string());
        assert!(matches!(result, CommandResult::Ok(_)));
    }

    #[test]
    fn command_result_err_from_kestrel() {
        let result: CommandResult<String> =
            CommandResult::err(KestrelError::Unauthorized("test".to_string()));
        assert!(matches!(result, CommandResult::Err(_)));
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
