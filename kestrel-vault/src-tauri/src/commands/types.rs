//! Shared command types for Tauri IPC.
//!
//! Defines all request/response structures used across command handlers.
//! These types are the ONLY data shapes that cross the IPC boundary.
//!
//! # Security Design
//!
//! - `VaultEntryResponse` NEVER includes password fields
//! - `PasswordRevealResponse` includes auto-clear metadata
//! - `CommandResult<T>` wraps all responses for consistent error handling
//! - `ValidationRules` are shared with the frontend for client-side hints
//!
//! # Naming Convention
//!
//! - `*Request` = input from frontend to Rust
//! - `*Response` = output from Rust to frontend
//! - `CommandResult<T>` = wrapper that serializes cleanly for Tauri

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ─── Command Result Wrapper ──────────────────────────────────────────

/// Wrapper type for all Tauri command responses.
///
/// Provides a consistent serialization format that cleanly separates
/// success data from error information. The `error` field is only
/// present when `ok` is `false`.
///
/// # Security
///
/// Error messages are always user-safe (never expose internal paths,
/// crypto details, or SQL queries). Validation errors are the only
/// case where the original message is preserved.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "ok")]
pub enum CommandResult<T: Serialize> {
    /// Successful response with data payload.
    #[serde(rename = "true")]
    Ok { data: T },
    /// Failed response with user-safe error message.
    #[serde(rename = "false")]
    Err { error: String },
}

impl<T: Serialize> CommandResult<T> {
    /// Creates a successful result with the given data.
    pub fn ok(data: T) -> Self {
        CommandResult::Ok { data }
    }

    /// Creates an error result with a user-safe message.
    pub fn err(error: String) -> Self {
        CommandResult::Err { error }
    }

    /// Creates an error result from a KestrelError, applying
    /// user-safe message mapping.
    pub fn from_kestrel_error(e: crate::error::KestrelError) -> Self {
        CommandResult::Err {
            error: e.to_user_message(),
        }
    }
}

impl<T: Serialize> From<Result<T, crate::error::KestrelError>> for CommandResult<T> {
    fn from(result: Result<T, crate::error::KestrelError>) -> Self {
        match result {
            Ok(data) => CommandResult::Ok { data },
            Err(e) => CommandResult::Err {
                error: e.to_user_message(),
            },
        }
    }
}

// ─── Vault Entry Response ────────────────────────────────────────────

/// Frontend-safe vault entry representation.
///
/// This type is the ONLY way the frontend sees vault entry data.
/// Password fields are NEVER included — they must be explicitly
/// requested via `vault_reveal_password`.
///
/// # Fields Omitted (Security)
///
/// - `encrypted_password` — ciphertext, never sent to frontend
/// - `password_nonce` — nonce, never sent to frontend
/// - `encrypted_notes` — ciphertext, never sent to frontend
/// - `notes_nonce` — nonce, never sent to frontend
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultEntryResponse {
    /// Unique entry identifier.
    pub id: Uuid,
    /// Display title (e.g., "GitHub", "Bank of America").
    pub title: String,
    /// Username or email for this credential.
    pub username: String,
    /// Associated URL (display-only, not a security boundary).
    pub url: Option<String>,
    /// Folder this entry belongs to.
    pub folder_id: Option<Uuid>,
    /// Whether this entry has a TOTP secret configured.
    pub has_totp: bool,
    /// Truncated preview of notes (max 80 chars), never full content.
    pub notes_preview: Option<String>,
    /// Tags for categorization.
    pub tags: Vec<String>,
    /// When this entry was created (ISO 8601).
    pub created_at: DateTime<Utc>,
    /// When this entry was last modified (ISO 8601).
    pub updated_at: DateTime<Utc>,
}

// ─── Password Reveal Response ────────────────────────────────────────

/// Temporary password reveal response with auto-clear metadata.
///
/// This type is returned ONLY by `vault_reveal_password` and
/// includes metadata to help the frontend enforce auto-clear
/// behavior (e.g., clearing the clipboard after 30 seconds).
///
/// # Security
///
/// - The `password` field is the ONLY time a decrypted password
///   is sent to the frontend.
/// - The frontend MUST clear this value from memory after use.
/// - `auto_clear_seconds` tells the frontend when to clear clipboard.
/// - Every reveal is logged in the audit trail.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PasswordRevealResponse {
    /// The decrypted password. Frontend MUST clear after use.
    pub password: String,
    /// Seconds until the frontend should clear clipboard.
    pub auto_clear_seconds: u32,
    /// When this reveal was authorized (for audit correlation).
    pub revealed_at: DateTime<Utc>,
    /// ID of the entry this password belongs to.
    pub entry_id: Uuid,
}

// ─── Session Response ────────────────────────────────────────────────

/// Frontend-safe session information.
///
/// Contains only non-sensitive session state. Keys, derived keys,
/// and internal session data are NEVER included.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionResponse {
    /// Session identifier (opaque token, not a secret).
    pub session_id: String,
    /// When this session expires (ISO 8601).
    pub expires_at: DateTime<Utc>,
    /// Whether the vault is currently unlocked.
    pub is_unlocked: bool,
}

// ─── Scan Result Response ────────────────────────────────────────────

/// Frontend-safe scan result representation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanResultResponse {
    /// Unique scan result identifier.
    pub id: Uuid,
    /// Overall threat level.
    pub threat_level: String,
    /// Human-readable description of the finding.
    pub description: String,
    /// Recommended remediation action.
    pub recommendation: String,
    /// When this scan was performed (ISO 8601).
    pub scanned_at: DateTime<Utc>,
    /// IDs of affected vault entries.
    pub affected_entry_ids: Vec<Uuid>,
}

// ─── Audit Event Response ────────────────────────────────────────────

/// Frontend-safe audit event representation.
///
/// Audit events NEVER contain passwords, decrypted data, or
/// cryptographic keys. Only non-sensitive metadata is included.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEventResponse {
    /// Unique event identifier.
    pub id: Uuid,
    /// Event category (auth, vault, file, system, security).
    pub category: String,
    /// Action type (create, read, update, delete, login, etc.).
    pub action: String,
    /// Human-readable event description (never contains secrets).
    pub description: String,
    /// When this event occurred (ISO 8601).
    pub timestamp: DateTime<Utc>,
    /// Additional metadata (structure depends on category/action).
    pub metadata: std::collections::HashMap<String, String>,
}

// ─── Validation Rules ────────────────────────────────────────────────

/// Shared validation constants for frontend and backend.
///
/// These values are exposed to the frontend for client-side
/// validation hints. The Rust backend ALWAYS performs its own
/// validation regardless of frontend checks.
///
/// # Security
///
/// Frontend validation is a UX convenience, NOT a security boundary.
/// All input validation is enforced server-side (in Rust).
pub struct ValidationRules;

impl ValidationRules {
    /// Maximum title length in characters.
    pub const MAX_TITLE_LEN: usize = 256;
    /// Maximum username length in characters.
    pub const MAX_USERNAME_LEN: usize = 256;
    /// Maximum password length in characters.
    pub const MAX_PASSWORD_LEN: usize = 1024;
    /// Maximum notes length in characters.
    pub const MAX_NOTES_LEN: usize = 10_000;
    /// Maximum URL length in characters.
    pub const MAX_URL_LEN: usize = 2048;
    /// Maximum search query length in characters.
    pub const MAX_QUERY_LEN: usize = 256;
    /// Maximum hint length in characters.
    pub const MAX_HINT_LEN: usize = 100;
    /// Minimum master password length in characters.
    pub const MIN_MASTER_PASSWORD_LEN: usize = 8;
    /// Maximum folder name length in characters.
    pub const MAX_FOLDER_NAME_LEN: usize = 128;
    /// Maximum tag length in characters.
    pub const MAX_TAG_LEN: usize = 64;
    /// Maximum number of tags per entry.
    pub const MAX_TAGS_PER_ENTRY: usize = 20;
    /// Maximum payload size in bytes (1 MB).
    pub const MAX_PAYLOAD_BYTES: usize = 1_048_576;
}

// ─── Pagination ──────────────────────────────────────────────────────

/// Pagination parameters for list/query commands.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaginationRequest {
    /// Maximum number of results to return.
    pub limit: i64,
    /// Number of results to skip.
    pub offset: i64,
}

impl Default for PaginationRequest {
    fn default() -> Self {
        Self {
            limit: 50,
            offset: 0,
        }
    }
}

impl PaginationRequest {
    /// Validates pagination parameters.
    pub fn validate(&self) -> Result<(), crate::error::KestrelError> {
        if self.limit < 1 {
            return Err(crate::error::KestrelError::Validation(
                "Limit must be at least 1".to_string(),
            ));
        }
        if self.limit > 1000 {
            return Err(crate::error::KestrelError::Validation(
                "Limit too large (max 1000)".to_string(),
            ));
        }
        if self.offset < 0 {
            return Err(crate::error::KestrelError::Validation(
                "Offset must be non-negative".to_string(),
            ));
        }
        Ok(())
    }
}

/// Paginated response with metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaginatedResponse<T: Serialize> {
    /// The result items for this page.
    pub items: Vec<T>,
    /// Total number of matching items.
    pub total_count: i64,
    /// Whether there are more results beyond this page.
    pub has_more: bool,
}

// ─── Input Validation Helpers ────────────────────────────────────────

/// Validates that a string contains no null bytes.
///
/// Null bytes can cause truncation attacks in downstream systems.
pub fn validate_no_null_bytes(s: &str, field_name: &str) -> Result<(), crate::error::KestrelError> {
    if s.contains('\0') {
        return Err(crate::error::KestrelError::Validation(format!(
            "{field_name} must not contain null bytes"
        )));
    }
    Ok(())
}

/// Validates string length within bounds.
pub fn validate_string_length(
    s: &str,
    min: usize,
    max: usize,
    field_name: &str,
) -> Result<(), crate::error::KestrelError> {
    if s.len() < min {
        return Err(crate::error::KestrelError::Validation(format!(
            "{field_name} must be at least {min} characters"
        )));
    }
    if s.len() > max {
        return Err(crate::error::KestrelError::Validation(format!(
            "{field_name} must be at most {max} characters"
        )));
    }
    Ok(())
}

/// Validates a UUID string format.
pub fn validate_uuid(id: &str, field_name: &str) -> Result<Uuid, crate::error::KestrelError> {
    Uuid::parse_str(id).map_err(|_| {
        crate::error::KestrelError::Validation(format!(
            "{field_name} must be a valid UUID"
        ))
    })
}

/// Validates a string is not blank (empty or whitespace-only).
pub fn validate_not_blank(s: &str, field_name: &str) -> Result<(), crate::error::KestrelError> {
    if s.trim().is_empty() {
        return Err(crate::error::KestrelError::Validation(format!(
            "{field_name} must not be blank"
        )));
    }
    Ok(())
}

/// Comprehensive string validation combining common checks.
pub fn validate_string_field(
    s: &str,
    min: usize,
    max: usize,
    field_name: &str,
    allow_blank: bool,
) -> Result<(), crate::error::KestrelError> {
    if !allow_blank {
        validate_not_blank(s, field_name)?;
    } else if s.is_empty() {
        return Ok(());
    }
    validate_no_null_bytes(s, field_name)?;
    validate_string_length(s, min, max, field_name)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_result_ok_serializes() {
        let result = CommandResult::ok(42u32);
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"ok\":true"));
        assert!(json.contains("\"data\":42"));
    }

    #[test]
    fn command_result_err_serializes() {
        let result: CommandResult<u32> = CommandResult::err("bad input".to_string());
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"ok\":false"));
        assert!(json.contains("\"error\":\"bad input\""));
    }

    #[test]
    fn validate_no_null_bytes_rejects() {
        assert!(validate_no_null_bytes("hello\0world", "test").is_err());
    }

    #[test]
    fn validate_no_null_bytes_allows() {
        assert!(validate_no_null_bytes("hello world", "test").is_ok());
    }

    #[test]
    fn validate_string_length_rejects_short() {
        assert!(validate_string_length("ab", 3, 10, "test").is_err());
    }

    #[test]
    fn validate_string_length_rejects_long() {
        assert!(validate_string_length("abcdefghijk", 3, 10, "test").is_err());
    }

    #[test]
    fn validate_string_length_allows_valid() {
        assert!(validate_string_length("abcde", 3, 10, "test").is_ok());
    }

    #[test]
    fn validate_uuid_rejects_invalid() {
        assert!(validate_uuid("not-a-uuid", "test").is_err());
    }

    #[test]
    fn validate_uuid_allows_valid() {
        let uuid = Uuid::new_v4();
        assert!(validate_uuid(&uuid.to_string(), "test").is_ok());
    }

    #[test]
    fn validate_not_blank_rejects_whitespace() {
        assert!(validate_not_blank("   ", "test").is_err());
    }

    #[test]
    fn pagination_default() {
        let p = PaginationRequest::default();
        assert_eq!(p.limit, 50);
        assert_eq!(p.offset, 0);
    }

    #[test]
    fn pagination_validates_limit() {
        let p = PaginationRequest { limit: 0, offset: 0 };
        assert!(p.validate().is_err());
    }

    #[test]
    fn validation_rules_constants() {
        assert_eq!(ValidationRules::MIN_MASTER_PASSWORD_LEN, 8);
        assert_eq!(ValidationRules::MAX_TITLE_LEN, 256);
    }
}
