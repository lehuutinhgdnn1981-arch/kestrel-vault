//! Error types for KESTREL Vault.
//!
//! This module defines the comprehensive error hierarchy used throughout
//! the application. All errors use `thiserror` for ergonomic derivation
//! and implement proper `Display` and `From` conversions.
//!
//! # Design Principles
//!
//! - Every operation returns `Result<T, KestrelError>` or a specific sub-error
//! - `unwrap()` is never used in production code
//! - Error messages never leak sensitive data (keys, passwords, plaintext)
//! - Errors are categorized by domain for proper handling


/// The top-level error type for all KESTREL Vault operations.
///
/// Each variant corresponds to a specific domain within the application,
/// allowing callers to pattern-match on the error category for
/// appropriate handling and recovery.
#[derive(Debug, thiserror::Error)]
pub enum KestrelError {
    /// Cryptographic operation failure (encryption, decryption, KDF, etc.)
    #[error("Cryptographic error: {0}")]
    Crypto(String),

    /// Database operation failure (query, connection, migration, etc.)
    #[error("Database error: {0}")]
    Database(String),

    /// Vault operation failure (entry CRUD, folder operations, etc.)
    #[error("Vault error: {0}")]
    Vault(String),

    /// Audit logging failure
    #[error("Audit error: {0}")]
    Audit(String),

    /// Threat scanner failure
    #[error("Scanner error: {0}")]
    Scanner(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Serialization/deserialization failure
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Input validation failure
    #[error("Validation error: {0}")]
    Validation(String),

    /// I/O operation failure
    #[error("I/O error: {0}")]
    Io(String),

    /// Authorization/authentication failure
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    /// Internal error for cases that should never happen
    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<std::io::Error> for KestrelError {
    fn from(err: std::io::Error) -> Self {
        KestrelError::Io(err.to_string())
    }
}

impl From<serde_json::Error> for KestrelError {
    fn from(err: serde_json::Error) -> Self {
        KestrelError::Serialization(err.to_string())
    }
}

impl From<sqlx::Error> for KestrelError {
    fn from(err: sqlx::Error) -> Self {
        KestrelError::Database(err.to_string())
    }
}

impl From<argon2::Error> for KestrelError {
    fn from(err: argon2::Error) -> Self {
        KestrelError::Crypto(err.to_string())
    }
}

impl From<aes_gcm::Error> for KestrelError {
    fn from(err: aes_gcm::Error) -> Self {
        KestrelError::Crypto(err.to_string())
    }
}

impl From<uuid::Error> for KestrelError {
    fn from(err: uuid::Error) -> Self {
        KestrelError::Validation(err.to_string())
    }
}

/// Convert KestrelError to a string suitable for Tauri command responses.
///
/// This strips any potentially sensitive information from error messages
/// before sending them to the frontend. Internal error details are
/// replaced with generic messages.
impl KestrelError {
    /// Returns a user-safe error message for the frontend.
    ///
    /// This method ensures that no cryptographic secrets, internal paths,
    /// or implementation details leak through Tauri command responses.
    pub fn to_user_message(&self) -> String {
        match self {
            KestrelError::Crypto(_) => "A cryptographic operation failed".to_string(),
            KestrelError::Database(_) => "A database operation failed".to_string(),
            KestrelError::Vault(_) => "A vault operation failed".to_string(),
            KestrelError::Audit(_) => "An audit operation failed".to_string(),
            KestrelError::Scanner(_) => "A scan operation failed".to_string(),
            KestrelError::Config(_) => "A configuration error occurred".to_string(),
            KestrelError::Serialization(_) => "A data processing error occurred".to_string(),
            KestrelError::Validation(msg) => msg.clone(),
            KestrelError::Io(_) => "An I/O operation failed".to_string(),
            KestrelError::Unauthorized(msg) => msg.clone(),
            KestrelError::Internal(_) => "An internal error occurred".to_string(),
        }
    }
}

/// Result type alias for KESTREL Vault operations.
pub type KestrelResult<T> = Result<T, KestrelError>;
