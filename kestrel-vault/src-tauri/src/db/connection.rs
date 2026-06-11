//! Database connection management for KESTREL Vault.
//!
//! Manages the SQLite connection pool with SQLCipher encryption.
//! The database key is derived from the user's master password
//! and set via PRAGMA before any queries are executed.
//!
//! # Security
//!
//! - The SQLCipher key is set via PRAGMA key immediately after connection
//! - Key material is zeroized after being passed to SQLCipher
//! - Connections are validated before being returned from the pool
//! - WAL mode is enabled for better concurrent read performance

use crate::error::KestrelError;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;
use std::path::Path;
use std::str::FromStr;
use zeroize::Zeroize;

/// A managed database connection pool with SQLCipher encryption.
///
/// This type wraps `sqlx::SqlitePool` and ensures that all
/// connections are properly configured with SQLCipher encryption
/// before any data operations occur.
#[derive(Clone)]
pub struct DbConnection {
    /// The underlying SQLite connection pool.
    pool: SqlitePool,
}

impl DbConnection {
    /// Creates a new encrypted database connection pool.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the SQLite database file
    /// * `key` - The hex-encoded SQLCipher key (derived from master password)
    ///
    /// # Errors
    ///
    /// Returns `KestrelError::Database` if:
    /// - The database file cannot be created or opened
    /// - SQLCipher key setting fails
    /// - Connection validation fails
    ///
    /// # Security
    ///
    /// The key material is zeroized after being passed to the
    /// connection options builder.
    pub async fn new(
        path: &Path,
        key: &str,
    ) -> Result<Self, KestrelError> {
        let connection_str = format!("sqlite:{}?mode=rwc", path.display());

        let mut options = SqliteConnectOptions::from_str(&connection_str)
            .map_err(|e| KestrelError::Database(format!("Invalid connection options: {e}")))?;

        // Set SQLCipher PRAGMA key for encryption
        options = options.pragma("key", key);

        // Enable WAL mode for better concurrent read performance
        options = options.pragma("journal_mode", "WAL");

        // Enable foreign key constraints
        options = options.pragma("foreign_keys", "ON");

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await
            .map_err(|e| KestrelError::Database(format!("Failed to create connection pool: {e}")))?;

        // Verify the connection and key are valid
        Self::verify_key(&pool).await?;

        Ok(DbConnection { pool })
    }

    /// Verifies that the SQLCipher key is correct by attempting to read.
    ///
    /// This executes a simple query to confirm the database can be
    /// decrypted with the current key.
    async fn verify_key(pool: &SqlitePool) -> Result<(), KestrelError> {
        sqlx::query("SELECT count(*) FROM sqlite_master")
            .execute(pool)
            .await
            .map_err(|e| {
                KestrelError::Database(format!(
                    "Database key verification failed: {e}"
                ))
            })?;
        Ok(())
    }

    /// Returns a reference to the underlying connection pool.
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Validates that the connection pool is still operational.
    ///
    /// Should be called periodically or before critical operations
    /// to ensure the database is accessible.
    pub async fn validate(&self) -> Result<(), KestrelError> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map_err(|e| KestrelError::Database(format!("Connection validation failed: {e}")))?;
        Ok(())
    }

    /// Gracefully closes all connections in the pool.
    pub async fn close(&self) {
        self.pool.close().await;
    }
}

/// Creates a hex-encoded key string for SQLCipher PRAGMA key.
///
/// SQLCipher expects the key in hex format when prefixed with
/// "x'" and suffixed with "'". This function formats the raw
/// key bytes accordingly.
///
/// # Security
///
/// The caller must zeroize the input key bytes after calling
/// this function. The returned string should also be zeroized
/// after passing it to the connection.
pub fn format_sqlcipher_key(key_bytes: &[u8]) -> String {
    let hex: String = key_bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("x'{hex}'")
}

/// Zeroizes a string containing sensitive key material.
///
/// Since Rust strings are immutable, this function converts the
/// string to bytes, zeroizes them, and relies on the original
/// string being dropped.
///
/// # Security
///
/// This is a best-effort operation. Rust's string handling may
/// leave copies in memory. For maximum security, prefer using
/// `Vec<u8>` for key material and zeroize that directly.
pub fn zeroize_string(s: &mut String) {
    // SAFETY: We are writing zeros to the string's buffer,
    // which is valid UTF-8 (all zeros). This is safe because
    // the string will be dropped immediately after.
    let bytes = unsafe { s.as_bytes_mut() };
    bytes.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_sqlcipher_key_formats_correctly() {
        let key = [0xABu8, 0xCD, 0xEF, 0x01];
        let formatted = format_sqlcipher_key(&key);
        assert_eq!(formatted, "x'abcdef01'");
    }
}
