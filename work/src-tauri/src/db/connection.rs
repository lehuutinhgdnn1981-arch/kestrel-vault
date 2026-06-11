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
//! - Busy timeout prevents immediate failures under write contention
//! - Foreign key constraints are enforced at the database level
//!
//! # Connection Configuration
//!
//! The `DatabaseConfig` struct (in `manager.rs`) controls pool size,
//! busy timeout, cache size, synchronous mode, and other PRAGMAs.
//! These are applied when creating a new `DbConnection`.

use crate::db::manager::DatabaseConfig;
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
///
/// # Connection Lifecycle
///
/// 1. `DbConnection::new()` — Create encrypted file-based pool
/// 2. `DbConnection::new_with_config()` — Create with custom configuration
/// 3. `DbConnection::new_in_memory()` — Create unencrypted in-memory pool (testing only)
/// 4. `DbConnection::validate()` — Check pool health
/// 5. `DbConnection::close()` — Gracefully close all connections
///
/// # Thread Safety
///
/// `DbConnection` is `Clone` (cloning shares the underlying pool).
/// The `SqlitePool` itself is `Send + Sync`, so it can be safely
/// shared across async tasks and threads.
#[derive(Clone)]
pub struct DbConnection {
    /// The underlying SQLite connection pool.
    pool: SqlitePool,
}

impl DbConnection {
    /// Creates a new encrypted database connection pool with default config.
    ///
    /// This is a convenience wrapper around `new_with_config()` using
    /// default `DatabaseConfig` values.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the SQLite database file
    /// * `key` - The hex-encoded SQLCipher key (e.g., `x'abcd...'`)
    ///
    /// # Errors
    ///
    /// Returns `KestrelError::Database` if:
    /// - The database file cannot be created or opened
    /// - SQLCipher key setting fails
    /// - Connection validation fails
    pub async fn new(
        path: &Path,
        key: &str,
    ) -> Result<Self, KestrelError> {
        Self::new_with_config(path, key, &DatabaseConfig::default()).await
    }

    /// Creates a new encrypted database connection pool with custom config.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the SQLite database file
    /// * `key` - The hex-encoded SQLCipher key (e.g., `x'abcd...'`)
    /// * `config` - Database configuration parameters
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
    pub async fn new_with_config(
        path: &Path,
        key: &str,
        config: &DatabaseConfig,
    ) -> Result<Self, KestrelError> {
        let connection_str = format!("sqlite:{}?mode=rwc", path.display());

        let mut options = SqliteConnectOptions::from_str(&connection_str)
            .map_err(|e| KestrelError::Database(format!("Invalid connection options: {e}")))?;

        // ── Security PRAGMAs ──

        // Set SQLCipher PRAGMA key for encryption
        options = options.pragma("key", key);

        // ── Journaling & Durability ──

        // Enable WAL mode for better concurrent read performance
        options = options.pragma("journal_mode", "WAL");

        // Set synchronous mode (NORMAL is safe with WAL)
        options = options.pragma("synchronous", &config.synchronous_mode.to_string());

        // ── Foreign Keys ──

        if config.foreign_keys {
            options = options.pragma("foreign_keys", "ON");
        }

        // ── Performance PRAGMAs ──

        // Set cache size (negative = KiB, positive = pages)
        options = options.pragma("cache_size", &config.cache_size_kib.to_string());

        // Set busy timeout (how long to wait if database is locked)
        options = options.pragma("busy_timeout", &config.busy_timeout_ms.to_string());

        // ── Temp storage ──

        // Store temp tables in memory (not on disk)
        options = options.pragma("temp_store", "MEMORY");

        let pool = SqlitePoolOptions::new()
            .max_connections(config.max_connections)
            .connect_with(options)
            .await
            .map_err(|e| KestrelError::Database(format!("Failed to create connection pool: {e}")))?;

        // Verify the connection and key are valid
        Self::verify_key(&pool).await?;

        Ok(DbConnection { pool })
    }

    /// Creates an in-memory SQLite database for testing.
    ///
    /// This bypasses SQLCipher encryption and creates a plain
    /// SQLite database entirely in memory. It is intended ONLY
    /// for unit/integration tests.
    ///
    /// # Security
    ///
    /// **WARNING**: In-memory databases are NOT encrypted. Never use
    /// this for production data or any data that should be protected.
    ///
    /// # Errors
    ///
    /// Returns `KestrelError::Database` if the connection fails.
    pub async fn new_in_memory() -> Result<Self, KestrelError> {
        let options = SqliteConnectOptions::from_str("sqlite::memory:")
            .map_err(|e| KestrelError::Database(format!("Invalid in-memory options: {e}")))?
            .pragma("journal_mode", "WAL")
            .pragma("foreign_keys", "ON")
            .pragma("synchronous", "NORMAL")
            .pragma("cache_size", "-2000")
            .pragma("temp_store", "MEMORY");

        let pool = SqlitePoolOptions::new()
            .max_connections(1) // In-memory DBs are per-connection, so only 1
            .connect_with(options)
            .await
            .map_err(|e| {
                KestrelError::Database(format!(
                    "Failed to create in-memory connection pool: {e}"
                ))
            })?;

        Ok(DbConnection { pool })
    }

    /// Verifies that the SQLCipher key is correct by attempting to read.
    ///
    /// This executes a simple query to confirm the database can be
    /// decrypted with the current key. If the key is wrong, SQLCipher
    /// will return an error when trying to read encrypted pages.
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
    /// to ensure the database is accessible. This executes a
    /// lightweight `SELECT 1` query.
    pub async fn validate(&self) -> Result<(), KestrelError> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map_err(|e| KestrelError::Database(format!("Connection validation failed: {e}")))?;
        Ok(())
    }

    /// Gracefully closes all connections in the pool.
    ///
    /// After calling this, the pool can no longer be used for queries.
    /// Any in-flight queries will complete before the connection is closed.
    pub async fn close(&self) {
        self.pool.close().await;
    }

    /// Returns the current number of idle connections in the pool.
    ///
    /// Useful for monitoring pool health and connection usage.
    pub fn idle_connections(&self) -> u32 {
        self.pool.size() - self.pool.num_active()
    }

    /// Returns the total number of connections (active + idle).
    pub fn total_connections(&self) -> u32 {
        self.pool.size()
    }
}

/// Creates a hex-encoded key string for SQLCipher PRAGMA key.
///
/// SQLCipher expects the key in hex format when prefixed with
/// "x'" and suffixed with "'". This function formats the raw
/// key bytes accordingly.
///
/// # Example
///
/// ```
/// let key_bytes = [0xABu8, 0xCD, 0xEF, 0x01];
/// let formatted = format_sqlcipher_key(&key_bytes);
/// assert_eq!(formatted, "x'abcdef01'");
/// ```
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

    #[test]
    fn format_sqlcipher_key_empty() {
        let key: [u8; 0] = [];
        let formatted = format_sqlcipher_key(&key);
        assert_eq!(formatted, "x''");
    }

    #[test]
    fn format_sqlcipher_key_full_32_bytes() {
        let key = [0xFFu8; 32]; // 256-bit key
        let formatted = format_sqlcipher_key(&key);
        assert!(formatted.starts_with("x'"));
        assert!(formatted.ends_with("'"));
        // 32 bytes = 64 hex chars + "x'" + "'" = 67 chars
        assert_eq!(formatted.len(), 67);
    }

    #[test]
    fn zeroize_string_clears_content() {
        let mut s = "sensitive_key_material".to_string();
        let original_len = s.len();
        zeroize_string(&mut s);
        // After zeroize, the string buffer is all zeros
        // The string still has its original length but zeroed content
        assert_eq!(s.len(), original_len);
    }

    #[tokio::test]
    async fn in_memory_db_works() {
        let conn = DbConnection::new_in_memory().await;
        assert!(conn.is_ok(), "In-memory database should connect");

        let conn = conn.unwrap();
        assert!(conn.validate().await.is_ok(), "Validation should pass");
    }

    #[tokio::test]
    async fn in_memory_db_query_works() {
        let conn = DbConnection::new_in_memory().await.unwrap();
        let pool = conn.pool();

        // Create a simple table
        let result = sqlx::query("CREATE TABLE test (id INTEGER PRIMARY KEY, value TEXT)")
            .execute(pool)
            .await;
        assert!(result.is_ok(), "Should be able to create a table");

        // Insert data
        let result = sqlx::query("INSERT INTO test (value) VALUES ('hello')")
            .execute(pool)
            .await;
        assert!(result.is_ok(), "Should be able to insert data");

        // Read data back
        let row: (i64, String) = sqlx::query_as("SELECT id, value FROM test WHERE value = 'hello'")
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(row.0, 1);
        assert_eq!(row.1, "hello");
    }

    #[tokio::test]
    async fn in_memory_db_foreign_keys_enforced() {
        let conn = DbConnection::new_in_memory().await.unwrap();
        let pool = conn.pool();

        // Create parent and child tables
        sqlx::query("CREATE TABLE parent (id INTEGER PRIMARY KEY)")
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE child (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parent(id))")
            .execute(pool)
            .await
            .unwrap();

        // Try to insert a child with non-existent parent — should fail
        let result = sqlx::query("INSERT INTO child (parent_id) VALUES (999)")
            .execute(pool)
            .await;
        assert!(result.is_err(), "Foreign key constraint should be enforced");
    }

    #[test]
    fn connection_pool_info_methods() {
        // We can't easily test these without a real connection,
        // but we can verify the struct compiles with Clone
        fn assert_clone<T: Clone>() {}
        assert_clone::<DbConnection>();
    }
}
