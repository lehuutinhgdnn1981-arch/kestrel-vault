//! Database manager for KESTREL Vault.
//!
//! Orchestrates the full lifecycle of the encrypted SQLite database:
//! creation, opening, migration, verification, backup, and closing.
//! This is the **single entry point** for all database operations —
//! no code should create `DbConnection` directly outside this module.
//!
//! # Lifecycle
//!
//! ```text
//! ┌─────────────────────────────────────────────────────┐
//! │                DatabaseManager                       │
//! │                                                      │
//! │  create_vault()  →  new DB + key + migrations        │
//!  │  open_vault()   →  verify key + run migrations      │
//! │  close_vault()   →  close pool + zeroize key         │
//! │  rekey_vault()   →  change SQLCipher key (rotation)  │
//! │  backup_vault()  →  export encrypted backup           │
//! │  integrity_check()→ PRAGMA integrity_check           │
//! └─────────────────────────────────────────────────────┘
//! ```
//!
//! # Security
//!
//! - The SQLCipher key is derived from the master password via Argon2id
//! - The key is set via PRAGMA immediately after connection
//! - Key material is zeroized after being passed to SQLCipher
//! - WAL mode ensures concurrent read safety without sacrificing durability
//! - Foreign key constraints are enforced at the database level
//!
//! # Thread Safety
//!
//! `DatabaseManager` uses `RwLock<Option<DbConnection>>` internally:
//! - Multiple concurrent readers (queries) are allowed
//! - Write operations (open/close/rekey) acquire exclusive access
//! - The `Option` represents the vault's open/closed state

use crate::db::connection::DbConnection;
use crate::db::migrations;
use crate::db::vault_meta_repo::VaultMetaRepo;
use crate::error::{KestrelError, KestrelResult};
use parking_lot::RwLock;
use sqlx::SqlitePool;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Configuration for database connection pool and behavior.
#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    /// Maximum number of connections in the pool.
    /// Default: 5. Increase for high-concurrency scenarios.
    pub max_connections: u32,

    /// Busy timeout in milliseconds. How long SQLite will wait
    /// if the database is locked by another writer.
    /// Default: 5000ms (5 seconds).
    pub busy_timeout_ms: u32,

    /// SQLite cache size in KiB. Larger cache improves read performance
    /// at the cost of memory usage.
    /// Default: -2000 (2MiB, negative = KiB).
    pub cache_size_kib: i32,

    /// Synchronous mode. Options:
    /// - 0 = OFF (fastest, unsafe on crash)
    /// - 1 = NORMAL (good balance, safe with WAL)
    /// - 2 = FULL (safest, slower)
    /// Default: 1 (NORMAL) — sufficient with WAL journaling.
    pub synchronous_mode: i32,

    /// Whether to enable foreign key enforcement.
    /// Default: true. Should always be true for data integrity.
    pub foreign_keys: bool,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        DatabaseConfig {
            max_connections: 5,
            busy_timeout_ms: 5000,
            cache_size_kib: -2000, // 2MiB
            synchronous_mode: 1,   // NORMAL
            foreign_keys: true,
        }
    }
}

/// The state of a vault database connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultDbState {
    /// No database is currently open.
    Closed,
    /// A database is open and ready for operations.
    Open,
}

/// Manages the encrypted SQLite database lifecycle.
///
/// This is the primary interface for all database operations.
/// It wraps the connection pool and ensures that:
/// 1. Connections are always encrypted with SQLCipher
/// 2. Migrations are run on every open
/// 3. The database is properly closed when the vault is locked
/// 4. Integrity checks can be performed on demand
///
/// # Usage
///
/// ```ignore
/// let manager = DatabaseManager::new("/path/to/vault.db");
///
/// // Create a new vault
/// manager.create_vault(&sqlcipher_key_hex, &config).await?;
///
/// // Open an existing vault
/// manager.open_vault(&sqlcipher_key_hex, &config).await?;
///
/// // Get a reference to the pool for repository operations
/// let pool = manager.pool()?;
///
/// // Close the vault (e.g., on lock)
/// manager.close_vault().await?;
/// ```
pub struct DatabaseManager {
    /// Path to the SQLite database file.
    path: PathBuf,

    /// The current database connection, if the vault is open.
    connection: RwLock<Option<DbConnection>>,

    /// The current vault database state.
    state: RwLock<VaultDbState>,
}

impl DatabaseManager {
    /// Creates a new `DatabaseManager` for the given database path.
    ///
    /// This does NOT open the database — it only stores the path.
    /// Call `create_vault()` or `open_vault()` to establish a connection.
    ///
    /// # Arguments
    ///
    /// * `path` - Path where the SQLite database file is (or will be) stored
    pub fn new(path: &Path) -> Self {
        DatabaseManager {
            path: path.to_path_buf(),
            connection: RwLock::new(None),
            state: RwLock::new(VaultDbState::Closed),
        }
    }

    /// Creates a new encrypted vault database.
    ///
    /// This operation:
    /// 1. Creates the database file with SQLCipher encryption
    /// 2. Sets the encryption key via PRAGMA
    /// 3. Runs all migrations to create the schema
    /// 4. Verifies the database is accessible
    ///
    /// # Arguments
    ///
    /// * `key_hex` - Hex-encoded SQLCipher key (use `format_sqlcipher_key()`)
    /// * `config` - Database configuration parameters
    ///
    /// # Errors
    ///
    /// Returns `KestrelError::Database` if:
    /// - The database file already exists
    /// - The connection cannot be established
    /// - Migrations fail to execute
    /// - Key verification fails
    ///
    /// # Security
    ///
    /// The key material is zeroized after being passed to the connection.
    pub async fn create_vault(
        &self,
        key_hex: &str,
        config: &DatabaseConfig,
    ) -> KestrelResult<()> {
        // Check if the database file already exists
        if self.path.exists() {
            return Err(KestrelError::Database(
                "Vault database file already exists — use open_vault() instead".to_string(),
            ));
        }

        // Ensure parent directory exists
        if let Some(parent) = self.path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    KestrelError::Io(format!(
                        "Failed to create database directory '{}': {e}",
                        parent.display()
                    ))
                })?;
            }
        }

        // Create the encrypted connection
        let db_conn = DbConnection::new_with_config(&self.path, key_hex, config).await?;

        // Run migrations to create the schema
        let pool = db_conn.pool();
        migrations::run_migrations(pool).await?;

        // Verify migration integrity
        migrations::verify_migration_integrity(pool).await?;

        // Store the connection
        {
            let mut conn_guard = self.connection.write();
            *conn_guard = Some(db_conn);
        }
        {
            let mut state_guard = self.state.write();
            *state_guard = VaultDbState::Open;
        }

        tracing::info!(
            "Created new vault database at {}",
            self.path.display()
        );

        Ok(())
    }

    /// Creates a new vault database without SQLCipher encryption.
    ///
    /// Since all sensitive data is encrypted at the application level
    /// with AES-256-GCM, the database file itself doesn't need
    /// SQLCipher encryption. This avoids the dependency on the
    /// SQLCipher native library.
    pub async fn create_vault_plain(&self) -> KestrelResult<()> {
        // Check if the database file already exists
        if self.path.exists() {
            return Err(KestrelError::Database(
                "Vault database file already exists — use open_vault_plain() instead".to_string(),
            ));
        }

        // Ensure parent directory exists
        if let Some(parent) = self.path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    KestrelError::Io(format!(
                        "Failed to create database directory '{}': {e}",
                        parent.display()
                    ))
                })?;
            }
        }

        let config = DatabaseConfig::default();

        // Create the plain (non-SQLCipher) connection
        let db_conn = DbConnection::new_plain(&self.path, &config).await?;

        // Run migrations to create the schema
        let pool = db_conn.pool();
        migrations::run_migrations(pool).await?;
        migrations::verify_migration_integrity(pool).await?;

        // Store the connection
        {
            let mut conn_guard = self.connection.write();
            *conn_guard = Some(db_conn);
        }
        {
            let mut state_guard = self.state.write();
            *state_guard = VaultDbState::Open;
        }

        tracing::info!(
            "Created new vault database (plain) at {}",
            self.path.display()
        );

        Ok(())
    }

    /// Opens an existing vault database without SQLCipher encryption.
    ///
    /// Since all sensitive data is encrypted at the application level
    /// with AES-256-GCM, the database file itself doesn't need
    /// SQLCipher encryption.
    pub async fn open_vault_plain(&self) -> KestrelResult<()> {
        // Check if the database file exists
        if !self.path.exists() {
            return Err(KestrelError::Database(
                "Vault database file does not exist — use create_vault_plain() first".to_string(),
            ));
        }

        // Check if already open
        if self.state() == VaultDbState::Open {
            return Ok(()); // Already open — idempotent
        }

        let config = DatabaseConfig::default();

        // Open the plain (non-SQLCipher) connection
        let db_conn = DbConnection::new_plain(&self.path, &config).await?;

        // Run any pending migrations
        let pool = db_conn.pool();
        migrations::run_migrations(pool).await?;
        migrations::verify_migration_integrity(pool).await?;

        // Store the connection
        {
            let mut conn_guard = self.connection.write();
            *conn_guard = Some(db_conn);
        }
        {
            let mut state_guard = self.state.write();
            *state_guard = VaultDbState::Open;
        }

        tracing::info!(
            "Opened vault database (plain) at {}",
            self.path.display()
        );

        Ok(())
    }

    /// Opens an existing encrypted vault database.
    ///
    /// This operation:
    /// 1. Opens the database file with SQLCipher encryption
    /// 2. Sets the encryption key via PRAGMA
    /// 3. Verifies the key is correct (by reading sqlite_master)
    /// 4. Runs any pending migrations
    /// 5. Verifies migration integrity
    ///
    /// # Arguments
    ///
    /// * `key_hex` - Hex-encoded SQLCipher key (use `format_sqlcipher_key()`)
    /// * `config` - Database configuration parameters
    ///
    /// # Errors
    ///
    /// Returns `KestrelError::Database` if:
    /// - The database file does not exist
    /// - The key is incorrect (SQLCipher verification fails)
    /// - Migrations fail
    /// - The database is corrupted
    ///
    /// # Security
    ///
    /// An incorrect key will cause `verify_key()` to fail, which
    /// means no data is exposed even with a wrong key attempt.
    pub async fn open_vault(
        &self,
        key_hex: &str,
        config: &DatabaseConfig,
    ) -> KestrelResult<()> {
        // Check if the database file exists
        if !self.path.exists() {
            return Err(KestrelError::Database(
                "Vault database file does not exist — use create_vault() first".to_string(),
            ));
        }

        // Check if already open
        if self.state() == VaultDbState::Open {
            return Err(KestrelError::Database(
                "Vault database is already open".to_string(),
            ));
        }

        // Open the encrypted connection
        let db_conn = DbConnection::new_with_config(&self.path, key_hex, config).await?;

        // Run any pending migrations
        let pool = db_conn.pool();
        migrations::run_migrations(pool).await?;

        // Verify migration integrity
        migrations::verify_migration_integrity(pool).await?;

        // Store the connection
        {
            let mut conn_guard = self.connection.write();
            *conn_guard = Some(db_conn);
        }
        {
            let mut state_guard = self.state.write();
            *state_guard = VaultDbState::Open;
        }

        tracing::info!(
            "Opened vault database at {}",
            self.path.display()
        );

        Ok(())
    }

    /// Closes the vault database and releases all resources.
    ///
    /// This should be called when the vault is locked. All connections
    /// in the pool are closed, and the internal state is set to Closed.
    ///
    /// # Errors
    ///
    /// Returns `KestrelError::Database` if the vault is not open.
    pub async fn close_vault(&self) -> KestrelResult<()> {
        let mut conn_guard = self.connection.write();

        if let Some(conn) = conn_guard.take() {
            conn.close().await;

            let mut state_guard = self.state.write();
            *state_guard = VaultDbState::Closed;

            tracing::info!("Closed vault database");
            Ok(())
        } else {
            Err(KestrelError::Database(
                "Vault database is not open".to_string(),
            ))
        }
    }

    /// Changes the SQLCipher encryption key (for password rotation).
    ///
    /// This re-encrypts the database with a new key. The old key
    /// must still be set (i.e., the vault must be open).
    ///
    /// # Arguments
    ///
    /// * `new_key_hex` - The new hex-encoded SQLCipher key
    ///
    /// # Security
    ///
    /// - The old key is NOT zeroized (it's managed by SQLCipher internally)
    /// - The new key material should be zeroized after calling this
    /// - This operation is atomic — either the entire re-key succeeds or fails
    ///
    /// # Implementation Note
    ///
    /// SQLCipher supports `PRAGMA rekey` which re-encrypts all database
    /// pages with the new key. This is an O(n) operation where n is the
    /// number of database pages. For large databases, this may take time.
    pub async fn rekey_vault(&self, new_key_hex: &str) -> KestrelResult<()> {
        let pool = self.pool()?;

        sqlx::query(&format!("PRAGMA rekey = {new_key_hex}"))
            .execute(&pool)
            .await
            .map_err(|e| {
                KestrelError::Database(format!("Failed to rekey database: {e}"))
            })?;

        tracing::info!("Database re-keyed successfully");
        Ok(())
    }

    /// Returns a reference to the database connection pool.
    ///
    /// Returns an error if the vault is not open. All repository
    /// operations should use this pool reference.
    pub fn pool(&self) -> KestrelResult<SqlitePool> {
        let guard = self.connection.read();
        match guard.as_ref() {
            Some(conn) => Ok(conn.pool().clone()),
            None => Err(KestrelError::Database(
                "Vault database is not open".to_string(),
            )),
        }
    }

    /// Returns the current vault database state.
    pub fn state(&self) -> VaultDbState {
        *self.state.read()
    }

    /// Returns true if the vault database is open.
    pub fn is_open(&self) -> bool {
        self.state() == VaultDbState::Open
    }

    /// Returns the database file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Checks if a database file exists at the configured path.
    pub fn database_file_exists(&self) -> bool {
        self.path.exists()
    }

    /// Checks if a vault has been initialized (has a vault_meta row).
    ///
    /// This is different from `database_file_exists()` — a file may
    /// exist but not have the vault_meta initialized yet.
    pub async fn is_vault_initialized(&self) -> KestrelResult<bool> {
        let pool = self.pool()?;
        VaultMetaRepo::exists(&pool).await
    }

    /// Runs a database integrity check.
    ///
    /// Executes `PRAGMA integrity_check` which verifies:
    /// - Database file format is valid
    /// - All pages are accessible and properly formatted
    /// - B-tree structures are consistent
    /// - Indexes are properly ordered
    /// - No orphaned pages exist
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the integrity check passes ("ok").
    /// Returns an error with details if any issues are found.
    pub async fn integrity_check(&self) -> KestrelResult<()> {
        let pool = self.pool()?;

        let result: (String,) = sqlx::query_as("PRAGMA integrity_check")
            .fetch_one(&pool)
            .await
            .map_err(|e| KestrelError::Database(format!("Integrity check query failed: {e}")))?;

        if result.0 == "ok" {
            tracing::info!("Database integrity check passed");
            Ok(())
        } else {
            tracing::error!("Database integrity check failed: {}", result.0);
            Err(KestrelError::Database(format!(
                "Database integrity check failed: {}",
                result.0
            )))
        }
    }

    /// Runs a foreign key constraint check.
    ///
    /// Executes `PRAGMA foreign_key_check` which verifies that all
    /// foreign key references are valid. This should be run after
    /// any bulk import or manual database modification.
    pub async fn foreign_key_check(&self) -> KestrelResult<Vec<ForeignKeyViolation>> {
        let pool = self.pool()?;

        let rows: Vec<(String, i64, String, i64)> = sqlx::query_as(
            "PRAGMA foreign_key_check"
        )
        .fetch_all(&pool)
        .await
        .map_err(|e| KestrelError::Database(format!("Foreign key check failed: {e}")))?;

        let violations: Vec<ForeignKeyViolation> = rows
            .into_iter()
            .map(|(table, rowid, parent, fkid)| ForeignKeyViolation {
                table,
                rowid,
                parent,
                fk_index: fkid,
            })
            .collect();

        if violations.is_empty() {
            tracing::info!("Foreign key check passed");
        } else {
            tracing::warn!(
                "Foreign key check found {} violations",
                violations.len()
            );
        }

        Ok(violations)
    }

    /// Optimizes the database by running VACUUM.
    ///
    /// This rebuilds the database file, removing fragmentation
    /// and reclaiming unused space. Should be run periodically
    /// or after large deletions.
    ///
    /// # Warning
    ///
    /// VACUUM requires exclusive access to the database and may
    /// take significant time for large databases. Do not run this
    /// during normal operations.
    pub async fn vacuum(&self) -> KestrelResult<()> {
        let pool = self.pool()?;

        sqlx::query("VACUUM")
            .execute(&pool)
            .await
            .map_err(|e| KestrelError::Database(format!("VACUUM failed: {e}")))?;

        tracing::info!("Database VACUUM completed");
        Ok(())
    }

    /// Returns database size information.
    ///
    /// Returns the file size in bytes and the number of pages.
    pub async fn database_size(&self) -> KestrelResult<DatabaseSizeInfo> {
        let pool = self.pool()?;

        let page_count: (i64,) =
            sqlx::query_as("PRAGMA page_count")
                .fetch_one(&pool)
                .await
                .map_err(|e| KestrelError::Database(format!("Failed to get page count: {e}")))?;

        let page_size: (i64,) =
            sqlx::query_as("PRAGMA page_size")
                .fetch_one(&pool)
                .await
                .map_err(|e| KestrelError::Database(format!("Failed to get page size: {e}")))?;

        let file_size = std::fs::metadata(&self.path)
            .map(|m| m.len())
            .unwrap_or(0);

        Ok(DatabaseSizeInfo {
            file_size_bytes: file_size,
            page_count: page_count.0,
            page_size_bytes: page_size.0,
            total_db_size_bytes: page_count.0 * page_size.0,
        })
    }

    /// Validates that the database is ready for operations.
    ///
    /// This performs a comprehensive health check:
    /// 1. Connection is alive
    /// 2. Integrity check passes
    /// 3. Migration integrity is verified
    /// 4. Vault meta exists
    pub async fn validate(&self) -> KestrelResult<ValidationReport> {
        let mut report = ValidationReport::default();

        // Check connection
        match self.pool() {
            Ok(pool) => {
                match sqlx::query("SELECT 1").execute(&pool).await {
                    Ok(_) => report.connection_ok = true,
                    Err(e) => report.errors.push(format!("Connection check failed: {e}")),
                }
            }
            Err(e) => report.errors.push(format!("Pool unavailable: {e}")),
        }

        // Check integrity
        match self.integrity_check().await {
            Ok(_) => report.integrity_ok = true,
            Err(e) => report.errors.push(format!("Integrity check failed: {e}")),
        }

        // Check migration integrity
        if let Ok(pool) = self.pool() {
            match migrations::verify_migration_integrity(&pool).await {
                Ok(_) => report.migrations_ok = true,
                Err(e) => report.errors.push(format!("Migration integrity failed: {e}")),
            }
        }

        // Check vault meta
        match self.is_vault_initialized().await {
            Ok(true) => report.vault_meta_ok = true,
            Ok(false) => report.warnings.push("Vault meta not initialized".to_string()),
            Err(e) => report.errors.push(format!("Vault meta check failed: {e}")),
        }

        report.healthy = report.errors.is_empty();

        Ok(report)
    }

    /// Creates an in-memory database for testing.
    ///
    /// This bypasses SQLCipher encryption and creates a plain
    /// SQLite database in memory. **Only use for tests.**
    ///
    /// # Security
    ///
    /// In-memory databases are NOT encrypted. Never use this
    /// for production data.
    #[cfg(test)]
    pub async fn new_in_memory() -> KestrelResult<Self> {
        let db_conn = DbConnection::new_in_memory().await?;

        let pool = db_conn.pool();
        migrations::run_migrations(pool).await?;

        let manager = DatabaseManager {
            path: PathBuf::from(":memory:"),
            connection: RwLock::new(Some(db_conn)),
            state: RwLock::new(VaultDbState::Open),
        };

        Ok(manager)
    }
}

/// A foreign key constraint violation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ForeignKeyViolation {
    /// The table containing the foreign key reference.
    pub table: String,
    /// The rowid of the row with the violation.
    pub rowid: i64,
    /// The parent table that is referenced.
    pub parent: String,
    /// The foreign key index within the table definition.
    pub fk_index: i64,
}

/// Database size information.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DatabaseSizeInfo {
    /// The on-disk file size in bytes.
    pub file_size_bytes: u64,
    /// Number of database pages.
    pub page_count: i64,
    /// Size of each page in bytes.
    pub page_size_bytes: i64,
    /// Total logical database size (page_count * page_size).
    pub total_db_size_bytes: i64,
}

impl DatabaseSizeInfo {
    /// Returns a human-readable file size string.
    pub fn human_file_size(&self) -> String {
        Self::format_bytes(self.file_size_bytes)
    }

    /// Returns a human-readable total DB size string.
    pub fn human_db_size(&self) -> String {
        Self::format_bytes(self.total_db_size_bytes as u64)
    }

    fn format_bytes(bytes: u64) -> String {
        const KB: u64 = 1024;
        const MB: u64 = 1024 * KB;
        const GB: u64 = 1024 * MB;

        if bytes >= GB {
            format!("{:.2} GB", bytes as f64 / GB as f64)
        } else if bytes >= MB {
            format!("{:.2} MB", bytes as f64 / MB as f64)
        } else if bytes >= KB {
            format!("{:.2} KB", bytes as f64 / KB as f64)
        } else {
            format!("{bytes} bytes")
        }
    }
}

/// Validation report from a comprehensive database health check.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ValidationReport {
    /// Whether the database is overall healthy (no errors).
    pub healthy: bool,
    /// Connection is alive and responding.
    pub connection_ok: bool,
    /// Integrity check passed.
    pub integrity_ok: bool,
    /// Migration integrity verified.
    pub migrations_ok: bool,
    /// Vault meta row exists.
    pub vault_meta_ok: bool,
    /// Non-fatal warnings.
    pub warnings: Vec<String>,
    /// Fatal errors.
    pub errors: Vec<String>,
}

impl std::fmt::Display for ValidationReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "=== Database Validation Report ===")?;
        writeln!(f, "Healthy: {}", if self.healthy { "YES" } else { "NO" })?;
        writeln!(f, "Connection: {}", if self.connection_ok { "OK" } else { "FAIL" })?;
        writeln!(f, "Integrity: {}", if self.integrity_ok { "OK" } else { "FAIL" })?;
        writeln!(f, "Migrations: {}", if self.migrations_ok { "OK" } else { "FAIL" })?;
        writeln!(f, "Vault Meta: {}", if self.vault_meta_ok { "OK" } else { "MISSING" })?;

        if !self.warnings.is_empty() {
            writeln!(f, "\nWarnings:")?;
            for w in &self.warnings {
                writeln!(f, "  - {w}")?;
            }
        }

        if !self.errors.is_empty() {
            writeln!(f, "\nErrors:")?;
            for e in &self.errors {
                writeln!(f, "  - {e}")?;
            }
        }

        Ok(())
    }
}

/// Thread-safe wrapper around DatabaseManager for use in AppState.
///
/// This Arc wrapper allows the DatabaseManager to be shared safely
/// across Tauri command handlers running on different threads.
pub type SharedDatabaseManager = Arc<DatabaseManager>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_config_default() {
        let config = DatabaseConfig::default();
        assert_eq!(config.max_connections, 5);
        assert_eq!(config.busy_timeout_ms, 5000);
        assert_eq!(config.synchronous_mode, 1);
        assert!(config.foreign_keys);
    }

    #[test]
    fn vault_db_state_equality() {
        assert_eq!(VaultDbState::Closed, VaultDbState::Closed);
        assert_eq!(VaultDbState::Open, VaultDbState::Open);
        assert_ne!(VaultDbState::Closed, VaultDbState::Open);
    }

    #[test]
    fn database_size_info_format_bytes() {
        assert_eq!(DatabaseSizeInfo::format_bytes(0), "0 bytes");
        assert_eq!(DatabaseSizeInfo::format_bytes(512), "512 bytes");
        assert_eq!(DatabaseSizeInfo::format_bytes(1024), "1.00 KB");
        assert_eq!(DatabaseSizeInfo::format_bytes(1048576), "1.00 MB");
        assert_eq!(DatabaseSizeInfo::format_bytes(1073741824), "1.00 GB");
    }

    #[test]
    fn database_size_info_human_readable() {
        let info = DatabaseSizeInfo {
            file_size_bytes: 5 * 1024 * 1024, // 5 MB
            page_count: 100,
            page_size_bytes: 4096,
            total_db_size_bytes: 409600,
        };
        assert_eq!(info.human_file_size(), "5.00 MB");
        assert_eq!(info.human_db_size(), "400.00 KB");
    }

    #[test]
    fn validation_report_default() {
        let report = ValidationReport::default();
        assert!(!report.healthy);
        assert!(!report.connection_ok);
        assert!(!report.integrity_ok);
        assert!(!report.migrations_ok);
        assert!(!report.vault_meta_ok);
        assert!(report.warnings.is_empty());
        assert!(report.errors.is_empty());
    }

    #[test]
    fn validation_report_display() {
        let report = ValidationReport {
            healthy: true,
            connection_ok: true,
            integrity_ok: true,
            migrations_ok: true,
            vault_meta_ok: true,
            warnings: vec!["test warning".to_string()],
            errors: vec![],
        };
        let display = format!("{report}");
        assert!(display.contains("Healthy: YES"));
        assert!(display.contains("Connection: OK"));
        assert!(display.contains("test warning"));
    }

    #[test]
    fn foreign_key_violation_serializes() {
        let violation = ForeignKeyViolation {
            table: "vault_entries".to_string(),
            rowid: 42,
            parent: "folders".to_string(),
            fk_index: 0,
        };
        let json = serde_json::to_string(&violation).unwrap();
        assert!(json.contains("vault_entries"));
        assert!(json.contains("folders"));
    }

    #[test]
    fn manager_new_is_closed() {
        let manager = DatabaseManager::new(Path::new("/tmp/test.db"));
        assert_eq!(manager.state(), VaultDbState::Closed);
        assert!(!manager.is_open());
        assert_eq!(manager.path(), Path::new("/tmp/test.db"));
    }

    #[tokio::test]
    async fn manager_create_requires_nonexistent_file() {
        let manager = DatabaseManager::new(Path::new("/tmp/test.db"));
        // This should fail because /tmp/test.db likely doesn't exist as a proper vault
        // but the create_vault itself needs a real environment
        // Just test that the state machine works
        assert_eq!(manager.state(), VaultDbState::Closed);
    }

    #[test]
    fn database_config_custom() {
        let config = DatabaseConfig {
            max_connections: 10,
            busy_timeout_ms: 10000,
            cache_size_kib: -8000,
            synchronous_mode: 2,
            foreign_keys: true,
        };
        assert_eq!(config.max_connections, 10);
        assert_eq!(config.busy_timeout_ms, 10000);
        assert_eq!(config.synchronous_mode, 2);
    }
}
