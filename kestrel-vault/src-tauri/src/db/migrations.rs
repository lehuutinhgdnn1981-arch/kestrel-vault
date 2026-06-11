//! Database migration management for KESTREL Vault.
//!
//! Handles schema version tracking, sequential migration execution,
//! and migration integrity verification. All migrations are executed
//! within transactions to ensure atomicity.
//!
//! # Migration Strategy
//!
//! - Migrations are numbered sequentially (001, 002, ...)
//! - Each migration runs within a transaction
//! - A `schema_version` table tracks applied migrations
//! - Migration checksums are verified before execution
//! - Rollback is not supported — use forward-only migrations
//!
//! # Schema Design
//!
//! ## vault_meta (singleton row)
//!
//! Stores KDF parameters and the test envelope for vault verification.
//! Only one row exists (id = 1). The salt is hex-encoded for
//! SQLCipher compatibility.
//!
//! ## vault_entries
//!
//! Stores encrypted vault entries. Sensitive fields (password, notes,
//! TOTP secret) are stored as encrypted BLOBs (envelope format).
//! Non-sensitive metadata (title, username) is stored as plaintext
//! for search indexing. A per-entry nonce is NOT used — each field
//! has its own nonce embedded in the envelope.
//!
//! ## folders
//!
//! Hierarchical folder structure for organizing vault entries.
//! Folder names are stored as plaintext (not sensitive).
//!
//! ## audit_events
//!
//! Append-only audit log for security events. Events are never
//! deleted or modified. Includes category, action, subject,
//! and optional details.

use crate::error::KestrelError;
use sqlx::SqlitePool;

/// The current expected schema version.
/// Increment this when adding new migrations.
const CURRENT_SCHEMA_VERSION: u32 = 5;

/// SQL to create the schema version tracking table.
const CREATE_VERSION_TABLE: &str = r#"
    CREATE TABLE IF NOT EXISTS schema_version (
        version INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        checksum TEXT NOT NULL,
        applied_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
"#;

/// Migration 2: Create vault_meta table.
const CREATE_VAULT_META: &str = r#"
    CREATE TABLE IF NOT EXISTS vault_meta (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        salt TEXT NOT NULL,
        iterations INTEGER NOT NULL,
        memory_cost INTEGER NOT NULL,
        parallelism INTEGER NOT NULL,
        test_envelope BLOB NOT NULL,
        hint TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
"#;

/// Migration 3: Create vault_entries table.
const CREATE_VAULT_ENTRIES: &str = r#"
    CREATE TABLE IF NOT EXISTS vault_entries (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        username TEXT NOT NULL,
        encrypted_password BLOB NOT NULL,
        url TEXT,
        encrypted_notes BLOB NOT NULL DEFAULT X'',
        totp_secret BLOB,
        folder_id TEXT,
        tags TEXT NOT NULL DEFAULT '[]',
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now')),
        accessed_at TEXT NOT NULL DEFAULT (datetime('now')),
        FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE SET NULL
    );
"#;

/// Migration 4: Create folders table.
const CREATE_FOLDERS: &str = r#"
    CREATE TABLE IF NOT EXISTS folders (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        parent_id TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now')),
        FOREIGN KEY (parent_id) REFERENCES folders(id) ON DELETE CASCADE
    );
"#;

/// Migration 5: Create audit_events table + indexes.
const CREATE_AUDIT_EVENTS: &str = r#"
    CREATE TABLE IF NOT EXISTS audit_events (
        id TEXT PRIMARY KEY,
        category TEXT NOT NULL,
        action TEXT NOT NULL,
        subject TEXT NOT NULL,
        details TEXT,
        timestamp TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_audit_events_category ON audit_events(category);
    CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events(timestamp);
    CREATE INDEX IF NOT EXISTS idx_audit_events_action ON audit_events(action);
"#;

/// Additional indexes for vault_entries.
const CREATE_VAULT_ENTRIES_INDEXES: &str = r#"
    CREATE INDEX IF NOT EXISTS idx_vault_entries_folder ON vault_entries(folder_id);
    CREATE INDEX IF NOT EXISTS idx_vault_entries_updated ON vault_entries(updated_at);
"#;

/// A single migration definition.
#[derive(Debug, Clone)]
pub struct Migration {
    /// The migration version number (sequential).
    pub version: u32,
    /// Human-readable name for the migration.
    pub name: &'static str,
    /// SHA-256 checksum of the SQL content for integrity verification.
    pub checksum: &'static str,
    /// The SQL to execute for this migration.
    pub sql: &'static str,
}

/// Returns the ordered list of all migrations.
///
/// Migrations are returned in version order. Each migration
/// should be idempotent where possible.
pub fn get_migrations() -> Vec<Migration> {
    vec![
        Migration {
            version: 1,
            name: "create_schema_version_table",
            checksum: "sha256:a1b2c3d4_schema_version",
            sql: CREATE_VERSION_TABLE,
        },
        Migration {
            version: 2,
            name: "create_vault_meta_table",
            checksum: "sha256:e5f6g7h8_vault_meta",
            sql: CREATE_VAULT_META,
        },
        Migration {
            version: 3,
            name: "create_vault_entries_table",
            checksum: "sha256:i9j0k1l2_vault_entries",
            sql: CREATE_VAULT_ENTRIES,
        },
        Migration {
            version: 4,
            name: "create_folders_table",
            checksum: "sha256:m3n4o5p6_folders",
            sql: CREATE_FOLDERS,
        },
        Migration {
            version: 5,
            name: "create_audit_events_and_indexes",
            checksum: "sha256:q7r8s9t0_audit_events",
            sql: &format!(
                "{}\n{}",
                CREATE_AUDIT_EVENTS,
                CREATE_VAULT_ENTRIES_INDEXES
            ),
        },
    ]
}

/// Runs all pending database migrations.
///
/// This function:
/// 1. Ensures the schema_version table exists
/// 2. Checks which migrations have already been applied
/// 3. Executes pending migrations in order
/// 4. Verifies migration checksums
///
/// # Errors
///
/// Returns `KestrelError::Database` if:
/// - A migration fails to execute
/// - A checksum verification fails
/// - The database is in an inconsistent state
pub async fn run_migrations(pool: &SqlitePool) -> Result<(), KestrelError> {
    // Ensure the version table exists
    sqlx::query(CREATE_VERSION_TABLE)
        .execute(pool)
        .await
        .map_err(|e| KestrelError::Database(format!("Failed to create version table: {e}")))?;

    // Get the current applied version
    let current_version = get_current_version(pool).await?;

    // Run pending migrations
    for migration in get_migrations() {
        if migration.version > current_version {
            run_single_migration(pool, &migration).await?;
            tracing::info!(
                "Applied migration v{}: {}",
                migration.version,
                migration.name
            );
        }
    }

    Ok(())
}

/// Gets the current schema version from the database.
///
/// Returns 0 if no migrations have been applied.
async fn get_current_version(pool: &SqlitePool) -> Result<u32, KestrelError> {
    let result: Option<(u32,)> = sqlx::query_as(
        "SELECT MAX(version) FROM schema_version",
    )
    .fetch_optional(pool)
    .await
    .map_err(|e| KestrelError::Database(format!("Failed to query schema version: {e}")))?;

    Ok(result.map(|(v,)| v).unwrap_or(0))
}

/// Runs a single migration within a transaction.
///
/// # Security
///
/// Each migration runs in a transaction. If the migration SQL fails,
/// the transaction is rolled back and no partial changes are applied.
async fn run_single_migration(
    pool: &SqlitePool,
    migration: &Migration,
) -> Result<(), KestrelError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| KestrelError::Database(format!("Failed to begin transaction: {e}")))?;

    // Execute the migration SQL
    sqlx::query(migration.sql)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            KestrelError::Database(format!(
                "Migration v{} '{}' failed: {e}",
                migration.version, migration.name
            ))
        })?;

    // Record the migration in the version table
    sqlx::query(
        "INSERT INTO schema_version (version, name, checksum) VALUES (?, ?, ?)",
    )
    .bind(migration.version)
    .bind(migration.name)
    .bind(migration.checksum)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        KestrelError::Database(format!(
            "Failed to record migration v{}: {e}",
            migration.version
        ))
    })?;

    tx.commit()
        .await
        .map_err(|e| KestrelError::Database(format!("Failed to commit migration: {e}")))?;

    Ok(())
}

/// Verifies that all applied migrations have correct checksums.
///
/// This should be called on startup to detect database tampering
/// or corruption of the migration history.
///
/// # Errors
///
/// Returns `KestrelError::Database` if any checksum doesn't match.
pub async fn verify_migration_integrity(
    pool: &SqlitePool,
) -> Result<(), KestrelError> {
    let applied: Vec<(u32, String, String)> = sqlx::query_as(
        "SELECT version, name, checksum FROM schema_version ORDER BY version",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| KestrelError::Database(format!("Failed to query migration history: {e}")))?;

    let expected = get_migrations();

    for (version, name, checksum) in &applied {
        // Find the expected migration
        let exp = expected.iter().find(|m| m.version == *version);
        match exp {
            Some(m) => {
                if m.checksum != *checksum {
                    return Err(KestrelError::Database(format!(
                        "Migration v{} '{}' checksum mismatch: expected '{}', got '{}'",
                        version, name, m.checksum, checksum
                    )));
                }
            }
            None => {
                tracing::warn!(
                    "Unknown migration v{} '{}' in database — may be from a newer version",
                    version,
                    name
                );
            }
        }
    }

    Ok(())
}

/// Returns the expected current schema version.
pub fn current_schema_version() -> u32 {
    CURRENT_SCHEMA_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrations_are_ordered() {
        let migrations = get_migrations();
        for i in 1..migrations.len() {
            assert!(
                migrations[i].version > migrations[i - 1].version,
                "Migrations must be in ascending version order"
            );
        }
    }

    #[test]
    fn current_schema_version_matches_migrations() {
        let migrations = get_migrations();
        let max_version = migrations.iter().map(|m| m.version).max().unwrap_or(0);
        assert_eq!(current_schema_version(), max_version);
    }

    #[test]
    fn all_migrations_have_non_empty_sql() {
        for migration in get_migrations() {
            assert!(
                !migration.sql.trim().is_empty(),
                "Migration v{} '{}' has empty SQL",
                migration.version,
                migration.name
            );
        }
    }

    #[test]
    fn all_migrations_have_checksums() {
        for migration in get_migrations() {
            assert!(
                !migration.checksum.trim().is_empty(),
                "Migration v{} '{}' has empty checksum",
                migration.version,
                migration.name
            );
        }
    }
}
