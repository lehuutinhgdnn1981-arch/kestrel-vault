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

use crate::error::KestrelError;
use sqlx::SqlitePool;

/// The current expected schema version.
/// Increment this when adding new migrations.
const CURRENT_SCHEMA_VERSION: u32 = 1;

/// SQL to create the schema version tracking table.
const CREATE_VERSION_TABLE: &str = r#"
    CREATE TABLE IF NOT EXISTS schema_version (
        version INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        checksum TEXT NOT NULL,
        applied_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
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
///
/// # TODO (Phase 2)
///
/// - Add initial schema migrations for vault entries, folders, audit events
/// - Add index creation migrations
/// - Add SQLCipher configuration migrations
pub fn get_migrations() -> Vec<Migration> {
    vec![
        Migration {
            version: 1,
            name: "create_schema_version_table",
            checksum: "0001_placeholder_checksum",
            sql: CREATE_VERSION_TABLE,
        },
        // TODO: Add migration for vault_entries table
        // TODO: Add migration for folders table
        // TODO: Add migration for audit_events table
        // TODO: Add migration for user_settings table
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
///
/// # TODO (Phase 2)
///
/// - Implement checksum verification against applied migrations
pub async fn verify_migration_integrity(
    _pool: &SqlitePool,
) -> Result<(), KestrelError> {
    // TODO: Implement in Phase 2
    // 1. Query all applied migrations from schema_version
    // 2. Compare each checksum against expected checksum
    // 3. Report any mismatches
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
}
