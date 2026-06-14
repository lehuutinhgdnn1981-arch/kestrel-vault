//! Backup Tauri commands for KESTREL Vault.
//!
//! Handles creating encrypted backups, restoring from backups,
//! and exporting vault data.
//!
//! # IPC Security
//!
//! - All backup commands require the vault to be unlocked
//!   (except verify and list which are read-only on files)
//! - Backup files are encrypted with the same SQLCipher key
//! - The master password is required to restore a backup

use crate::commands::types::{CommandError, CommandResult};
use crate::db::backup::{BackupInfo, DbBackup, EncryptedExport};
use std::path::PathBuf;
use tauri::State;

use super::auth_commands::AppState;

/// Creates an encrypted backup of the vault database.
///
/// Uses SQLite's VACUUM INTO for a consistent snapshot.
/// The backup is encrypted with the same key as the original.
///
/// # Required State
///
/// Vault must be unlocked.
#[tauri::command]
pub fn backup_create(
    backup_path: String,
    state: State<'_, AppState>,
) -> CommandResult<BackupInfo> {
    state.require_unlocked()?;
    state.validate_session()?;

    let pool = state.get_db_pool().ok_or_else(|| {
        CommandError::unauthorized("Database not available")
    })?;

    let path = PathBuf::from(&backup_path);
    let result = crate::commands::async_runtime::block_on(async {
        DbBackup::create_backup(&pool, &path).await
    }).map_err(CommandError::from_kestrel)?;

    Ok(result.info)
}

/// Verifies a backup file exists and has valid content.
///
/// This is a read-only operation that checks file existence,
/// size, and SQLite header validity. It does NOT require
/// the vault to be unlocked.
#[tauri::command]
pub fn backup_verify(backup_path: String) -> CommandResult<bool> {
    let path = PathBuf::from(&backup_path);
    DbBackup::verify_backup_file(&path).map_err(CommandError::from_kestrel)
}

/// Lists all backup files in a directory.
///
/// Returns paths sorted by modification time (newest first).
/// Does NOT require the vault to be unlocked.
#[tauri::command]
pub fn backup_list(backup_dir: String) -> CommandResult<Vec<PathBuf>> {
    let dir = PathBuf::from(&backup_dir);
    DbBackup::list_backups(&dir).map_err(CommandError::from_kestrel)
}

/// Deletes a backup file.
///
/// This permanently removes the encrypted backup file.
/// Does NOT require the vault to be unlocked (file-level operation).
#[tauri::command]
pub fn backup_delete(backup_path: String) -> CommandResult<()> {
    let path = PathBuf::from(&backup_path);
    DbBackup::delete_backup(&path).map_err(CommandError::from_kestrel)
}

/// Exports vault data as an encrypted JSON structure.
///
/// All sensitive fields remain encrypted. This is NOT a plaintext export.
/// Useful for migration while preserving encryption.
///
/// # Required State
///
/// Vault must be unlocked.
#[tauri::command]
pub fn backup_export_encrypted(
    state: State<'_, AppState>,
) -> CommandResult<EncryptedExport> {
    state.require_unlocked()?;
    state.validate_session()?;

    let pool = state.get_db_pool().ok_or_else(|| {
        CommandError::unauthorized("Database not available")
    })?;

    let export = crate::commands::async_runtime::block_on(async {
        DbBackup::export_encrypted(&pool).await
    }).map_err(CommandError::from_kestrel)?;

    Ok(export)
}

/// Restores vault from a backup file.
///
/// This replaces the current database with the backup.
/// The vault must be unlocked so we can access the database path.
///
/// # Security
///
/// The backup file must be an encrypted SQLCipher database.
/// The user will need the master password to access restored data.
#[tauri::command]
pub fn backup_restore(
    backup_path: String,
    state: State<'_, AppState>,
) -> CommandResult<()> {
    state.require_unlocked()?;
    state.validate_session()?;

    let path = PathBuf::from(&backup_path);

    // Verify backup file first
    DbBackup::verify_backup_file(&path).map_err(CommandError::from_kestrel)?;

    // Get the current database path from the database manager
    let db_manager = state.get_db_manager().ok_or_else(|| {
        CommandError::unauthorized("Database manager not available")
    })?;
    let db_path = db_manager.path().to_path_buf();

    // Copy backup over current database
    std::fs::copy(&path, &db_path).map_err(|e| {
        CommandError::from_kestrel(crate::error::KestrelError::Io(format!(
            "Failed to restore backup: {e}"
        )))
    })?;

    tracing::info!("Vault restored from backup: {}", path.display());
    Ok(())
}
