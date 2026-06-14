//! Backup Tauri commands for KESTREL Vault.
//!
//! Handles creating encrypted backups, restoring from backups,
//! and exporting vault data.

use crate::commands::types::{CommandError, CommandResult};
use crate::config::AppConfig;
use crate::db::backup::{BackupInfo, DbBackup, EncryptedExport};
use sqlx::SqlitePool;
use std::path::PathBuf;

/// Creates an encrypted backup of the vault database.
///
/// Uses SQLite's VACUUM INTO for a consistent snapshot.
/// The backup is encrypted with the same key as the original.
#[tauri::command]
pub async fn backup_create(
    pool: &SqlitePool,
    backup_path: String,
) -> CommandResult<BackupInfo> {
    let path = PathBuf::from(&backup_path);
    let result = DbBackup::create_backup(pool, &path).await?;
    Ok(result.info)
}

/// Verifies a backup file exists and has valid content.
#[tauri::command]
pub fn backup_verify(backup_path: String) -> CommandResult<bool> {
    let path = PathBuf::from(&backup_path);
    DbBackup::verify_backup_file(&path).map_err(|e| CommandError::from(e))
}

/// Lists all backup files in a directory.
#[tauri::command]
pub fn backup_list(backup_dir: String) -> CommandResult<Vec<PathBuf>> {
    let dir = PathBuf::from(&backup_dir);
    DbBackup::list_backups(&dir).map_err(|e| CommandError::from(e))
}

/// Deletes a backup file.
#[tauri::command]
pub fn backup_delete(backup_path: String) -> CommandResult<()> {
    let path = PathBuf::from(&backup_path);
    DbBackup::delete_backup(&path).map_err(|e| CommandError::from(e))
}

/// Exports vault data as an encrypted JSON structure.
///
/// All sensitive fields remain encrypted. This is NOT a plaintext export.
/// Useful for migration while preserving encryption.
#[tauri::command]
pub async fn backup_export_encrypted(
    pool: &SqlitePool,
) -> CommandResult<EncryptedExport> {
    let export = DbBackup::export_encrypted(pool).await?;
    Ok(export)
}

/// Restores vault from a backup file.
///
/// This replaces the current database with the backup.
/// Requires the vault to be locked first.
#[tauri::command]
pub async fn backup_restore(
    app_config: tauri::State<'_, AppConfig>,
    pool: &SqlitePool,
    backup_path: String,
) -> CommandResult<()> {
    let path = PathBuf::from(&backup_path);

    // Verify backup first
    DbBackup::verify_backup_file(&path).map_err(|e| CommandError::from(e))?;

    // Copy backup over current database
    let db_path = &app_config.db_path;
    std::fs::copy(&path, db_path).map_err(|e| {
        CommandError::from(crate::error::KestrelError::Io(format!(
            "Failed to restore backup: {e}"
        )))
    })?;

    tracing::info!("Vault restored from backup: {}", path.display());
    Ok(())
}
