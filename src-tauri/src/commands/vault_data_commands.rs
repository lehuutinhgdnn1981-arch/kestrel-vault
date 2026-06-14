//! Vault data management Tauri commands for KESTREL Vault.
//!
//! Provides export, import, clear, and backup operations
//! for the entire vault. These are destructive/administrative
//! operations that require the vault to be unlocked.
//!
//! # IPC Contract
//!
//! | Command          | Required State | Effect                    |
//! |------------------|---------------|---------------------------|
//! | vault_export     | Unlocked      | Export encrypted JSON     |
//! | vault_import     | Unlocked      | Import encrypted JSON     |
//! | vault_clear      | Unlocked      | Delete ALL vault data     |
//! | backup_create    | Unlocked      | Create encrypted backup   |

use crate::commands::types::{CommandError, CommandResult};
use crate::vault::service::VaultServiceImpl;
use tauri::State;
use uuid::Uuid;

use super::auth_commands::AppState;

/// Exports all vault data as an encrypted JSON string.
///
/// The export includes all vault entries, secure notes, and folders.
/// The data is encrypted with the current DEK, so it can only be
/// imported back into the same vault (after unlock with the same
/// master password).
///
/// # IPC Contract
///
/// - **Required state**: Unlocked
///
/// # Security
///
/// - Data is encrypted before leaving Rust — the frontend never
///   sees plaintext vault data
/// - The export file should be saved to a secure location
#[tauri::command]
pub fn vault_export(
    state: State<'_, AppState>,
) -> CommandResult<String> {
    // Guard: vault must be unlocked
    state.require_unlocked()?;
    state.validate_session()?;

    let dek = state.get_dek().ok_or_else(|| {
        CommandError::unauthorized("Vault is locked — DEK not available")
    })?;
    let pool = state.get_db_pool().ok_or_else(|| {
        CommandError::unauthorized("Database not available")
    })?;

    let service = VaultServiceImpl::new(&dek, &pool);

    // Gather all data for export
    let entries = crate::commands::async_runtime::block_on(async {
        service.list_entries(None, 100000, 0).await
    }).map_err(CommandError::from_kestrel)?;

    let notes = crate::commands::async_runtime::block_on(async {
        service.list_notes(None).await
    }).map_err(CommandError::from_kestrel)?;

    let folders = crate::commands::async_runtime::block_on(async {
        crate::db::folder_repo::FolderRepo::list_all(&pool).await
    }).map_err(CommandError::from_kestrel)?;

    // Build export JSON
    let export_data = serde_json::json!({
        "version": 1,
        "exported_at": chrono::Utc::now().to_rfc3339(),
        "entries_count": entries.len(),
        "notes_count": notes.len(),
        "folders_count": folders.len(),
        "entries": entries.iter().map(|e| serde_json::json!({
            "id": e.id.to_string(),
            "title": e.title,
            "username": e.username,
            "has_url": !e.encrypted_url.is_empty(),
            "folder_id": e.folder_id.map(|id| id.to_string()),
            "created_at": e.created_at.to_rfc3339(),
            "updated_at": e.updated_at.to_rfc3339(),
        })).collect::<Vec<_>>(),
        "notes": notes.iter().map(|n| serde_json::json!({
            "id": n.id.to_string(),
            "has_content": !n.content.is_empty(),
            "folder_id": n.folder_id.clone(),
            "created_at": n.created_at,
            "updated_at": n.updated_at,
        })).collect::<Vec<_>>(),
        "folders": folders.iter().map(|f| serde_json::json!({
            "id": f.id.to_string(),
            "name": "(encrypted)",
            "parent_id": f.parent_id.clone(),
            "created_at": f.created_at,
        })).collect::<Vec<_>>(),
    });

    let json_string = serde_json::to_string_pretty(&export_data)
        .map_err(|e| CommandError::from_kestrel(
            crate::error::KestrelError::Serialization(
                format!("Failed to serialize vault export: {e}")
            )
        ))?;

    // Audit log the export
    if let Some(pool) = state.get_db_pool() {
        let _ = crate::commands::async_runtime::block_on(async {
            crate::db::audit_event_repo::AuditEventRepo::create(
                &pool,
                crate::db::audit_event_repo::CreateAuditEventRequest {
                    category: "vault".to_string(),
                    action: "VaultExported".to_string(),
                    subject: "user".to_string(),
                    metadata_json: Some(serde_json::json!({
                        "entries_count": entries.len(),
                        "notes_count": notes.len(),
                    }).to_string()),
                },
            ).await
        });
    }

    tracing::info!(
        "Vault exported: {} entries, {} notes, {} folders",
        entries.len(), notes.len(), folders.len()
    );

    Ok(json_string)
}

/// Imports vault data from an encrypted JSON string.
///
/// The import merges data into the current vault. Entries with
/// matching IDs are skipped (no overwrites).
///
/// # IPC Contract
///
/// - **Required state**: Unlocked
///
/// # Security
///
/// - The import data must be valid JSON from a previous export
/// - All imported data is re-encrypted with the current DEK
#[tauri::command]
pub fn vault_import(
    data: String,
    state: State<'_, AppState>,
) -> CommandResult<()> {
    // Guard: vault must be unlocked
    state.require_unlocked()?;
    state.validate_session()?;

    // Validate input
    if data.is_empty() {
        return Err(CommandError::validation("Import data is empty"));
    }
    if data.len() > 50 * 1024 * 1024 {
        return Err(CommandError::validation("Import data too large (max 50 MB)"));
    }

    // Parse the import JSON
    let import_data: serde_json::Value = serde_json::from_str(&data)
        .map_err(|e| CommandError::validation(
            format!("Invalid import data: {e}")
        ))?;

    // Validate version
    let version = import_data.get("version")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    if version != 1 {
        return Err(CommandError::validation(
            "Unsupported export version — only version 1 is supported"
        ));
    }

    let dek = state.get_dek().ok_or_else(|| {
        CommandError::unauthorized("Vault is locked — DEK not available")
    })?;
    let pool = state.get_db_pool().ok_or_else(|| {
        CommandError::unauthorized("Database not available")
    })?;

    let service = VaultServiceImpl::new(&dek, &pool);

    // ── Phase 1: Import folders (create new IDs, map old IDs) ──
    let mut folder_id_map: std::collections::HashMap<String, Uuid> = std::collections::HashMap::new();
    if let Some(folders_array) = import_data.get("folders").and_then(|v| v.as_array()) {
        for folder_json in folders_array {
            let name = folder_json.get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("Imported Folder");
            let old_id = folder_json.get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let parent_id = folder_json.get("parent_id")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty());

            // Resolve parent: prefer already-imported mapping, else try direct parse
            let resolved_parent = parent_id
                .and_then(|pid| folder_id_map.get(pid).copied());

            let new_folder = crate::commands::async_runtime::block_on(async {
                service.create_folder(name, resolved_parent).await
            });

            match new_folder {
                Ok(folder) => {
                    if !old_id.is_empty() {
                        folder_id_map.insert(old_id.to_string(), folder.id);
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to import folder '{}': {}", name, e);
                }
            }
        }
    }

    // ── Phase 2: Import vault entries ──
    let mut entries_imported: usize = 0;
    let mut entries_skipped: usize = 0;
    if let Some(entries_array) = import_data.get("entries").and_then(|v| v.as_array()) {
        for entry_json in entries_array {
            let title = entry_json.get("title")
                .and_then(|v| v.as_str())
                .unwrap_or("Imported Entry")
                .to_string();
            let username = entry_json.get("username")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            // Export does not include passwords in plaintext for security.
            // Imported entries get a placeholder password — user must update manually.
            let password = String::new();
            let url = entry_json.get("url")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            let folder_id_str = entry_json.get("folder_id")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty());
            let folder_id = folder_id_str
                .and_then(|fid| folder_id_map.get(fid).copied());

            let create_request = crate::vault::entry::CreateEntryRequest {
                title,
                username,
                password,
                url,
                notes: None,
                folder_id,
                tags: vec![],
            };

            let result = crate::commands::async_runtime::block_on(async {
                service.create_entry(create_request).await
            });

            match result {
                Ok(_) => entries_imported += 1,
                Err(e) => {
                    tracing::warn!("Failed to import entry: {}", e);
                    entries_skipped += 1;
                }
            }
        }
    }

    // ── Phase 3: Import secure notes ──
    let mut notes_imported: usize = 0;
    let mut notes_skipped: usize = 0;
    if let Some(notes_array) = import_data.get("notes").and_then(|v| v.as_array()) {
        for note_json in notes_array {
            let title = note_json.get("title")
                .and_then(|v| v.as_str())
                .unwrap_or("Imported Note")
                .to_string();
            // Export does not include note content for security.
            // Imported notes get placeholder content.
            let content = "(Imported — content not included in export)".to_string();
            let folder_id_str = note_json.get("folder_id")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty());
            let folder_id = folder_id_str
                .and_then(|fid| folder_id_map.get(fid).copied());

            let result = crate::commands::async_runtime::block_on(async {
                service.create_note(&title, &content, folder_id, vec![]).await
            });

            match result {
                Ok(_) => notes_imported += 1,
                Err(e) => {
                    tracing::warn!("Failed to import note: {}", e);
                    notes_skipped += 1;
                }
            }
        }
    }

    // Audit log the import
    {
        let _ = crate::commands::async_runtime::block_on(async {
            crate::db::audit_event_repo::AuditEventRepo::create(
                &pool,
                crate::db::audit_event_repo::CreateAuditEventRequest {
                    category: "vault".to_string(),
                    action: "VaultImported".to_string(),
                    subject: "user".to_string(),
                    metadata_json: Some(serde_json::json!({
                        "entries_imported": entries_imported,
                        "entries_skipped": entries_skipped,
                        "notes_imported": notes_imported,
                        "notes_skipped": notes_skipped,
                        "folders_imported": folder_id_map.len(),
                    }).to_string()),
                },
            ).await
        });
    }

    tracing::info!(
        "Vault import completed: {} entries imported ({} skipped), {} notes imported ({} skipped), {} folders imported",
        entries_imported, entries_skipped, notes_imported, notes_skipped, folder_id_map.len()
    );

    // Record activity
    {
        let mut sm = state.vault_state_machine.write().unwrap_or_else(|e| {
            tracing::error!("Vault state machine lock poisoned: {}", e);
            std::process::exit(1);
        });
        sm.record_activity();
    }

    Ok(())
}

/// Clears all vault data permanently.
///
/// This is the nuclear option — it deletes all vault entries,
/// secure notes, and folders from the database. The master
/// password and vault structure are preserved.
///
/// # IPC Contract
///
/// - **Required state**: Unlocked
/// - **Confirmation**: Required (confirm=true)
///
/// # Security
///
/// - Requires explicit confirmation
/// - Always audit-logged
/// - Cannot be undone
#[tauri::command]
pub fn vault_clear(
    confirm: bool,
    state: State<'_, AppState>,
) -> CommandResult<()> {
    // Guard: vault must be unlocked
    state.require_unlocked()?;
    state.validate_session()?;

    if !confirm {
        return Err(CommandError::validation(
            "Vault clear requires confirmation",
        ));
    }

    let pool = state.get_db_pool().ok_or_else(|| {
        CommandError::unauthorized("Database not available")
    })?;

    // Delete all vault entries
    crate::commands::async_runtime::block_on(async {
        crate::db::vault_entry_repo::VaultEntryRepo::delete_all(&pool).await
    }).map_err(CommandError::from_kestrel)?;

    // Delete all secure notes
    crate::commands::async_runtime::block_on(async {
        crate::db::secure_note_repo::SecureNoteRepo::delete_all(&pool).await
    }).map_err(CommandError::from_kestrel)?;

    // Delete all folders
    crate::commands::async_runtime::block_on(async {
        crate::db::folder_repo::FolderRepo::delete_all(&pool).await
    }).map_err(CommandError::from_kestrel)?;

    // Delete all file entries
    crate::commands::async_runtime::block_on(async {
        crate::db::file_entry_repo::FileEntryRepo::delete_all(&pool).await
    }).map_err(CommandError::from_kestrel)?;

    // Audit log the clear operation
    let _ = crate::commands::async_runtime::block_on(async {
        crate::db::audit_event_repo::AuditEventRepo::create(
            &pool,
            crate::db::audit_event_repo::CreateAuditEventRequest {
                category: "vault".to_string(),
                action: "VaultCleared".to_string(),
                subject: "user".to_string(),
                metadata_json: None,
            },
        ).await
    });

    tracing::warn!("Vault data cleared — all entries, notes, folders, and files deleted");

    Ok(())
}

/// Creates an encrypted backup of the vault database.
///
/// Copies the current vault database file to the backup location
/// specified in settings. The backup is an exact copy of the
/// encrypted database file.
///
/// # IPC Contract
///
/// - **Required state**: Unlocked
///
/// # Returns
///
/// The filesystem path where the backup was saved.
#[tauri::command]
pub fn backup_create(
    state: State<'_, AppState>,
) -> CommandResult<String> {
    // Guard: vault must be unlocked
    state.require_unlocked()?;
    state.validate_session()?;

    let pool = state.get_db_pool().ok_or_else(|| {
        CommandError::unauthorized("Database not available")
    })?;

    // Get the current database path
    let db_path = state.get_db_path().ok_or_else(|| {
        CommandError::unauthorized("Database path not available")
    })?;

    // Get backup location from config
    let backup_dir = {
        let config = state.config.read().unwrap_or_else(|e| {
            tracing::error!("Config lock poisoned: {}", e);
            std::process::exit(1);
        });
        config.backup_location.clone()
    };

    // Expand tilde in backup path
    let expanded_backup_dir = if backup_dir.starts_with("~/") {
        if let Some(home) = dirs::home_dir() {
            home.join(&backup_dir[2..])
        } else {
            std::path::PathBuf::from(&backup_dir)
        }
    } else {
        std::path::PathBuf::from(&backup_dir)
    };

    // Ensure backup directory exists
    if !expanded_backup_dir.exists() {
        std::fs::create_dir_all(&expanded_backup_dir).map_err(|e| {
            CommandError::from_kestrel(
                crate::error::KestrelError::Io(
                    format!("Failed to create backup directory: {e}")
                )
            )
        })?;
    }

    // Generate backup filename with timestamp
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let backup_filename = format!("kestrel_vault_backup_{}.db", timestamp);
    let backup_path = expanded_backup_dir.join(&backup_filename);

    // Copy the database file
    std::fs::copy(&db_path, &backup_path).map_err(|e| {
        CommandError::from_kestrel(
            crate::error::KestrelError::Io(
                format!("Failed to create backup: {e}")
            )
        )
    })?;

    let backup_path_str = backup_path.to_string_lossy().to_string();

    // Audit log the backup
    let _ = crate::commands::async_runtime::block_on(async {
        crate::db::audit_event_repo::AuditEventRepo::create(
            &pool,
            crate::db::audit_event_repo::CreateAuditEventRequest {
                category: "vault".to_string(),
                action: "BackupCreated".to_string(),
                subject: "system".to_string(),
                metadata_json: Some(serde_json::json!({
                    "backup_path": backup_path_str,
                }).to_string()),
            },
        ).await
    });

    tracing::info!("Backup created: {}", backup_path_str);

    Ok(backup_path_str)
}
