//! Folder management Tauri commands for KESTREL Vault.
//!
//! Provides CRUD operations for organizing vault entries into folders.
//! Folder names are encrypted for privacy — the organizational structure
//! (parent-child relationships) is stored as plaintext.
//!
//! # Security
//!
//! - Folder names are encrypted with the DEK before storage
//! - Parent-child relationships are stored as plaintext IDs (not sensitive)
//! - All operations require the vault to be unlocked

use crate::commands::types::{
    validate_field, validate_uuid, CommandError, CommandResult,
    FolderResponse, MAX_FOLDER_NAME_LEN,
};
use crate::crypto::vault_crypto::VaultCryptoService;
use crate::db::folder_repo::FolderRepo;
use tauri::State;

use super::auth_commands::AppState;

/// Lists all folders with decrypted names.
#[tauri::command]
pub fn folder_list(
    state: State<'_, AppState>,
) -> CommandResult<Vec<FolderResponse>> {
    state.require_unlocked()?;
    state.validate_session()?;

    let dek = state.get_dek().ok_or_else(|| {
        CommandError::unauthorized("Vault is locked — DEK not available")
    })?;
    let pool = state.get_db_pool().ok_or_else(|| {
        CommandError::unauthorized("Database not available")
    })?;

    let folders = crate::commands::async_runtime::block_on(async {
        FolderRepo::list_all(&pool).await
    }).map_err(CommandError::from_kestrel)?;

    let crypto_service = VaultCryptoService::new_dek(&dek);

    let mut responses = Vec::new();
    for folder in folders {
        // Decrypt folder name
        let name = if folder.name.is_empty() {
            "(unnamed)".to_string()
        } else {
            match crypto_service.decrypt_field(&folder.id, "name", &folder.name) {
                Ok(decrypted) => String::from_utf8_lossy(&decrypted.plaintext).to_string(),
                Err(_) => "(decryption failed)".to_string(),
            }
        };

        let entry_count = crate::commands::async_runtime::block_on(async {
            FolderRepo::count_entries(&pool, &folder.id).await
        }).unwrap_or(0);

        responses.push(FolderResponse {
            id: folder.id,
            name,
            parent_id: folder.parent_id,
            entry_count,
            created_at: folder.created_at,
        });
    }

    Ok(responses)
}

/// Creates a new folder with an encrypted name.
#[tauri::command]
pub fn folder_create(
    name: String,
    parent_id: Option<String>,
    state: State<'_, AppState>,
) -> CommandResult<FolderResponse> {
    state.require_unlocked()?;
    state.validate_session()?;

    validate_field(&name, MAX_FOLDER_NAME_LEN, "Folder name")?;
    if let Some(ref pid) = parent_id {
        validate_uuid(pid, "parent_id")?;
    }

    let dek = state.get_dek().ok_or_else(|| {
        CommandError::unauthorized("Vault is locked — DEK not available")
    })?;
    let pool = state.get_db_pool().ok_or_else(|| {
        CommandError::unauthorized("Database not available")
    })?;

    // Generate folder ID first so we can use it as AAD context
    let folder_id = uuid::Uuid::new_v4().to_string();

    // Encrypt the folder name using the DEK
    let crypto_service = VaultCryptoService::new_dek(&dek);
    let encrypted = crypto_service.encrypt_field(&folder_id, "name", name.as_bytes())
        .map_err(CommandError::from_kestrel)?;

    // Extract nonce from envelope bytes: [version:1][nonce:12][ciphertext:N][tag:16]
    let nonce_bytes = if encrypted.envelope_bytes.len() > 13 {
        encrypted.envelope_bytes[1..13].to_vec()
    } else {
        return Err(CommandError::from_kestrel(
            crate::error::KestrelError::Crypto("Envelope too short to extract nonce".to_string())
        ));
    };

    let request = crate::db::folder_repo::CreateFolderRequest {
        encrypted_name: encrypted.envelope_bytes,
        nonce: nonce_bytes,
        parent_id,
    };

    let folder = crate::commands::async_runtime::block_on(async {
        FolderRepo::create(&pool, request).await
    }).map_err(CommandError::from_kestrel)?;

    Ok(FolderResponse {
        id: folder.id,
        name,
        parent_id: folder.parent_id,
        entry_count: 0,
        created_at: folder.created_at,
    })
}

/// Deletes a folder by ID.
///
/// Entries in the folder will have their folder_id set to NULL (orphaned).
#[tauri::command]
pub fn folder_delete(
    id: String,
    state: State<'_, AppState>,
) -> CommandResult<()> {
    state.require_unlocked()?;
    state.validate_session()?;

    validate_uuid(&id, "id")?;

    let pool = state.get_db_pool().ok_or_else(|| {
        CommandError::unauthorized("Database not available")
    })?;

    crate::commands::async_runtime::block_on(async {
        FolderRepo::delete(&pool, &id).await
    }).map_err(CommandError::from_kestrel)?;

    Ok(())
}
