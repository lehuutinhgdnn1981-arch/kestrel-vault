//! Vault entry Tauri commands for KESTREL Vault.
//!
//! Provides CRUD operations for password vault entries.
//! All sensitive fields are encrypted in Rust — React never
//! sees passwords except through explicit reveal.

use crate::commands::types::{
    validate_field, validate_uuid, CommandError, CommandResult,
    PasswordRevealResponse, VaultEntryResponse,
    MAX_TITLE_LEN, MAX_URL_LEN, MAX_USERNAME_LEN, MAX_NOTES_LEN,
};
use crate::vault::entry::CreateEntryRequest;
use crate::vault::service::VaultServiceImpl;
use tauri::State;

use super::auth_commands::AppState;

/// Default auto-clear timeout for password reveals (in seconds).
#[allow(dead_code)]
const DEFAULT_AUTO_CLEAR_SECONDS: u32 = 30;

/// Creates a new vault entry.
#[tauri::command]
pub fn vault_create_entry(
    title: String,
    username: String,
    password: String,
    url: Option<String>,
    notes: Option<String>,
    folder_id: Option<String>,
    tags: Vec<String>,
    state: State<'_, AppState>,
) -> CommandResult<VaultEntryResponse> {
    state.require_unlocked()?;
    state.validate_session()?;

    validate_field(&title, MAX_TITLE_LEN, "Title")?;
    validate_field(&username, MAX_USERNAME_LEN, "Username")?;
    if password.is_empty() {
        return Err(CommandError::validation("Password is required"));
    }
    if password.len() > 1024 {
        return Err(CommandError::validation(
            "Password must be at most 1024 characters",
        ));
    }
    if let Some(ref u) = url {
        validate_field(u, MAX_URL_LEN, "URL")?;
    }
    if let Some(ref n) = notes {
        validate_field(n, MAX_NOTES_LEN, "Notes")?;
    }
    if let Some(ref fid) = folder_id {
        validate_uuid(fid, "folder_id")?;
    }
    for tag in &tags {
        validate_field(tag, 64, "Tag")?;
    }

    let dek = state.get_dek().ok_or_else(|| {
        CommandError::unauthorized("Vault is locked — DEK not available")
    })?;

    let pool = state.get_db_pool().ok_or_else(|| {
        CommandError::unauthorized("Database not available")
    })?;

    let service = VaultServiceImpl::new(&dek, &pool);
    let create_request = CreateEntryRequest {
        title: title.clone(),
        username: username.clone(),
        password,
        url,
        notes,
        folder_id: folder_id.and_then(|s| uuid::Uuid::parse_str(&s).ok()),
        tags,
    };

    let entry = crate::commands::async_runtime::block_on(async {
        service.create_entry(create_request).await
    }).map_err(CommandError::from_kestrel)?;

    {
        let mut sm = state.vault_state_machine.write().unwrap_or_else(|e| {
            tracing::error!("Vault state machine lock poisoned: {}", e);
            std::process::exit(1);
        });
        sm.record_activity();
    }

    tracing::info!("Vault entry created: id={}", entry.id);

    Ok(VaultEntryResponse {
        id: entry.id.to_string(),
        title: entry.title.clone(),
        username: entry.username.clone(),
        url: None,
        folder_id: entry.folder_id.map(|u| u.to_string()),
        has_totp: entry.has_totp(),
        notes_preview: None,
        created_at: entry.created_at.to_rfc3339(),
        updated_at: entry.updated_at.to_rfc3339(),
    })
}

/// Retrieves a vault entry by ID.
#[tauri::command]
pub fn vault_get_entry(
    id: String,
    state: State<'_, AppState>,
) -> CommandResult<VaultEntryResponse> {
    state.require_unlocked()?;
    state.validate_session()?;

    validate_uuid(&id, "id")?;

    let dek = state.get_dek().ok_or_else(|| {
        CommandError::unauthorized("Vault is locked — DEK not available")
    })?;
    let pool = state.get_db_pool().ok_or_else(|| {
        CommandError::unauthorized("Database not available")
    })?;

    let entry_id = uuid::Uuid::parse_str(&id).map_err(|_| {
        CommandError::validation("Invalid entry UUID")
    })?;
    let service = VaultServiceImpl::new(&dek, &pool);
    let entry = crate::commands::async_runtime::block_on(async {
        service.get_entry(entry_id).await
    }).map_err(CommandError::from_kestrel)?;

    {
        let mut sm = state.vault_state_machine.write().unwrap_or_else(|e| {
            tracing::error!("Vault state machine lock poisoned: {}", e);
            std::process::exit(1);
        });
        sm.record_activity();
    }

    Ok(VaultEntryResponse {
        id: entry.id.to_string(),
        title: entry.title.clone(),
        username: entry.username.clone(),
        url: None,
        folder_id: entry.folder_id.map(|u| u.to_string()),
        has_totp: entry.has_totp(),
        notes_preview: None,
        created_at: entry.created_at.to_rfc3339(),
        updated_at: entry.updated_at.to_rfc3339(),
    })
}

/// Updates an existing vault entry.
#[tauri::command]
pub fn vault_update_entry(
    id: String,
    title: Option<String>,
    username: Option<String>,
    password: Option<String>,
    url: Option<String>,
    notes: Option<String>,
    folder_id: Option<String>,
    tags: Option<Vec<String>>,
    state: State<'_, AppState>,
) -> CommandResult<VaultEntryResponse> {
    state.require_unlocked()?;
    state.validate_session()?;

    validate_uuid(&id, "id")?;
    if let Some(ref t) = title {
        validate_field(t, MAX_TITLE_LEN, "Title")?;
    }
    if let Some(ref u) = username {
        validate_field(u, MAX_USERNAME_LEN, "Username")?;
    }
    if let Some(ref p) = password {
        if p.is_empty() {
            return Err(CommandError::validation(
                "Password cannot be empty",
            ));
        }
        if p.len() > 1024 {
            return Err(CommandError::validation(
                "Password must be at most 1024 characters",
            ));
        }
    }
    if let Some(ref u) = url {
        validate_field(u, MAX_URL_LEN, "URL")?;
    }
    if let Some(ref n) = notes {
        validate_field(n, MAX_NOTES_LEN, "Notes")?;
    }
    if let Some(ref fid) = folder_id {
        validate_uuid(fid, "folder_id")?;
    }
    if let Some(ref tag_list) = tags {
        for tag in tag_list {
            validate_field(tag, 64, "Tag")?;
        }
    }

    let dek = state.get_dek().ok_or_else(|| {
        CommandError::unauthorized("Vault is locked — DEK not available")
    })?;
    let pool = state.get_db_pool().ok_or_else(|| {
        CommandError::unauthorized("Database not available")
    })?;

    let entry_id = uuid::Uuid::parse_str(&id).map_err(|_| {
        CommandError::validation("Invalid entry UUID")
    })?;

    let update_request = crate::vault::entry::UpdateEntryRequest {
        title,
        username,
        password,
        url,
        notes,
        // Fix: .and_then instead of .map to avoid Option<Option<Uuid>>
        folder_id: folder_id.and_then(|fid| {
            uuid::Uuid::parse_str(&fid).ok()
        }),
        tags,
    };

    let service = VaultServiceImpl::new(&dek, &pool);
    let entry = crate::commands::async_runtime::block_on(async {
        service.update_entry(entry_id, update_request).await
    }).map_err(CommandError::from_kestrel)?;

    {
        let mut sm = state.vault_state_machine.write().unwrap_or_else(|e| {
            tracing::error!("Vault state machine lock poisoned: {}", e);
            std::process::exit(1);
        });
        sm.record_activity();
    }

    tracing::info!("Vault entry updated: id={}", entry.id);

    Ok(VaultEntryResponse {
        id: entry.id.to_string(),
        title: entry.title.clone(),
        username: entry.username.clone(),
        url: None,
        folder_id: entry.folder_id.map(|u| u.to_string()),
        has_totp: entry.has_totp(),
        notes_preview: None,
        created_at: entry.created_at.to_rfc3339(),
        updated_at: entry.updated_at.to_rfc3339(),
    })
}

/// Deletes a vault entry.
#[tauri::command]
pub fn vault_delete_entry(
    id: String,
    confirm: bool,
    state: State<'_, AppState>,
) -> CommandResult<()> {
    state.require_unlocked()?;
    state.validate_session()?;

    validate_uuid(&id, "id")?;
    if !confirm {
        return Err(CommandError::validation(
            "Deletion requires confirmation",
        ));
    }

    let dek = state.get_dek().ok_or_else(|| {
        CommandError::unauthorized("Vault is locked — DEK not available")
    })?;
    let pool = state.get_db_pool().ok_or_else(|| {
        CommandError::unauthorized("Database not available")
    })?;

    let entry_id = uuid::Uuid::parse_str(&id).map_err(|_| {
        CommandError::validation("Invalid entry UUID")
    })?;
    let service = VaultServiceImpl::new(&dek, &pool);
    crate::commands::async_runtime::block_on(async {
        service.delete_entry(entry_id).await
    }).map_err(CommandError::from_kestrel)?;

    {
        let mut sm = state.vault_state_machine.write().unwrap_or_else(|e| {
            tracing::error!("Vault state machine lock poisoned: {}", e);
            std::process::exit(1);
        });
        sm.record_activity();
    }

    tracing::info!("Vault entry deleted: id={}", id);

    Ok(())
}

/// Lists vault entries with optional folder filtering.
#[tauri::command]
pub fn vault_list_entries(
    folder_id: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
    state: State<'_, AppState>,
) -> CommandResult<Vec<VaultEntryResponse>> {
    state.require_unlocked()?;
    state.validate_session()?;

    if let Some(ref fid) = folder_id {
        validate_uuid(fid, "folder_id")?;
    }
    let limit = limit.unwrap_or(50).min(200);
    let offset = offset.unwrap_or(0).max(0);

    let dek = state.get_dek().ok_or_else(|| {
        CommandError::unauthorized("Vault is locked — DEK not available")
    })?;
    let pool = state.get_db_pool().ok_or_else(|| {
        CommandError::unauthorized("Database not available")
    })?;

    let service = VaultServiceImpl::new(&dek, &pool);
    let folder_uuid = folder_id.and_then(|s| uuid::Uuid::parse_str(&s).ok());
    let entries = crate::commands::async_runtime::block_on(async {
        service.list_entries(folder_uuid, limit, offset).await
    }).map_err(CommandError::from_kestrel)?;

    {
        let mut sm = state.vault_state_machine.write().unwrap_or_else(|e| {
            tracing::error!("Vault state machine lock poisoned: {}", e);
            std::process::exit(1);
        });
        sm.record_activity();
    }

    let responses: Vec<VaultEntryResponse> = entries.into_iter().map(|e| VaultEntryResponse {
        id: e.id.to_string(),
        title: e.title.clone(),
        username: e.username.clone(),
        url: None,
        folder_id: e.folder_id.map(|u| u.to_string()),
        has_totp: e.has_totp(),
        notes_preview: None,
        created_at: e.created_at.to_rfc3339(),
        updated_at: e.updated_at.to_rfc3339(),
    }).collect();

    Ok(responses)
}

/// Searches vault entries by title and username.
#[tauri::command]
pub fn vault_search_entries(
    query: String,
    limit: Option<i64>,
    state: State<'_, AppState>,
) -> CommandResult<Vec<VaultEntryResponse>> {
    state.require_unlocked()?;
    state.validate_session()?;

    validate_field(&query, 256, "Query")?;
    let limit = limit.unwrap_or(50).min(200);

    let dek = state.get_dek().ok_or_else(|| {
        CommandError::unauthorized("Vault is locked — DEK not available")
    })?;
    let pool = state.get_db_pool().ok_or_else(|| {
        CommandError::unauthorized("Database not available")
    })?;

    let service = VaultServiceImpl::new(&dek, &pool);
    let entries = crate::commands::async_runtime::block_on(async {
        service.search_entries(&query, limit).await
    }).map_err(CommandError::from_kestrel)?;

    {
        let mut sm = state.vault_state_machine.write().unwrap_or_else(|e| {
            tracing::error!("Vault state machine lock poisoned: {}", e);
            std::process::exit(1);
        });
        sm.record_activity();
    }

    let responses: Vec<VaultEntryResponse> = entries.into_iter().map(|e| VaultEntryResponse {
        id: e.id.to_string(),
        title: e.title.clone(),
        username: e.username.clone(),
        url: None,
        folder_id: e.folder_id.map(|u| u.to_string()),
        has_totp: e.has_totp(),
        notes_preview: None,
        created_at: e.created_at.to_rfc3339(),
        updated_at: e.updated_at.to_rfc3339(),
    }).collect();

    Ok(responses)
}

/// Reveals the password for a specific entry.
#[tauri::command]
pub fn vault_reveal_password(
    id: String,
    state: State<'_, AppState>,
) -> CommandResult<PasswordRevealResponse> {
    state.require_unlocked()?;
    state.validate_session()?;

    validate_uuid(&id, "id")?;

    let dek = state.get_dek().ok_or_else(|| {
        CommandError::unauthorized("Vault is locked — DEK not available")
    })?;
    let pool = state.get_db_pool().ok_or_else(|| {
        CommandError::unauthorized("Database not available")
    })?;

    let entry_id = uuid::Uuid::parse_str(&id).map_err(|_| {
        CommandError::validation("Invalid entry UUID")
    })?;
    let service = VaultServiceImpl::new(&dek, &pool);
    let decrypted = crate::commands::async_runtime::block_on(async {
        service.reveal_password(entry_id).await
    }).map_err(CommandError::from_kestrel)?;

    let password_string = String::from_utf8(decrypted.plaintext.clone())
        .map_err(|_| CommandError::from_kestrel(
            crate::error::KestrelError::Crypto("Password is not valid UTF-8".to_string())
        ))?;

    {
        let mut sm = state.vault_state_machine.write().unwrap_or_else(|e| {
            tracing::error!("Vault state machine lock poisoned: {}", e);
            std::process::exit(1);
        });
        sm.record_activity();
    }

    tracing::warn!("Password reveal completed for entry: {}", id);

    Ok(PasswordRevealResponse {
        password: password_string,
        auto_clear_seconds: DEFAULT_AUTO_CLEAR_SECONDS,
    })
}
