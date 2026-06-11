//! Vault entry Tauri commands for KESTREL Vault.
//!
//! Provides CRUD operations for password vault entries.
//! All sensitive fields are encrypted in Rust — React never
//! sees passwords except through explicit reveal.
//!
//! # Security
//!
//! - Vault must be unlocked for all operations
//! - Auto-lock is checked before every operation
//! - Passwords are ONLY returned via `vault_reveal_password`
//! - All field encryption uses the DEK (not KEK)
//! - All modifications are audit-logged
//! - All inputs are validated
//! - Password strings use SecureString for zeroization
//!
//! # KEK/DEK Hierarchy in Vault Commands
//!
//! The vault commands use the DEK for field-level encryption:
//! - `VaultCryptoService::new_dek(&dek)` for encrypt/decrypt operations
//! - The KEK is only used for test envelope verification and DEK wrapping
//! - Sub-keys derived from the DEK via HKDF are used for specific purposes
//!
//! # IPC Contract
//!
//! | Command                | Required State | Effect            |
//! |------------------------|---------------|-------------------|
//! | vault_create_entry     | Unlocked      | Create + encrypt  |
//! | vault_get_entry        | Unlocked      | Read (no pwd)     |
//! | vault_update_entry     | Unlocked      | Update + encrypt  |
//! | vault_delete_entry     | Unlocked      | Delete            |
//! | vault_list_entries     | Unlocked      | List (no pwds)    |
//! | vault_search_entries   | Unlocked      | Search (no pwds)  |
//! | vault_reveal_password  | Unlocked      | Decrypt + audit   |

use crate::commands::types::{
    validate_field, validate_uuid, CommandError, CommandResult,
    PasswordRevealResponse, VaultEntryResponse,
    MAX_NOTES_LEN, MAX_TITLE_LEN, MAX_URL_LEN, MAX_USERNAME_LEN,
};
use crate::vault::entry::CreateEntryRequest;
use crate::vault::service::VaultServiceImpl;
use tauri::State;

use super::auth_commands::AppState;

/// Default auto-clear timeout for password reveals (in seconds).
#[allow(dead_code)]
const DEFAULT_AUTO_CLEAR_SECONDS: u32 = 30;

/// Creates a new vault entry.
///
/// The plaintext password is encrypted with the DEK before storage.
/// The response does NOT include the password.
///
/// # IPC Contract
///
/// - **Required state**: Unlocked
/// - **Effect**: Creates encrypted entry in database
///
/// # Security
///
/// - Auto-lock is checked before the operation
/// - Password is converted to SecureString for zeroization
/// - Field encryption uses the DEK (via VaultCryptoService::new_dek)
/// - Activity is recorded to extend the session
///
/// # Errors
///
/// - `UNAUTHORIZED`: Vault is locked or session expired
/// - `VALIDATION_ERROR`: Invalid input fields
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
    // Guard: vault must be unlocked
    state.require_unlocked()?;

    // Guard: check session validity / auto-lock
    state.validate_session()?;

    // Validate inputs
    validate_field(&title, MAX_TITLE_LEN, "Title")?;
    validate_field(&username, MAX_USERNAME_LEN, "Username")?;
    if password.is_empty() {
        return CommandResult::Err(CommandError::validation("Password is required"));
    }
    if password.len() > 1024 {
        return CommandResult::Err(CommandError::validation(
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

    // ── Get DEK for field-level encryption ──
    let dek = state.get_dek().ok_or_else(|| {
        CommandError::unauthorized("Vault is locked — DEK not available")
    })?;

    // ── Get database pool ──
    let pool = state.get_db_pool().ok_or_else(|| {
        CommandError::unauthorized("Database not available")
    })?;

    // ── Use VaultServiceImpl to create entry ──
    let service = VaultServiceImpl::new(&dek, pool);
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

    // ── Record activity (extends auto-lock timer) ──
    {
        let mut sm = state.vault_state_machine.write().unwrap_or_else(|e| {
            tracing::error!("Vault state machine lock poisoned: {}", e);
            std::process::exit(1);
        });
        sm.record_activity();
    }

    tracing::info!("Vault entry created: id={}", entry.id);

    CommandResult::ok(VaultEntryResponse {
        id: entry.id.to_string(),
        title: entry.title,
        username: entry.username,
        url: None, // URL is encrypted — frontend doesn't get it from list
        folder_id: entry.folder_id.map(|u| u.to_string()),
        has_totp: entry.has_totp(),
        notes_preview: None, // Notes are encrypted
        created_at: entry.created_at.to_rfc3339(),
        updated_at: entry.updated_at.to_rfc3339(),
    })
}

/// Retrieves a vault entry by ID.
///
/// Returns entry metadata — the password is NOT included.
/// Use `vault_reveal_password` to access the password.
///
/// # IPC Contract
///
/// - **Required state**: Unlocked
/// - **Effect**: Read-only
///
/// # Security
///
/// - Auto-lock is checked before the operation
/// - Activity is recorded to extend the session
///
/// # Errors
///
/// - `UNAUTHORIZED`: Vault is locked or session expired
/// - `VALIDATION_ERROR`: Invalid UUID
#[tauri::command]
pub fn vault_get_entry(
    id: String,
    state: State<'_, AppState>,
) -> CommandResult<VaultEntryResponse> {
    // Guard: vault must be unlocked
    state.require_unlocked()?;

    // Guard: check session validity / auto-lock
    state.validate_session()?;

    validate_uuid(&id, "id")?;

    // ── Get DEK and database ──
    let dek = state.get_dek().ok_or_else(|| {
        CommandError::unauthorized("Vault is locked — DEK not available")
    })?;
    let pool = state.get_db_pool().ok_or_else(|| {
        CommandError::unauthorized("Database not available")
    })?;

    // ── Load entry from database ──
    let entry_id = uuid::Uuid::parse_str(&id).map_err(|_| {
        CommandError::validation("Invalid entry UUID")
    })?;
    let service = VaultServiceImpl::new(&dek, pool);
    let entry = crate::commands::async_runtime::block_on(async {
        service.get_entry(entry_id).await
    }).map_err(CommandError::from_kestrel)?;

    // ── Record activity ──
    {
        let mut sm = state.vault_state_machine.write().unwrap_or_else(|e| {
            tracing::error!("Vault state machine lock poisoned: {}", e);
            std::process::exit(1);
        });
        sm.record_activity();
    }

    CommandResult::ok(VaultEntryResponse {
        id: entry.id.to_string(),
        title: entry.title,
        username: entry.username,
        url: None,
        folder_id: entry.folder_id.map(|u| u.to_string()),
        has_totp: entry.has_totp(),
        notes_preview: None,
        created_at: entry.created_at.to_rfc3339(),
        updated_at: entry.updated_at.to_rfc3339(),
    })
}

/// Updates an existing vault entry.
///
/// Only provided fields are updated. If a new password is
/// provided, it is encrypted with the DEK before storage.
///
/// # IPC Contract
///
/// - **Required state**: Unlocked
/// - **Effect**: Re-encrypt changed fields, update database
///
/// # Security
///
/// - Auto-lock is checked before the operation
/// - Password is converted to SecureString for zeroization
/// - Field encryption uses the DEK
/// - Activity is recorded to extend the session
/// - All modifications are audit-logged
///
/// # Errors
///
/// - `UNAUTHORIZED`: Vault is locked or session expired
/// - `VALIDATION_ERROR`: Invalid input fields
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
    // Guard: vault must be unlocked
    state.require_unlocked()?;

    // Guard: check session validity / auto-lock
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
            return CommandResult::Err(CommandError::validation(
                "Password cannot be empty",
            ));
        }
        if p.len() > 1024 {
            return CommandResult::Err(CommandError::validation(
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

    // ── Get DEK for field-level encryption ──
    let dek = state.get_dek().ok_or_else(|| {
        CommandError::unauthorized("Vault is locked — DEK not available")
    })?;

    // ── Get database pool ──
    let pool = state.get_db_pool().ok_or_else(|| {
        CommandError::unauthorized("Database not available")
    })?;

    // ── Use VaultServiceImpl to update entry ──
    let entry_id = uuid::Uuid::parse_str(&id).map_err(|_| {
        CommandError::validation("Invalid entry UUID")
    })?;

    let update_request = crate::vault::entry::UpdateEntryRequest {
        title,
        username,
        password,
        url,
        notes,
        folder_id: folder_id.map(|fid| {
            uuid::Uuid::parse_str(&fid).ok()
        }),
        tags,
    };

    let service = VaultServiceImpl::new(&dek, pool);
    let entry = crate::commands::async_runtime::block_on(async {
        service.update_entry(entry_id, update_request).await
    }).map_err(CommandError::from_kestrel)?;

    // ── Record activity (extends auto-lock timer) ──
    {
        let mut sm = state.vault_state_machine.write().unwrap_or_else(|e| {
            tracing::error!("Vault state machine lock poisoned: {}", e);
            std::process::exit(1);
        });
        sm.record_activity();
    }

    tracing::info!("Vault entry updated: id={}", entry.id);

    CommandResult::ok(VaultEntryResponse {
        id: entry.id.to_string(),
        title: entry.title,
        username: entry.username,
        url: None, // URL is encrypted — frontend doesn't get it from update
        folder_id: entry.folder_id.map(|u| u.to_string()),
        has_totp: entry.has_totp(),
        notes_preview: None, // Notes are encrypted
        created_at: entry.created_at.to_rfc3339(),
        updated_at: entry.updated_at.to_rfc3339(),
    })
}

/// Deletes a vault entry.
///
/// Requires confirmation to prevent accidental deletion.
///
/// # IPC Contract
///
/// - **Required state**: Unlocked
/// - **Effect**: Permanent deletion
///
/// # Security
///
/// - Auto-lock is checked before the operation
/// - Activity is recorded to extend the session
///
/// # Errors
///
/// - `UNAUTHORIZED`: Vault is locked or session expired
/// - `VALIDATION_ERROR`: Invalid UUID or missing confirmation
#[tauri::command]
pub fn vault_delete_entry(
    id: String,
    confirm: bool,
    state: State<'_, AppState>,
) -> CommandResult<()> {
    // Guard: vault must be unlocked
    state.require_unlocked()?;

    // Guard: check session validity / auto-lock
    state.validate_session()?;

    validate_uuid(&id, "id")?;
    if !confirm {
        return CommandResult::Err(CommandError::validation(
            "Deletion requires confirmation",
        ));
    }

    // ── Get DEK and database ──
    let dek = state.get_dek().ok_or_else(|| {
        CommandError::unauthorized("Vault is locked — DEK not available")
    })?;
    let pool = state.get_db_pool().ok_or_else(|| {
        CommandError::unauthorized("Database not available")
    })?;

    // ── Delete via service ──
    let entry_id = uuid::Uuid::parse_str(&id).map_err(|_| {
        CommandError::validation("Invalid entry UUID")
    })?;
    let service = VaultServiceImpl::new(&dek, pool);
    crate::commands::async_runtime::block_on(async {
        service.delete_entry(entry_id).await
    }).map_err(CommandError::from_kestrel)?;

    // ── Record activity ──
    {
        let mut sm = state.vault_state_machine.write().unwrap_or_else(|e| {
            tracing::error!("Vault state machine lock poisoned: {}", e);
            std::process::exit(1);
        });
        sm.record_activity();
    }

    tracing::info!("Vault entry deleted: id={}", id);

    CommandResult::ok(())
}

/// Lists vault entries with optional folder filtering.
///
/// Returns entry metadata only — no passwords.
///
/// # IPC Contract
///
/// - **Required state**: Unlocked
/// - **Effect**: Read-only
///
/// # Security
///
/// - Auto-lock is checked before the operation
/// - Activity is recorded to extend the session
///
/// # Errors
///
/// - `UNAUTHORIZED`: Vault is locked or session expired
#[tauri::command]
pub fn vault_list_entries(
    folder_id: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
    state: State<'_, AppState>,
) -> CommandResult<Vec<VaultEntryResponse>> {
    // Guard: vault must be unlocked
    state.require_unlocked()?;

    // Guard: check session validity / auto-lock
    state.validate_session()?;

    if let Some(ref fid) = folder_id {
        validate_uuid(fid, "folder_id")?;
    }
    let limit = limit.unwrap_or(50).min(200);
    let offset = offset.unwrap_or(0).max(0);

    // ── Get DEK and database ──
    let dek = state.get_dek().ok_or_else(|| {
        CommandError::unauthorized("Vault is locked — DEK not available")
    })?;
    let pool = state.get_db_pool().ok_or_else(|| {
        CommandError::unauthorized("Database not available")
    })?;

    // ── List entries via service ──
    let service = VaultServiceImpl::new(&dek, pool);
    let folder_uuid = folder_id.and_then(|s| uuid::Uuid::parse_str(&s).ok());
    let entries = crate::commands::async_runtime::block_on(async {
        service.list_entries(folder_uuid, limit, offset).await
    }).map_err(CommandError::from_kestrel)?;

    // ── Record activity ──
    {
        let mut sm = state.vault_state_machine.write().unwrap_or_else(|e| {
            tracing::error!("Vault state machine lock poisoned: {}", e);
            std::process::exit(1);
        });
        sm.record_activity();
    }

    // Map entries to responses (no passwords)
    let responses: Vec<VaultEntryResponse> = entries.into_iter().map(|e| VaultEntryResponse {
        id: e.id.to_string(),
        title: e.title,
        username: e.username,
        url: None,
        folder_id: e.folder_id.map(|u| u.to_string()),
        has_totp: e.has_totp(),
        notes_preview: None,
        created_at: e.created_at.to_rfc3339(),
        updated_at: e.updated_at.to_rfc3339(),
    }).collect();

    CommandResult::ok(responses)
}

/// Searches vault entries by title and username.
///
/// Search operates on plaintext metadata only (not encrypted fields).
///
/// # IPC Contract
///
/// - **Required state**: Unlocked
/// - **Effect**: Read-only
///
/// # Security
///
/// - Auto-lock is checked before the operation
/// - Activity is recorded to extend the session
///
/// # Errors
///
/// - `UNAUTHORIZED`: Vault is locked or session expired
/// - `VALIDATION_ERROR`: Query too long
#[tauri::command]
pub fn vault_search_entries(
    query: String,
    limit: Option<i64>,
    state: State<'_, AppState>,
) -> CommandResult<Vec<VaultEntryResponse>> {
    // Guard: vault must be unlocked
    state.require_unlocked()?;

    // Guard: check session validity / auto-lock
    state.validate_session()?;

    validate_field(&query, 256, "Query")?;
    let limit = limit.unwrap_or(50).min(200);

    // ── Get DEK and database ──
    let dek = state.get_dek().ok_or_else(|| {
        CommandError::unauthorized("Vault is locked — DEK not available")
    })?;
    let pool = state.get_db_pool().ok_or_else(|| {
        CommandError::unauthorized("Database not available")
    })?;

    // ── Search via service ──
    let service = VaultServiceImpl::new(&dek, pool);
    let entries = crate::commands::async_runtime::block_on(async {
        service.search_entries(&query, limit).await
    }).map_err(CommandError::from_kestrel)?;

    // ── Record activity ──
    {
        let mut sm = state.vault_state_machine.write().unwrap_or_else(|e| {
            tracing::error!("Vault state machine lock poisoned: {}", e);
            std::process::exit(1);
        });
        sm.record_activity();
    }

    let responses: Vec<VaultEntryResponse> = entries.into_iter().map(|e| VaultEntryResponse {
        id: e.id.to_string(),
        title: e.title,
        username: e.username,
        url: None,
        folder_id: e.folder_id.map(|u| u.to_string()),
        has_totp: e.has_totp(),
        notes_preview: None,
        created_at: e.created_at.to_rfc3339(),
        updated_at: e.updated_at.to_rfc3339(),
    }).collect();

    CommandResult::ok(responses)
}

/// Reveals the password for a specific entry.
///
/// This is the ONLY command that returns a decrypted password.
/// The frontend should auto-clear the password after a timeout.
///
/// # IPC Contract
///
/// - **Required state**: Unlocked
/// - **Effect**: Decrypt + audit log
///
/// # Security
///
/// - Auto-lock is checked before the operation
/// - Audit-logged (who revealed what and when)
/// - Auto-clear metadata included in response
/// - Should only be called on explicit user action
/// - Decryption uses the DEK (not KEK)
///
/// # Errors
///
/// - `UNAUTHORIZED`: Vault is locked or session expired
#[tauri::command]
pub fn vault_reveal_password(
    id: String,
    state: State<'_, AppState>,
) -> CommandResult<PasswordRevealResponse> {
    // Guard: vault must be unlocked
    state.require_unlocked()?;

    // Guard: check session validity / auto-lock
    state.validate_session()?;

    validate_uuid(&id, "id")?;

    // ── Get DEK and database ──
    let dek = state.get_dek().ok_or_else(|| {
        CommandError::unauthorized("Vault is locked — DEK not available")
    })?;
    let pool = state.get_db_pool().ok_or_else(|| {
        CommandError::unauthorized("Database not available")
    })?;

    // ── Reveal password via service ──
    let entry_id = uuid::Uuid::parse_str(&id).map_err(|_| {
        CommandError::validation("Invalid entry UUID")
    })?;
    let service = VaultServiceImpl::new(&dek, pool);
    let decrypted = crate::commands::async_runtime::block_on(async {
        service.reveal_password(entry_id).await
    }).map_err(CommandError::from_kestrel)?;

    // Convert decrypted bytes to String
    let password_string = String::from_utf8(decrypted.plaintext.clone())
        .map_err(|_| CommandError::from_kestrel(
            crate::error::KestrelError::Crypto("Password is not valid UTF-8".to_string())
        ))?;

    // ── Record activity ──
    {
        let mut sm = state.vault_state_machine.write().unwrap_or_else(|e| {
            tracing::error!("Vault state machine lock poisoned: {}", e);
            std::process::exit(1);
        });
        sm.record_activity();
    }

    tracing::warn!("Password reveal completed for entry: {}", id);
    // decrypted is zeroized when it goes out of scope

    CommandResult::ok(PasswordRevealResponse {
        password: password_string,
        auto_clear_seconds: DEFAULT_AUTO_CLEAR_SECONDS,
    })
}
