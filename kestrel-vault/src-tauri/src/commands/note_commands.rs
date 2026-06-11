//! Secure note Tauri commands for KESTREL Vault.
//!
//! Provides CRUD operations for secure notes. Both title and content
//! are encrypted — unlike vault entries where title/username are
//! plaintext for search. Secure notes require explicit reveal to
//! access decrypted content.
//!
//! # Security
//!
//! - Vault must be unlocked for all operations
//! - Auto-lock is checked before every operation
//! - Note content is ONLY returned via `note_reveal`
//! - All field encryption uses the DEK (not KEK)
//! - All modifications are audit-logged
//! - All inputs are validated
//!
//! # IPC Contract
//!
//! | Command          | Required State | Effect            |
//! |------------------|---------------|-------------------|
//! | note_create      | Unlocked      | Create + encrypt  |
//! | note_list        | Unlocked      | List (titles only)|
//! | note_get         | Unlocked      | Read (no content) |
//! | note_update      | Unlocked      | Update + encrypt  |
//! | note_delete      | Unlocked      | Delete            |
//! | note_reveal      | Unlocked      | Decrypt + audit   |

use crate::commands::types::{
    validate_field, validate_uuid, CommandError, CommandResult,
    SecureNoteResponse, SecureNoteRevealResponse,
    MAX_NOTES_LEN, MAX_TITLE_LEN,
};
use crate::vault::service::VaultServiceImpl;
use tauri::State;

use super::auth_commands::AppState;

/// Default auto-clear timeout for note reveals (in seconds).
const DEFAULT_AUTO_CLEAR_SECONDS: u32 = 60;

/// Maximum length for note content.
const MAX_CONTENT_LEN: usize = 100_000;

/// Creates a new secure note.
///
/// Both the title and content are encrypted with the DEK before storage.
/// The response does NOT include the content.
///
/// # IPC Contract
///
/// - **Required state**: Unlocked
/// - **Effect**: Creates encrypted note in database
///
/// # Errors
///
/// - `UNAUTHORIZED`: Vault is locked or session expired
/// - `VALIDATION_ERROR`: Invalid input fields
#[tauri::command]
pub fn note_create(
    title: String,
    content: String,
    folder_id: Option<String>,
    tags: Vec<String>,
    state: State<'_, AppState>,
) -> CommandResult<SecureNoteResponse> {
    // Guard: vault must be unlocked
    state.require_unlocked()?;
    state.validate_session()?;

    // Validate inputs
    validate_field(&title, MAX_TITLE_LEN, "Title")?;
    if content.is_empty() {
        return CommandResult::Err(CommandError::validation("Content is required"));
    }
    validate_field(&content, MAX_CONTENT_LEN, "Content")?;
    if let Some(ref fid) = folder_id {
        validate_uuid(fid, "folder_id")?;
    }
    for tag in &tags {
        validate_field(tag, 64, "Tag")?;
    }

    // Get DEK for field-level encryption
    let dek = state.get_dek().ok_or_else(|| {
        CommandError::unauthorized("Vault is locked — DEK not available")
    })?;

    // Get database pool
    let pool = state.get_db_pool().ok_or_else(|| {
        CommandError::unauthorized("Database not available")
    })?;

    // Use VaultServiceImpl to create note
    let service = VaultServiceImpl::new(&dek, pool);
    let folder_uuid = folder_id.and_then(|s| uuid::Uuid::parse_str(&s).ok());

    let row = crate::commands::async_runtime::block_on(async {
        service.create_note(&title, &content, folder_uuid, tags).await
    }).map_err(CommandError::from_kestrel)?;

    // Record activity
    {
        let mut sm = state.vault_state_machine.write().unwrap_or_else(|e| {
            tracing::error!("Vault state machine lock poisoned: {}", e);
            std::process::exit(1);
        });
        sm.record_activity();
    }

    tracing::info!("Secure note created: id={}", row.id);

    // Decrypt title for the response
    let decrypted_title = crate::commands::async_runtime::block_on(async {
        service.decrypt_note_title(&row.id, &row.title).await
    }).unwrap_or_else(|_| "<Encrypted>".to_string());

    CommandResult::ok(SecureNoteResponse {
        id: row.id,
        title: decrypted_title,
        has_content: !row.content.is_empty(),
        folder_id: row.folder_id,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

/// Lists secure notes with optional folder filtering.
///
/// Returns note metadata with decrypted titles. Content is NOT included.
///
/// # IPC Contract
///
/// - **Required state**: Unlocked
/// - **Effect**: Read-only
#[tauri::command]
pub fn note_list(
    folder_id: Option<String>,
    state: State<'_, AppState>,
) -> CommandResult<Vec<SecureNoteResponse>> {
    // Guard: vault must be unlocked
    state.require_unlocked()?;
    state.validate_session()?;

    if let Some(ref fid) = folder_id {
        validate_uuid(fid, "folder_id")?;
    }

    // Get DEK and database
    let dek = state.get_dek().ok_or_else(|| {
        CommandError::unauthorized("Vault is locked — DEK not available")
    })?;
    let pool = state.get_db_pool().ok_or_else(|| {
        CommandError::unauthorized("Database not available")
    })?;

    let service = VaultServiceImpl::new(&dek, pool);
    let folder_uuid = folder_id.and_then(|s| uuid::Uuid::parse_str(&s).ok());

    let rows = crate::commands::async_runtime::block_on(async {
        service.list_notes(folder_uuid).await
    }).map_err(CommandError::from_kestrel)?;

    // Record activity
    {
        let mut sm = state.vault_state_machine.write().unwrap_or_else(|e| {
            tracing::error!("Vault state machine lock poisoned: {}", e);
            std::process::exit(1);
        });
        sm.record_activity();
    }

    // Decrypt titles for display
    let responses: Vec<SecureNoteResponse> = rows.iter().map(|row| {
        let title = crate::commands::async_runtime::block_on(async {
            service.decrypt_note_title(&row.id, &row.title).await
        }).unwrap_or_else(|_| "<Encrypted>".to_string());

        SecureNoteResponse {
            id: row.id.clone(),
            title,
            has_content: !row.content.is_empty(),
            folder_id: row.folder_id.clone(),
            created_at: row.created_at.clone(),
            updated_at: row.updated_at.clone(),
        }
    }).collect();

    CommandResult::ok(responses)
}

/// Gets a single secure note by ID.
///
/// Returns note metadata with decrypted title. Content is NOT included.
/// Use `note_reveal` to access the content.
///
/// # IPC Contract
///
/// - **Required state**: Unlocked
/// - **Effect**: Read-only
#[tauri::command]
pub fn note_get(
    id: String,
    state: State<'_, AppState>,
) -> CommandResult<SecureNoteResponse> {
    // Guard: vault must be unlocked
    state.require_unlocked()?;
    state.validate_session()?;

    validate_uuid(&id, "id")?;

    let dek = state.get_dek().ok_or_else(|| {
        CommandError::unauthorized("Vault is locked — DEK not available")
    })?;
    let pool = state.get_db_pool().ok_or_else(|| {
        CommandError::unauthorized("Database not available")
    })?;

    let note_id = uuid::Uuid::parse_str(&id).map_err(|_| {
        CommandError::validation("Invalid note UUID")
    })?;

    let service = VaultServiceImpl::new(&dek, pool);
    let row = crate::commands::async_runtime::block_on(async {
        service.get_note(note_id).await
    }).map_err(CommandError::from_kestrel)?;

    // Record activity
    {
        let mut sm = state.vault_state_machine.write().unwrap_or_else(|e| {
            tracing::error!("Vault state machine lock poisoned: {}", e);
            std::process::exit(1);
        });
        sm.record_activity();
    }

    // Decrypt title for display
    let decrypted_title = crate::commands::async_runtime::block_on(async {
        service.decrypt_note_title(&row.id, &row.title).await
    }).unwrap_or_else(|_| "<Encrypted>".to_string());

    CommandResult::ok(SecureNoteResponse {
        id: row.id,
        title: decrypted_title,
        has_content: !row.content.is_empty(),
        folder_id: row.folder_id,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

/// Updates an existing secure note.
///
/// Only provided fields are updated. Changed fields are re-encrypted
/// with fresh nonces.
///
/// # IPC Contract
///
/// - **Required state**: Unlocked
/// - **Effect**: Re-encrypt changed fields, update database
#[tauri::command]
pub fn note_update(
    id: String,
    title: Option<String>,
    content: Option<String>,
    folder_id: Option<String>,
    tags: Option<Vec<String>>,
    state: State<'_, AppState>,
) -> CommandResult<SecureNoteResponse> {
    // Guard: vault must be unlocked
    state.require_unlocked()?;
    state.validate_session()?;

    validate_uuid(&id, "id")?;
    if let Some(ref t) = title {
        validate_field(t, MAX_TITLE_LEN, "Title")?;
    }
    if let Some(ref c) = content {
        validate_field(c, MAX_CONTENT_LEN, "Content")?;
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

    let note_id = uuid::Uuid::parse_str(&id).map_err(|_| {
        CommandError::validation("Invalid note UUID")
    })?;

    let service = VaultServiceImpl::new(&dek, pool);

    // Parse folder_id: Some("null") means remove from folder, Some(uuid) means assign
    let parsed_folder_id = folder_id.map(|fid| {
        if fid == "null" || fid.is_empty() {
            None
        } else {
            uuid::Uuid::parse_str(&fid).ok()
        }
    });

    let row = crate::commands::async_runtime::block_on(async {
        service.update_note(note_id, title, content, parsed_folder_id, tags).await
    }).map_err(CommandError::from_kestrel)?;

    // Record activity
    {
        let mut sm = state.vault_state_machine.write().unwrap_or_else(|e| {
            tracing::error!("Vault state machine lock poisoned: {}", e);
            std::process::exit(1);
        });
        sm.record_activity();
    }

    tracing::info!("Secure note updated: id={}", row.id);

    // Decrypt title for the response
    let decrypted_title = crate::commands::async_runtime::block_on(async {
        service.decrypt_note_title(&row.id, &row.title).await
    }).unwrap_or_else(|_| "<Encrypted>".to_string());

    CommandResult::ok(SecureNoteResponse {
        id: row.id,
        title: decrypted_title,
        has_content: !row.content.is_empty(),
        folder_id: row.folder_id,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

/// Deletes a secure note.
///
/// Requires confirmation to prevent accidental deletion.
///
/// # IPC Contract
///
/// - **Required state**: Unlocked
/// - **Effect**: Permanent deletion
#[tauri::command]
pub fn note_delete(
    id: String,
    confirm: bool,
    state: State<'_, AppState>,
) -> CommandResult<()> {
    // Guard: vault must be unlocked
    state.require_unlocked()?;
    state.validate_session()?;

    validate_uuid(&id, "id")?;
    if !confirm {
        return CommandResult::Err(CommandError::validation(
            "Deletion requires confirmation",
        ));
    }

    let dek = state.get_dek().ok_or_else(|| {
        CommandError::unauthorized("Vault is locked — DEK not available")
    })?;
    let pool = state.get_db_pool().ok_or_else(|| {
        CommandError::unauthorized("Database not available")
    })?;

    let note_id = uuid::Uuid::parse_str(&id).map_err(|_| {
        CommandError::validation("Invalid note UUID")
    })?;

    let service = VaultServiceImpl::new(&dek, pool);
    crate::commands::async_runtime::block_on(async {
        service.delete_note(note_id).await
    }).map_err(CommandError::from_kestrel)?;

    // Record activity
    {
        let mut sm = state.vault_state_machine.write().unwrap_or_else(|e| {
            tracing::error!("Vault state machine lock poisoned: {}", e);
            std::process::exit(1);
        });
        sm.record_activity();
    }

    tracing::info!("Secure note deleted: id={}", id);

    CommandResult::ok(())
}

/// Reveals the content of a secure note.
///
/// This is the ONLY command that returns decrypted note content.
/// The frontend should auto-clear the content after a timeout.
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
#[tauri::command]
pub fn note_reveal(
    id: String,
    state: State<'_, AppState>,
) -> CommandResult<SecureNoteRevealResponse> {
    // Guard: vault must be unlocked
    state.require_unlocked()?;
    state.validate_session()?;

    validate_uuid(&id, "id")?;

    let dek = state.get_dek().ok_or_else(|| {
        CommandError::unauthorized("Vault is locked — DEK not available")
    })?;
    let pool = state.get_db_pool().ok_or_else(|| {
        CommandError::unauthorized("Database not available")
    })?;

    let note_id = uuid::Uuid::parse_str(&id).map_err(|_| {
        CommandError::validation("Invalid note UUID")
    })?;

    let service = VaultServiceImpl::new(&dek, pool);
    let (decrypted_title, decrypted_content) = crate::commands::async_runtime::block_on(async {
        service.reveal_note(note_id).await
    }).map_err(CommandError::from_kestrel)?;

    // Convert to strings
    let title_string = String::from_utf8(decrypted_title.plaintext.clone())
        .map_err(|_| CommandError::from_kestrel(
            crate::error::KestrelError::Crypto("Note title is not valid UTF-8".to_string())
        ))?;
    let content_string = String::from_utf8(decrypted_content.plaintext.clone())
        .map_err(|_| CommandError::from_kestrel(
            crate::error::KestrelError::Crypto("Note content is not valid UTF-8".to_string())
        ))?;

    // Record activity
    {
        let mut sm = state.vault_state_machine.write().unwrap_or_else(|e| {
            tracing::error!("Vault state machine lock poisoned: {}", e);
            std::process::exit(1);
        });
        sm.record_activity();
    }

    tracing::warn!("Note content reveal completed for note: {}", id);

    CommandResult::ok(SecureNoteRevealResponse {
        id,
        title: title_string,
        content: content_string,
        auto_clear_seconds: DEFAULT_AUTO_CLEAR_SECONDS,
    })
}
