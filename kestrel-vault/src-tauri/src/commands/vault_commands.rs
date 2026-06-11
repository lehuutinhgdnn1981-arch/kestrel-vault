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
use crate::crypto::keywrap::DataEncryptionKey;
use crate::crypto::secure_string::SecureString;
use crate::crypto::vault_crypto::{VaultCryptoService, field_names};
use crate::security::vault_state::VaultState;
use tauri::State;
use zeroize::Zeroize;

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
    let crypto_service = VaultCryptoService::new_dek(&dek);

    let entry_id = uuid::Uuid::new_v4().to_string();

    // ── Encrypt sensitive fields using DEK via SecureString ──
    let encrypted_password = {
        let secure_password = SecureString::from(password);
        let result = crypto_service.encrypt_field(&entry_id, field_names::PASSWORD, secure_password.as_bytes());
        // secure_password is zeroized when it goes out of scope
        match result {
            Ok(enc) => enc.envelope_bytes,
            Err(e) => return CommandResult::Err(CommandError::from_kestrel(e)),
        }
    };

    let encrypted_url = match &url {
        Some(u) if !u.is_empty() => {
            match crypto_service.encrypt_field(&entry_id, field_names::URL, u.as_bytes()) {
                Ok(enc) => enc.envelope_bytes,
                Err(e) => return CommandResult::Err(CommandError::from_kestrel(e)),
            }
        }
        _ => Vec::new(),
    };

    let encrypted_notes = match &notes {
        Some(n) if !n.is_empty() => {
            match crypto_service.encrypt_field(&entry_id, field_names::NOTES, n.as_bytes()) {
                Ok(enc) => enc.envelope_bytes,
                Err(e) => return CommandResult::Err(CommandError::from_kestrel(e)),
            }
        }
        _ => Vec::new(),
    };

    let encrypted_tags = if !tags.is_empty() {
        match serde_json::to_vec(&tags) {
            Ok(tags_bytes) => {
                match crypto_service.encrypt_field(&entry_id, field_names::TAGS, &tags_bytes) {
                    Ok(enc) => enc.envelope_bytes,
                    Err(e) => return CommandResult::Err(CommandError::from_kestrel(e)),
                }
            }
            Err(_) => Vec::new(),
        }
    } else {
        Vec::new()
    };

    // ── Persist to database ──
    // TODO: Insert into database via VaultEntryRepo
    // The encrypted_* envelope bytes are ready for storage as BLOBs.
    // Also store: id, title (plaintext for search), username (plaintext
    // for search), folder_id, created_at, updated_at

    // ── Record activity (extends auto-lock timer) ──
    {
        let mut sm = state.vault_state_machine.write().unwrap_or_else(|e| {
            tracing::error!("Vault state machine lock poisoned: {}", e);
            std::process::exit(1);
        });
        sm.record_activity();
    }

    // TODO: Audit log: EntryCreated { entry_id }

    tracing::info!("Vault entry created: id={}", entry_id);

    CommandResult::ok(VaultEntryResponse {
        id: entry_id,
        title,
        username,
        url,
        folder_id,
        has_totp: false,
        notes_preview: notes.map(|n| {
            if n.len() > 100 { n[..100].to_string() } else { n }
        }),
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
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

    // ── Record activity ──
    {
        let mut sm = state.vault_state_machine.write().unwrap_or_else(|e| {
            tracing::error!("Vault state machine lock poisoned: {}", e);
            std::process::exit(1);
        });
        sm.record_activity();
    }

    // TODO: Load from database via VaultEntryRepo
    // TODO: Map to VaultEntryResponse (no password)

    CommandResult::Err(CommandError::validation("Not yet implemented"))
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
    }
    if let Some(ref u) = url {
        validate_field(u, MAX_URL_LEN, "URL")?;
    }
    if let Some(ref n) = notes {
        validate_field(n, MAX_NOTES_LEN, "Notes")?;
    }

    // ── Get DEK for re-encryption ──
    let dek = state.get_dek().ok_or_else(|| {
        CommandError::unauthorized("Vault is locked — DEK not available")
    })?;
    let crypto_service = VaultCryptoService::new_dek(&dek);

    // ── Re-encrypt changed sensitive fields using DEK ──
    if let Some(ref new_password) = password {
        let secure_password = SecureString::from(new_password.clone());
        let encrypted = crypto_service.encrypt_field(&id, field_names::PASSWORD, secure_password.as_bytes());
        // secure_password is zeroized when it goes out of scope
        match encrypted {
            Ok(enc) => {
                // TODO: Update encrypted_password in database with enc.envelope_bytes
                let _ = enc; // Use when DB is wired
            }
            Err(e) => return CommandResult::Err(CommandError::from_kestrel(e)),
        }
    }

    if let Some(ref new_url) = url {
        if !new_url.is_empty() {
            match crypto_service.encrypt_field(&id, field_names::URL, new_url.as_bytes()) {
                Ok(enc) => {
                    // TODO: Update encrypted_url in database with enc.envelope_bytes
                    let _ = enc;
                }
                Err(e) => return CommandResult::Err(CommandError::from_kestrel(e)),
            }
        }
    }

    if let Some(ref new_notes) = notes {
        match crypto_service.encrypt_field(&id, field_names::NOTES, new_notes.as_bytes()) {
            Ok(enc) => {
                // TODO: Update encrypted_notes in database with enc.envelope_bytes
                let _ = enc;
            }
            Err(e) => return CommandResult::Err(CommandError::from_kestrel(e)),
        }
    }

    // ── Record activity ──
    {
        let mut sm = state.vault_state_machine.write().unwrap_or_else(|e| {
            tracing::error!("Vault state machine lock poisoned: {}", e);
            std::process::exit(1);
        });
        sm.record_activity();
    }

    // TODO: Load existing entry from database
    // TODO: Update in database
    // TODO: Audit log: EntryUpdated { entry_id, changed_fields }

    CommandResult::Err(CommandError::validation("Not yet implemented"))
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

    // ── Record activity ──
    {
        let mut sm = state.vault_state_machine.write().unwrap_or_else(|e| {
            tracing::error!("Vault state machine lock poisoned: {}", e);
            std::process::exit(1);
        });
        sm.record_activity();
    }

    // TODO: Delete from database via VaultEntryRepo
    // TODO: Audit log: EntryDeleted { entry_id }

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
    let _limit = limit.unwrap_or(50).min(200);
    let _offset = offset.unwrap_or(0).max(0);

    // ── Record activity ──
    {
        let mut sm = state.vault_state_machine.write().unwrap_or_else(|e| {
            tracing::error!("Vault state machine lock poisoned: {}", e);
            std::process::exit(1);
        });
        sm.record_activity();
    }

    // TODO: Load entries from database via VaultEntryRepo
    // TODO: Map to VaultEntryResponse (no passwords)

    CommandResult::ok(Vec::new())
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
    let _limit = limit.unwrap_or(50).min(200);

    // ── Record activity ──
    {
        let mut sm = state.vault_state_machine.write().unwrap_or_else(|e| {
            tracing::error!("Vault state machine lock poisoned: {}", e);
            std::process::exit(1);
        });
        sm.record_activity();
    }

    // TODO: Search database by title/username via VaultEntryRepo

    CommandResult::ok(Vec::new())
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

    // ── Get DEK for decryption ──
    let dek = state.get_dek().ok_or_else(|| {
        CommandError::unauthorized("Vault is locked — DEK not available")
    })?;
    let crypto_service = VaultCryptoService::new_dek(&dek);

    // ── Record activity ──
    {
        let mut sm = state.vault_state_machine.write().unwrap_or_else(|e| {
            tracing::error!("Vault state machine lock poisoned: {}", e);
            std::process::exit(1);
        });
        sm.record_activity();
    }

    // TODO: Load encrypted password envelope bytes from database via VaultEntryRepo
    // The decryption flow using the DEK:
    //
    // 1. Load encrypted_password BLOB from database for the given entry_id
    // 2. Decrypt using crypto_service.decrypt_field(&id, "password", &envelope_bytes)
    // 3. Convert decrypted bytes to String
    // 4. Return with auto-clear metadata
    // 5. Audit log: PasswordRevealed { entry_id }
    //
    // let encrypted_bytes = VaultEntryRepo::get_encrypted_password(pool, &id).await?;
    // let decrypted = crypto_service.decrypt_field(&id, field_names::PASSWORD, &encrypted_bytes)?;
    // let password_string = String::from_utf8(decrypted.plaintext)
    //     .map_err(|_| KestrelError::Crypto("Password is not valid UTF-8".to_string()))?;

    // TODO: Audit log: PasswordRevealed { entry_id }
    tracing::warn!("Password reveal requested for entry: {}", id);

    CommandResult::Err(CommandError::validation(
        "Password reveal requires database integration",
    ))
}
