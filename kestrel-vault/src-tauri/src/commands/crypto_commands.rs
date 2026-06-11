//! Cryptographic utility Tauri commands for KESTREL Vault.
//!
//! WARNING: These commands expose crypto operations to the frontend.
//! They should be used VERY sparingly and ONLY when the operation
//! cannot be performed within the normal vault flow.
//!
//! # Security Considerations
//!
//! - `derive_key`: Exposes key derivation — use ONLY for vault init/unlock
//! - `encrypt_data`: Exposes encryption — use ONLY for special cases
//! - `decrypt_data`: Exposes decryption — HIGH RISK, audit-log every call
//!
//! These commands exist primarily for the vault initialization and
//! unlock flow. They should NOT be used for routine vault operations,
//! which handle encryption internally.

use crate::commands::types::{CommandError, CommandResult};
use tauri::State;

use super::auth_commands::AppState;

/// Derives a cryptographic key from a password.
///
/// WARNING: This exposes key derivation to the frontend.
/// Use ONLY for vault initialization and unlock.
///
/// # Security
//!
//! - The derived key is NEVER returned to the frontend
//! - Only a key reference/handle is returned for internal use
//! - All key material stays in Rust memory
#[tauri::command]
pub fn crypto_derive_key(
    _password: String,
    _salt: String,
    _state: State<'_, AppState>,
) -> CommandResult<String> {
    // TODO: This should NOT return the key to frontend
    // Instead, derive the key internally and return a handle
    // The frontend should never see key material

    Err(CommandError::validation(
        "Direct key derivation is not available via IPC. Use auth_unlock instead.",
    ))
}

/// Encrypts data with the vault's master key.
///
/// WARNING: Prefer using domain-specific commands (vault_create_entry, etc.)
/// which handle encryption internally.
///
/// # Security
//!
//! - Data is encrypted in Rust memory
/// - The ciphertext is returned, not the key
/// - Audit-logged
#[tauri::command]
pub fn crypto_encrypt_data(
    _plaintext: String,
    _context: String,
    _state: State<'_, AppState>,
) -> CommandResult<String> {
    // TODO: Check vault is unlocked
    // TODO: Encrypt using seal_envelope
    // TODO: Return base64-encoded envelope
    // TODO: Audit log: DataEncrypted

    Err(CommandError::validation(
        "Direct encryption is not available via IPC. Use domain-specific commands instead.",
    ))
}

/// Decrypts data with the vault's master key.
///
/// WARNING: HIGH RISK — this returns decrypted data to the frontend.
//! Every call is audit-logged. Use ONLY when there is no
//! domain-specific command available.
///
/// # Security
//!
//! - Every call is audit-logged
//! - The decrypted data is sent to the frontend
//! - Frontend should auto-clear the data
#[tauri::command]
pub fn crypto_decrypt_data(
    _ciphertext: String,
    _context: String,
    _state: State<'_, AppState>,
) -> CommandResult<String> {
    // TODO: Check vault is unlocked
    // TODO: Audit log: DataDecrypted (HIGH PRIORITY)
    // TODO: Decrypt using open_envelope
    // TODO: Return plaintext

    Err(CommandError::validation(
        "Direct decryption is not available via IPC. Use domain-specific commands instead.",
    ))
}
