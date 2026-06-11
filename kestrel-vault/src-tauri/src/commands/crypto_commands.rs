//! Tauri commands for cryptographic operations.
//!
//! ⚠️ **WARNING**: These commands expose cryptographic primitives to the
//! frontend. Each command must be carefully reviewed for security
//! implications. In general, the frontend should NOT need direct
//! access to crypto operations — they should be used internally
//! by other service layers.
//!
//! # Security Implications
//!
//! - `derive_key`: Exposes key derivation to frontend. Risk: key material
//!   could be intercepted in the IPC channel. Mitigation: keys are never
//!   returned as raw bytes; only opaque handles are returned.
//!
//! - `encrypt_data`: Exposes encryption to frontend. Risk: misuse could
//!   lead to weak encryption (wrong nonce, wrong key). Mitigation:
//!   nonces are auto-generated; keys are validated.
//!
//! - `decrypt_data`: Exposes decryption to frontend. Risk: could be used
//!   to decrypt data without proper authorization. Mitigation: session
//!   validation is required before decryption.
//!
//! # Recommendation
//!
//! These commands should be DEPRECATED in favor of higher-level
//! service commands that handle crypto internally. The frontend
//! should never need to manage encryption directly.

use crate::commands::vault_commands::AppState;
use crate::crypto::cipher::{Ciphertext, Nonce};
use crate::crypto::kdf::{DerivedKey, Salt};
use crate::error::KestrelError;
use crate::security::session::SessionManager;

/// Derives a cryptographic key from a password.
///
/// ⚠️ **SECURITY WARNING**: This command exposes key derivation to
/// the frontend. The derived key is returned as an opaque handle
/// that cannot be serialized or inspected by the frontend.
///
/// # Arguments
///
/// * `password` - The master password
/// * `salt_hex` - The hex-encoded salt (or empty to generate a new one)
///
/// # Returns
///
/// A hex-encoded salt and an opaque key identifier.
///
/// # Security
///
/// - The password is zeroized after key derivation
/// - The derived key is never returned as raw bytes
/// - Only an opaque handle (session-bound) is returned
#[tauri::command]
pub async fn derive_key(
    _state: tauri::State<'_, AppState>,
    password: String,
    salt_hex: Option<String>,
) -> Result<String, String> {
    if password.is_empty() {
        return Err("Password must not be empty".to_string());
    }

    // Parse or generate salt
    let salt = match salt_hex {
        Some(hex) => {
            let bytes = hex_to_bytes(&hex)
                .map_err(|e| format!("Invalid salt: {e}"))?;
            if bytes.len() != 16 {
                return Err("Salt must be 16 bytes (32 hex characters)".to_string());
            }
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&bytes);
            Salt(arr)
        }
        None => Salt::generate()
            .map_err(|e| e.to_user_message())?,
    };

    // Derive key
    let _derived = crate::crypto::kdf::derive_key(password.as_bytes(), &salt)
        .map_err(|e| e.to_user_message())?;

    // TODO (Phase 2): Store key in session and return opaque handle
    // The key should NEVER be returned to the frontend directly.
    // Instead, store it in the SessionManager and return a handle ID.
    Err(KestrelError::Crypto("Not yet implemented — keys must be managed via session".to_string()).to_user_message())
}

/// Encrypts data using the session's current key.
///
/// ⚠️ **SECURITY WARNING**: This command exposes encryption to the
/// frontend. Prefer using higher-level service commands that
/// handle encryption internally.
///
/// # Arguments
///
/// * `data` - The plaintext data to encrypt (base64-encoded)
/// * `key_handle` - The opaque key handle from `derive_key`
/// * `associated_data` - Optional additional authenticated data
///
/// # Returns
///
/// Base64-encoded ciphertext and nonce.
///
/// # Security
///
/// - The plaintext is zeroized after encryption
/// - A fresh nonce is generated for each encryption
/// - Associated data is verified during decryption
#[tauri::command]
pub async fn encrypt_data(
    _state: tauri::State<'_, AppState>,
    data: String,
    _key_handle: String,
    _associated_data: Option<String>,
) -> Result<serde_json::Value, String> {
    if data.is_empty() {
        return Err("Data must not be empty".to_string());
    }

    // TODO (Phase 2): Look up key by handle in session
    // TODO (Phase 2): Encrypt the data
    // TODO (Phase 2): Return base64-encoded ciphertext and nonce
    Err(KestrelError::Crypto("Not yet implemented".to_string()).to_user_message())
}

/// Decrypts data using the session's current key.
///
/// ⚠️ **SECURITY WARNING**: This command exposes decryption to the
/// frontend. Unauthorized decryption attempts must be prevented
/// through session validation and rate limiting.
///
/// # Arguments
///
/// * `ciphertext` - The encrypted data (base64-encoded)
/// * `nonce` - The nonce used during encryption (base64-encoded)
/// * `key_handle` - The opaque key handle from `derive_key`
/// * `associated_data` - The same associated data used during encryption
///
/// # Returns
///
/// Base64-encoded decrypted data.
///
/// # Security
///
/// - Session validation is required before decryption
/// - Failed decryption attempts are rate-limited and logged
/// - The decrypted data should be zeroized after use by the frontend
#[tauri::command]
pub async fn decrypt_data(
    _state: tauri::State<'_, AppState>,
    _ciphertext: String,
    _nonce: String,
    _key_handle: String,
    _associated_data: Option<String>,
) -> Result<String, String> {
    // TODO (Phase 2): Validate session
    // TODO (Phase 2): Look up key by handle in session
    // TODO (Phase 2): Decrypt the data
    // TODO (Phase 2): Return base64-encoded plaintext
    Err(KestrelError::Crypto("Not yet implemented".to_string()).to_user_message())
}

/// Converts a hex string to a byte vector.
fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("Hex string must have even length".to_string());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| format!("Invalid hex character: {e}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_to_bytes_valid() {
        let result = hex_to_bytes("0a1b2c").unwrap();
        assert_eq!(result, vec![10, 27, 44]);
    }

    #[test]
    fn hex_to_bytes_empty() {
        let result = hex_to_bytes("").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn hex_to_bytes_odd_length() {
        let result = hex_to_bytes("abc");
        assert!(result.is_err());
    }

    #[test]
    fn hex_to_bytes_invalid_char() {
        let result = hex_to_bytes("zz");
        assert!(result.is_err());
    }
}
