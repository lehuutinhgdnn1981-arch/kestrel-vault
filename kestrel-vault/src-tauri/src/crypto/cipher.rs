//! Authenticated encryption module using AES-256-GCM.
//!
//! This module provides authenticated encryption and decryption using
//! the AES-256-GCM algorithm. This is the ONLY symmetric cipher
//! permitted in KESTREL Vault.
//!
//! # Why AES-256-GCM?
//!
//! - **Authenticated encryption**: Provides both confidentiality and integrity
//! - **No padding oracle attacks**: Stream cipher mode, no padding needed
//! - **NIST recommended**: Widely analyzed and standardized
//! - **Hardware acceleration**: AES-NI available on modern CPUs
//!
//! # Forbidden Algorithms
//!
//! - **AES-ECB**: No authentication, deterministic encryption
//! - **AES-CBC**: No built-in authentication, padding oracle vulnerable
//! - **Any unauthenticated mode**: Must use AEAD

use crate::error::KestrelError;
use crate::crypto::kdf::DerivedKey;
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, AeadCore};
use zeroize::Zeroize;

/// Nonce length in bytes. 12 bytes (96 bits) is the standard for AES-GCM.
pub const NONCE_LEN: usize = 12;

/// AES-256-GCM authentication tag length in bytes (128 bits).
pub const TAG_LEN: usize = 16;

/// Ciphertext produced by AES-256-GCM encryption.
///
/// This newtype wraps a byte vector containing the encrypted data
/// with the authentication tag appended. It prevents accidental
/// use of ciphertext as plaintext or vice versa.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Ciphertext(pub Vec<u8>);

/// Nonce (number used once) for AES-256-GCM.
///
/// Each encryption operation MUST use a unique nonce.
/// Reusing a nonce with the same key is catastrophic for GCM.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Nonce(pub [u8; NONCE_LEN]);

/// Authentication tag for AES-256-GCM.
///
/// Separated for cases where the tag needs to be verified
/// independently. In standard usage, the tag is appended
/// to the ciphertext.
#[derive(Clone, Debug, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub struct AeadTag(pub [u8; TAG_LEN]);

/// Encrypts plaintext using AES-256-GCM with associated data.
///
/// # Arguments
///
/// * `key` - The derived encryption key (256 bits)
/// * `plaintext` - The data to encrypt
/// * `associated_data` - Additional authenticated data (not encrypted, but integrity-protected)
///
/// # Returns
///
/// A tuple of (Nonce, Ciphertext) where the ciphertext includes
/// the authentication tag appended.
///
/// # Errors
///
/// Returns `KestrelError::Crypto` if encryption fails.
///
/// # Security
///
/// - A fresh random nonce is generated for each encryption
/// - The nonce MUST be stored alongside the ciphertext for decryption
/// - Never reuse a nonce with the same key
pub fn encrypt(
    key: &DerivedKey,
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<(Nonce, Ciphertext), KestrelError> {
    let cipher = Aes256Gcm::new_from_slice(key.expose())
        .map_err(|e| KestrelError::Crypto(format!("Invalid key length: {e}")))?;

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let nonce_copy = Nonce(nonce.into());

    let ciphertext = cipher
        .encrypt(&nonce, aes_gcm::aead::Payload {
            msg: plaintext,
            aad: associated_data,
        })
        .map_err(|e| KestrelError::Crypto(format!("Encryption failed: {e}")))?;

    Ok((nonce_copy, Ciphertext(ciphertext)))
}

/// Decrypts ciphertext using AES-256-GCM with associated data.
///
/// # Arguments
///
/// * `key` - The derived encryption key (256 bits)
/// * `nonce` - The nonce used during encryption
/// * `ciphertext` - The encrypted data (including authentication tag)
/// * `associated_data` - The same associated data used during encryption
///
/// # Returns
///
/// The decrypted plaintext as a byte vector.
///
/// # Errors
///
/// Returns `KestrelError::Crypto` if:
/// - The key is incorrect
/// - The ciphertext has been tampered with
/// - The associated data does not match
///
/// # Security
///
/// The authentication tag is verified before any plaintext is released.
/// This prevents chosen-ciphertext attacks.
pub fn decrypt(
    key: &DerivedKey,
    nonce: &Nonce,
    ciphertext: &Ciphertext,
    associated_data: &[u8],
) -> Result<Vec<u8>, KestrelError> {
    let cipher = Aes256Gcm::new_from_slice(key.expose())
        .map_err(|e| KestrelError::Crypto(format!("Invalid key length: {e}")))?;

    let nonce = aes_gcm::Nonce::from_slice(&nonce.0);

    let plaintext = cipher
        .decrypt(nonce, aes_gcm::aead::Payload {
            msg: &ciphertext.0,
            aad: associated_data,
        })
        .map_err(|_| KestrelError::Crypto("Decryption failed: authentication tag mismatch".to_string()))?;

    Ok(plaintext)
}

/// Encrypts plaintext without associated data.
///
/// Convenience wrapper around `encrypt()` with empty associated data.
/// Use this when there is no additional context to bind to the ciphertext.
///
/// # Errors
///
/// Same as `encrypt()`.
pub fn encrypt_simple(
    key: &DerivedKey,
    plaintext: &[u8],
) -> Result<(Nonce, Ciphertext), KestrelError> {
    encrypt(key, plaintext, &[])
}

/// Decrypts ciphertext without associated data.
///
/// Convenience wrapper around `decrypt()` with empty associated data.
///
/// # Errors
///
/// Same as `decrypt()`.
pub fn decrypt_simple(
    key: &DerivedKey,
    nonce: &Nonce,
    ciphertext: &Ciphertext,
) -> Result<Vec<u8>, KestrelError> {
    decrypt(key, nonce, ciphertext, &[])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::{derive_key, Salt};

    fn test_key() -> DerivedKey {
        let salt = Salt([0x42u8; 16]);
        derive_key(b"test-encryption-key", &salt).unwrap()
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = test_key();
        let plaintext = b"secret vault data";
        let (nonce, ciphertext) = encrypt_simple(&key, plaintext).unwrap();
        let decrypted = decrypt_simple(&key, &nonce, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_decrypt_with_aad() {
        let key = test_key();
        let plaintext = b"secret vault data";
        let aad = b"entry-id-12345";
        let (nonce, ciphertext) = encrypt(&key, plaintext, aad).unwrap();
        let decrypted = decrypt(&key, &nonce, &ciphertext, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = test_key();
        let plaintext = b"secret vault data";
        let (nonce, mut ciphertext) = encrypt_simple(&key, plaintext).unwrap();
        // Tamper with ciphertext
        ciphertext.0[0] ^= 0xFF;
        let result = decrypt_simple(&key, &nonce, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_aad_fails() {
        let key = test_key();
        let plaintext = b"secret vault data";
        let (nonce, ciphertext) = encrypt(&key, plaintext, b"correct-aad").unwrap();
        let result = decrypt(&key, &nonce, &ciphertext, b"wrong-aad");
        assert!(result.is_err());
    }
}
