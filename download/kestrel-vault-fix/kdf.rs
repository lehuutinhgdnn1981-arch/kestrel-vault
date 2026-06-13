//! Key Derivation Function module.
//!
//! Provides Argon2id-based key derivation for converting user passwords
//! into cryptographic keys. Argon2id is the recommended KDF as it
//! combines resistance to side-channel attacks (Argon2i) with
//! resistance to GPU cracking (Argon2d).
//!
//! # Security Parameters
//!
//! The default parameters follow OWASP recommendations:
//! - Memory: 256 MB (256 * 1024 KiB)
//! - Iterations: 3
//! - Parallelism: 4
//!
//! # Important
//!
//! - PBKDF2 and scrypt are NOT used as primary KDFs
//! - All derived key material implements `Zeroize` on drop
//! - Salt values are always cryptographically random

use crate::error::KestrelError;
use crate::crypto::kdf_params::KdfParams;
use crate::crypto::random::random_bytes;
use argon2::{Algorithm, Argon2, Params, Version};
use secrecy::{CloneableSecret, ExposeSecret, SecretBox};
use zeroize::Zeroize;

/// Salt length in bytes. 16 bytes (128 bits) per Argon2 RFC 9106.
pub const SALT_LEN: usize = 16;

/// Derived key length in bytes. 32 bytes (256 bits) for AES-256.
pub const DERIVED_KEY_LEN: usize = 32;

/// Memory cost in KiB. 256 MB = 262144 KiB.
/// Follows OWASP recommendation for Argon2id.
pub const MEMORY_COST: u32 = 256 * 1024;

/// Number of Argon2id iterations (time cost).
/// Follows OWASP recommendation.
pub const ITERATIONS: u32 = 3;

/// Degree of parallelism (lanes).
/// Follows OWASP recommendation.
pub const PARALLELISM: u32 = 4;

/// A cryptographically random salt for key derivation.
///
/// This is a newtype wrapper around a fixed-size byte array
/// to prevent misuse (e.g., using a salt as a key).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Salt(pub [u8; SALT_LEN]);

impl Salt {
    /// Generates a new cryptographically random salt.
    ///
    /// # Errors
    ///
    /// Returns an error if the system random number generator fails.
    pub fn generate() -> Result<Self, KestrelError> {
        let mut bytes = [0u8; SALT_LEN];
        random_bytes(&mut bytes)?;
        Ok(Salt(bytes))
    }
}

/// A derived cryptographic key with automatic zeroization.
///
/// The key material is wrapped in `Secret` to prevent accidental
/// exposure through logging or debug output. When this value is
/// dropped, the key material is securely erased from memory.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct DerivedKey {
    /// The raw key bytes, protected by secrecy and zeroize.
    key: SecretBox<[u8; DERIVED_KEY_LEN]>,
}

// Implement CloneableSecret so that SecretBox<DerivedKey> can be cloned.
// This is required by the secrecy crate for SecretBox::clone().
impl CloneableSecret for DerivedKey {}

impl DerivedKey {
    /// Creates a new `DerivedKey` from raw key bytes.
    ///
    /// # Security
    ///
    /// The caller is responsible for ensuring the input bytes
    /// are a legitimate derived key, not arbitrary data.
    pub fn new(bytes: [u8; DERIVED_KEY_LEN]) -> Self {
        DerivedKey {
            key: SecretBox::new(Box::new(bytes)),
        }
    }

    /// Exposes the raw key bytes for use in cryptographic operations.
    ///
    /// # Security
    ///
    /// The exposed reference should not be stored or logged.
    /// Use only for passing to encryption/decryption functions.
    pub fn expose(&self) -> &[u8; DERIVED_KEY_LEN] {
        self.key.expose_secret()
    }
}

/// Derives a cryptographic key from a password and salt using Argon2id.
///
/// This function uses the Argon2id algorithm with parameters chosen
/// according to OWASP recommendations for password hashing.
///
/// # Arguments
///
/// * `password` - The user's master password (as raw bytes)
/// * `salt` - A cryptographically random salt
///
/// # Errors
///
/// Returns `KestrelError::Crypto` if Argon2id computation fails,
/// which should only occur with invalid parameters.
///
/// # Example (conceptual)
///
/// ```ignore
/// let salt = Salt::generate()?;
/// let key = derive_key(b"my-password", &salt)?;
/// // key is automatically zeroized when dropped
/// ```
pub fn derive_key(
    password: &[u8],
    salt: &Salt,
) -> Result<DerivedKey, KestrelError> {
    let params = Params::new(MEMORY_COST, ITERATIONS, PARALLELISM, Some(DERIVED_KEY_LEN))
        .map_err(|e| KestrelError::Crypto(format!("Invalid Argon2 params: {e}")))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key_bytes = [0u8; DERIVED_KEY_LEN];
    argon2
        .hash_password_into(password, &salt.0, &mut key_bytes)
        .map_err(|e| KestrelError::Crypto(format!("Argon2id derivation failed: {e}")))?;

    Ok(DerivedKey::new(key_bytes))
}

/// Derives a key and also returns a fresh salt.
///
/// Convenience function that generates a new salt and derives
/// the key in one step.
///
/// # Errors
///
/// Returns an error if salt generation or key derivation fails.
pub fn derive_key_with_new_salt(
    password: &[u8],
) -> Result<(DerivedKey, Salt), KestrelError> {
    let salt = Salt::generate()?;
    let key = derive_key(password, &salt)?;
    Ok((key, salt))
}

/// Derives a cryptographic key using custom KDF parameters.
///
/// This function allows specifying custom Argon2id parameters,
/// which is needed when loading parameters from the database
/// that may differ from the current defaults.
///
/// # Arguments
///
/// * `password` - The user's master password (as raw bytes)
/// * `salt` - A cryptographically random salt
/// * `params` - The KDF parameters to use
///
/// # Errors
///
/// Returns `KestrelError::Crypto` if:
/// - The Argon2id parameters are invalid
/// - The key derivation computation fails
///
/// # Security
///
/// The parameters are validated before use to prevent downgrade attacks.
pub fn derive_key_with_params(
    password: &[u8],
    salt: &Salt,
    params: &KdfParams,
) -> Result<DerivedKey, KestrelError> {
    // Validate parameters before use
    params.validate()?;

    let argon2_params = Params::new(
        params.memory_cost_kib,
        params.iterations,
        params.parallelism,
        Some(params.key_len as usize),
    )
    .map_err(|e| KestrelError::Crypto(format!("Invalid Argon2 params: {e}")))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut key_bytes = [0u8; DERIVED_KEY_LEN];
    argon2
        .hash_password_into(password, &salt.0, &mut key_bytes)
        .map_err(|e| KestrelError::Crypto(format!("Argon2id derivation failed: {e}")))?;

    Ok(DerivedKey::new(key_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_key_deterministic() -> Result<(), KestrelError> {
        let salt = Salt([0x42u8; SALT_LEN]);
        let key1 = derive_key(b"test-password", &salt)?;
        let key2 = derive_key(b"test-password", &salt)?;
        assert_eq!(key1.expose(), key2.expose());
        Ok(())
    }

    #[test]
    fn derive_key_different_passwords() -> Result<(), KestrelError> {
        let salt = Salt([0x42u8; SALT_LEN]);
        let key1 = derive_key(b"password-a", &salt)?;
        let key2 = derive_key(b"password-b", &salt)?;
        assert_ne!(key1.expose(), key2.expose());
        Ok(())
    }

    #[test]
    fn salt_generation_unique() -> Result<(), KestrelError> {
        let s1 = Salt::generate()?;
        let s2 = Salt::generate()?;
        assert_ne!(s1.0, s2.0);
        Ok(())
    }
}
