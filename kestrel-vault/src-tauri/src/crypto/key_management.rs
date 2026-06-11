//! Key management module for KESTREL Vault.
//!
//! This module handles the lifecycle of cryptographic keys:
//! - Master key derivation from user passwords
//! - Key rotation for forward secrecy
//! - Key splitting for memory-safe storage (Shamir's Secret Sharing - future)
//! - Automatic zeroization of all key material
//!
//! # Security Model
//!
//! The master password never leaves memory and is zeroized after
//! key derivation. Derived keys are wrapped in `secrecy::Secret`
//! to prevent accidental exposure through logging or serialization.

use crate::error::KestrelError;
use crate::crypto::kdf::{self, DerivedKey, Salt};
use secrecy::{ExposeSecret, Secret, Zeroize};
use zeroize::ZeroizeOnDrop;

/// The master encryption key for the vault.
///
/// This key is derived from the user's master password and is
/// used to encrypt/decrypt all vault entries. It is never persisted
/// directly — only derived from the password at runtime.
///
/// # Security
///
/// - Wrapped in `secrecy::Secret` — no Debug, no Clone of inner data
/// - Implements `ZeroizeOnDrop` — key material erased on drop
/// - Never serialized or logged
#[derive(ZeroizeOnDrop)]
pub struct MasterKey {
    /// The derived key material, protected by secrecy.
    key: Secret<DerivedKey>,
}

impl Clone for MasterKey {
    /// Clones the master key by cloning the inner derived key.
    ///
    /// # Security
    ///
    /// Each clone holds its own copy of the key material, which will
    /// be independently zeroized on drop. Minimize the number of
    /// clones to reduce the attack surface for memory extraction.
    fn clone(&self) -> Self {
        MasterKey {
            key: Secret::new(self.key.expose_secret().clone()),
        }
    }
}

impl MasterKey {
    /// Derives a master key from a password and salt.
    ///
    /// # Arguments
    ///
    /// * `password` - The user's master password (cleared after use)
    /// * `salt` - The salt used for key derivation
    ///
    /// # Errors
    ///
    /// Returns `KestrelError::Crypto` if Argon2id derivation fails.
    ///
    /// # Security
    ///
    /// The password parameter should be zeroized by the caller
    /// after this function returns.
    pub fn from_password(
        password: &[u8],
        salt: &Salt,
    ) -> Result<Self, KestrelError> {
        let derived = kdf::derive_key(password, salt)?;
        Ok(MasterKey {
            key: Secret::new(derived),
        })
    }

    /// Derives a master key with a new random salt.
    ///
    /// Convenience function that generates a fresh salt.
    ///
    /// # Returns
    ///
    /// A tuple of (MasterKey, Salt). The salt must be persisted
    /// for future key derivation.
    ///
    /// # Errors
    ///
    /// Returns an error if salt generation or key derivation fails.
    pub fn from_password_new_salt(
        password: &[u8],
    ) -> Result<(Self, Salt), KestrelError> {
        let (derived, salt) = kdf::derive_key_with_new_salt(password)?;
        Ok((
            MasterKey {
                key: Secret::new(derived),
            },
            salt,
        ))
    }

    /// Accesses the underlying derived key for cryptographic operations.
    ///
    /// # Security
    ///
    /// The exposed reference should be used only for passing to
    /// encrypt/decrypt functions and must not be stored or logged.
    pub fn derived_key(&self) -> &DerivedKey {
        self.key.expose_secret()
    }
}

/// Result of a key rotation operation.
///
/// Contains both the old and new key references for
/// re-encrypting vault data.
pub struct KeyRotationResult {
    /// The new salt for the rotated key.
    pub new_salt: Salt,
    /// Number of entries re-encrypted during rotation.
    pub entries_reencrypted: u32,
}

/// Rotates the master key by re-deriving from a new password.
///
/// This operation:
/// 1. Derives a new key from the new password
/// 2. Re-encrypts all vault entries with the new key
/// 3. Returns the new salt for storage
///
/// # Errors
///
/// Returns an error if key derivation or re-encryption fails.
///
/// # TODO (Phase 2)
///
/// - Implement re-encryption of all vault entries
/// - Add transactional re-encryption (rollback on failure)
/// - Add progress reporting for large vaults
pub fn rotate_master_key(
    _old_key: &MasterKey,
    _new_password: &[u8],
) -> Result<KeyRotationResult, KestrelError> {
    // TODO: Implement key rotation in Phase 2
    // 1. Derive new key from new password
    // 2. Load all encrypted vault entries
    // 3. Decrypt each entry with old key
    // 4. Re-encrypt each entry with new key
    // 5. Store new salt and updated entries in transaction
    // 6. Zeroize all intermediate plaintext
    Err(KestrelError::Crypto(
        "Key rotation not yet implemented".to_string(),
    ))
}

/// Splits a key into shares for distributed storage.
///
/// Uses Shamir's Secret Sharing to split the key into `n` shares,
/// any `threshold` of which can reconstruct the original key.
///
/// # TODO (Phase 3)
///
/// - Implement Shamir's Secret Sharing
/// - Add share validation
/// - Add secure share reconstruction
pub fn split_key(
    _key: &MasterKey,
    _n: u8,
    _threshold: u8,
) -> Result<Vec<KeyShare>, KestrelError> {
    // TODO: Implement Shamir's Secret Sharing in Phase 3
    Err(KestrelError::Crypto(
        "Key splitting not yet implemented".to_string(),
    ))
}

/// Reconstructs a master key from a sufficient number of shares.
///
/// # TODO (Phase 3)
///
/// - Implement share reconstruction
/// - Validate share consistency
/// - Zeroize shares after reconstruction
pub fn combine_key_shares(
    _shares: &[KeyShare],
) -> Result<MasterKey, KestrelError> {
    // TODO: Implement key reconstruction in Phase 3
    Err(KestrelError::Crypto(
        "Key share combination not yet implemented".to_string(),
    ))
}

/// A share of a split key, for use with Shamir's Secret Sharing.
///
/// Each share is a point on the polynomial used to split the key.
/// No single share reveals any information about the key.
///
/// # TODO (Phase 3)
///
/// - Implement actual share structure
/// - Add serialization for secure storage
#[derive(Debug)]
pub struct KeyShare {
    /// The share index (x-coordinate in Shamir's scheme).
    pub index: u8,
    /// The share value (y-coordinate in Shamir's scheme).
    /// Will be wrapped in Secret once implemented.
    pub value: Vec<u8>,
}

impl Zeroize for KeyShare {
    fn zeroize(&mut self) {
        self.value.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn master_key_from_password() -> Result<(), KestrelError> {
        let salt = Salt::generate()?;
        let _key = MasterKey::from_password(b"test-master-password", &salt)?;
        Ok(())
    }

    #[test]
    fn master_key_new_salt() -> Result<(), KestrelError> {
        let (_key, salt) = MasterKey::from_password_new_salt(b"test-master-password")?;
        assert_ne!(salt.0, [0u8; 16]);
        Ok(())
    }

    #[test]
    fn same_password_same_salt_same_key() -> Result<(), KestrelError> {
        let salt = Salt::generate()?;
        let key1 = MasterKey::from_password(b"same-password", &salt)?;
        let key2 = MasterKey::from_password(b"same-password", &salt)?;
        assert_eq!(key1.derived_key().expose(), key2.derived_key().expose());
        Ok(())
    }
}
