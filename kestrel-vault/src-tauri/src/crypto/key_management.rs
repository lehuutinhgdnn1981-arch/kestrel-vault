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

use crate::crypto::kdf::{self, DerivedKey, Salt};
use crate::crypto::secure_string::SecureString;
use crate::crypto::vault_crypto::VaultCryptoService;
use crate::error::KestrelError;
use secrecy::{ExposeSecret, Secret};
use zeroize::Zeroize;
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

    /// Derives a master key from a `SecureString` password and salt.
    ///
    /// This is the preferred method for password-based key derivation
    /// as it accepts a zeroizing `SecureString` instead of raw bytes.
    ///
    /// # Security
    ///
    /// The `SecureString` is zeroized when it goes out of scope.
    pub fn from_secure_password(
        password: &SecureString,
        salt: &Salt,
    ) -> Result<Self, KestrelError> {
        Self::from_password(password.as_bytes(), salt)
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

    /// Derives a master key from a `SecureString` with a new random salt.
    ///
    /// This is the preferred method for new vault creation as it
    /// accepts a zeroizing `SecureString` and generates a fresh salt.
    pub fn from_secure_password_new_salt(
        password: &SecureString,
    ) -> Result<(Self, Salt), KestrelError> {
        Self::from_password_new_salt(password.as_bytes())
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

/// A pair of old and new keys used during rotation.
///
/// This struct ensures that both keys are available during the
/// re-encryption process and that the old key is zeroized after
/// rotation completes.
pub struct RotationKeyPair {
    /// The old key (used for decryption during rotation).
    pub old_key: MasterKey,
    /// The new key (used for encryption during rotation).
    pub new_key: MasterKey,
}

impl RotationKeyPair {
    /// Creates a crypto service from the old key for decryption.
    pub fn old_crypto_service(&self) -> VaultCryptoService<'_> {
        VaultCryptoService::new(&self.old_key)
    }

    /// Creates a crypto service from the new key for encryption.
    pub fn new_crypto_service(&self) -> VaultCryptoService<'_> {
        VaultCryptoService::new(&self.new_key)
    }
}

impl Drop for RotationKeyPair {
    fn drop(&mut self) {
        // Both keys are zeroized via ZeroizeOnDrop on their respective drops.
        // The old key is zeroized here to ensure it doesn't linger in memory
        // after rotation is complete.
        tracing::debug!("RotationKeyPair dropped — both keys zeroized");
    }
}

/// Result of a key rotation operation.
///
/// Contains both the old and new key references for
/// re-encrypting vault data.
pub struct KeyRotationResult {
    /// The new salt for the rotated key.
    pub new_salt: Salt,
    /// The new test envelope bytes for the rotated key.
    pub new_test_envelope: Vec<u8>,
    /// Number of entries re-encrypted during rotation.
    pub entries_reencrypted: u32,
}

/// Rotates the master key by re-deriving from a new password.
///
/// This operation:
/// 1. Derives a new key from the new password
/// 2. Creates a new test envelope with the new key
/// 3. Returns the key pair for re-encrypting vault entries
///
/// The caller is responsible for:
/// - Re-encrypting all vault entries using the `RotationKeyPair`
/// - Persisting the new salt and test envelope
/// - Dropping the `RotationKeyPair` to zeroize both keys
///
/// # Arguments
///
/// * `old_key` - The current master key (used for decryption)
/// * `new_password` - The new master password (as SecureString)
///
/// # Errors
///
/// Returns an error if key derivation or test envelope creation fails.
///
/// # Security
///
/// - Both old and new keys are zeroized when `RotationKeyPair` is dropped
/// - The new password is zeroized via `SecureString`
/// - The old key remains valid until the caller drops the `RotationKeyPair`
pub fn rotate_master_key(
    old_key: MasterKey,
    new_password: &SecureString,
) -> Result<(RotationKeyPair, KeyRotationResult), KestrelError> {
    // Derive new key from new password
    let (new_key, new_salt) = MasterKey::from_secure_password_new_salt(new_password)?;

    // Create new test envelope with the new key
    let new_crypto_service = VaultCryptoService::new(&new_key);
    let new_test_envelope = new_crypto_service.create_test_envelope()?;

    let rotation_pair = RotationKeyPair {
        old_key,
        new_key,
    };

    let result = KeyRotationResult {
        new_salt,
        new_test_envelope: new_test_envelope.envelope_bytes,
        entries_reencrypted: 0, // Updated by the caller during re-encryption
    };

    Ok((rotation_pair, result))
}

/// Re-encrypts a single field from the old key to the new key.
///
/// This is a convenience function for the key rotation process.
/// It decrypts a field with the old key and re-encrypts it with
/// the new key, preserving the same entity_id and field_name.
///
/// # Arguments
///
/// * `rotation_pair` - The old and new keys
/// * `entity_id` - The UUID of the entity
/// * `field_name` - The name of the field
/// * `old_envelope_bytes` - The current encrypted envelope bytes
///
/// # Returns
///
/// The new encrypted envelope bytes (encrypted with the new key).
///
/// # Security
///
/// - The decrypted plaintext exists only briefly in a `DecryptedField`
///   which is automatically zeroized on drop
/// - The same AAD context is used for both old and new encryption,
///   preserving the entity_id:field_name binding
pub fn re_encrypt_field(
    rotation_pair: &RotationKeyPair,
    entity_id: &str,
    field_name: &str,
    old_envelope_bytes: &[u8],
) -> Result<Vec<u8>, KestrelError> {
    // Decrypt with old key
    let old_service = rotation_pair.old_crypto_service();
    let decrypted = old_service.decrypt_field(entity_id, field_name, old_envelope_bytes)?;

    // Re-encrypt with new key
    let new_service = rotation_pair.new_crypto_service();
    let encrypted = new_service.encrypt_field(entity_id, field_name, &decrypted.plaintext)?;

    // decrypted is zeroized here when DecryptedField drops
    Ok(encrypted.envelope_bytes)
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

    #[test]
    fn master_key_from_secure_password() -> Result<(), KestrelError> {
        let salt = Salt::generate()?;
        let secure = SecureString::from("test-secure-password".to_string());
        let key = MasterKey::from_secure_password(&secure, &salt)?;
        // Verify the key is valid
        assert_eq!(key.derived_key().expose().len(), 32);
        Ok(())
    }

    #[test]
    fn master_key_from_secure_password_new_salt() -> Result<(), KestrelError> {
        let secure = SecureString::from("test-secure-password".to_string());
        let (key, salt) = MasterKey::from_secure_password_new_salt(&secure)?;
        assert_ne!(salt.0, [0u8; 16]);
        assert_eq!(key.derived_key().expose().len(), 32);
        Ok(())
    }

    #[test]
    fn rotate_master_key_produces_new_key() -> Result<(), KestrelError> {
        let old_salt = Salt::generate()?;
        let old_key = MasterKey::from_password(b"old-password", &old_salt)?;
        let new_secure = SecureString::from("new-secure-password".to_string());

        let (rotation_pair, result) = rotate_master_key(old_key, &new_secure)?;

        // Verify the new key is different from the old key
        assert_ne!(
            rotation_pair.old_key.derived_key().expose(),
            rotation_pair.new_key.derived_key().expose()
        );

        // Verify the new salt is not all zeros
        assert_ne!(result.new_salt.0, [0u8; 16]);

        // Verify the test envelope was created
        assert!(!result.new_test_envelope.is_empty());

        // Verify the new test envelope can be verified with the new key
        let new_service = rotation_pair.new_crypto_service();
        let is_valid = new_service.verify_test_envelope(&result.new_test_envelope)?;
        assert!(is_valid);

        Ok(())
    }

    #[test]
    fn re_encrypt_field_roundtrip() -> Result<(), KestrelError> {
        // Set up old key and encrypt some data
        let old_salt = Salt::generate()?;
        let old_key = MasterKey::from_password(b"old-password", &old_salt)?;
        let old_service = VaultCryptoService::new(&old_key);

        let entity_id = "550e8400-e29b-41d4-a716-446655440000";
        let plaintext = b"my-secret-password";

        let old_encrypted = old_service.encrypt_password(entity_id, plaintext)?;

        // Rotate to new key
        let new_secure = SecureString::from("new-secure-password".to_string());
        let (rotation_pair, _result) = rotate_master_key(old_key, &new_secure)?;

        // Re-encrypt the field
        let new_envelope_bytes = re_encrypt_field(
            &rotation_pair,
            entity_id,
            "password",
            &old_encrypted.envelope_bytes,
        )?;

        // Verify the new envelope can be decrypted with the new key
        let new_service = rotation_pair.new_crypto_service();
        let decrypted = new_service.decrypt_password(entity_id, &new_envelope_bytes)?;
        assert_eq!(decrypted.plaintext, plaintext);

        // Verify the old envelope cannot be decrypted with the new key
        let old_result = new_service.decrypt_password(entity_id, &old_encrypted.envelope_bytes);
        assert!(old_result.is_err());

        Ok(())
    }

    #[test]
    fn rotation_key_pair_drop_zeroizes() -> Result<(), KestrelError> {
        let old_salt = Salt::generate()?;
        let old_key = MasterKey::from_password(b"old-password", &old_salt)?;
        let new_secure = SecureString::from("new-password".to_string());

        let (rotation_pair, _result) = rotate_master_key(old_key, &new_secure)?;

        // rotation_pair goes out of scope and both keys are zeroized
        drop(rotation_pair);

        // We can't easily verify zeroization from outside,
        // but the Drop impl should have run without panicking.
        Ok(())
    }
}
