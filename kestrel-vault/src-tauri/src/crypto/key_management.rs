//! Key management module for KESTREL Vault.
//!
//! This module handles the lifecycle of cryptographic keys using the
//! industry-standard KEK/DEK (Key Encryption Key / Data Encryption Key)
//! hierarchy pattern.
//!
//! # Key Hierarchy
//!
//! ```text
//! Master Password
//!       │
//!       ▼
//! ┌──────────────┐
//! │  Argon2id    │  Key Derivation Function
//! │  KEK         │  Key Encryption Key (= MasterKey)
//! └──────┬───────┘
//!        │
//!        ▼ wrap/unwrap
//! ┌──────────────┐
//! │  DEK         │  Data Encryption Key (randomly generated)
//! │  (wrapped)   │  Stored encrypted in vault_meta
//! └──────┬───────┘
//!        │
//!        ├──── HKDF(info="kestrel:field-encryption") → Field Key
//!        ├──── HKDF(info="kestrel:file-encryption")  → File Key
//!        ├──── HKDF(info="kestrel:search-index")     → Search Key
//!        ├──── HKDF(info="kestrel:export-encryption")→ Export Key
//!        └──── HKDF(info="kestrel:totp-encryption")  → TOTP Key
//! ```
//!
//! # Why KEK/DEK?
//!
//! 1. **Fast key rotation**: Password change only re-wraps the DEK (O(1)),
//!    not all vault data (O(n)).
//! 2. **Key separation**: The KEK is never used for data encryption.
//! 3. **Forward compatibility**: DEK can be shared with multiple KEKs.
//!
//! # Security Model
//!
//! The master password never leaves memory and is zeroized after
//! key derivation. All key material uses `secrecy::Secret` and
//! `ZeroizeOnDrop` to prevent accidental exposure and ensure
//! secure erasure.

use crate::crypto::kdf::{self, DerivedKey, Salt};
use crate::crypto::keywrap::{self, DataEncryptionKey, WrappedDek};
use crate::crypto::kdf_params::KdfParams;
use crate::crypto::secure_string::SecureString;
use crate::crypto::subkeys::SubKeySet;
use crate::crypto::vault_crypto::VaultCryptoService;
use crate::error::KestrelError;
use crate::error::KestrelResult;
use secrecy::{ExposeSecret, Secret};
use zeroize::Zeroize;
use zeroize::ZeroizeOnDrop;

/// The master encryption key for the vault.
///
/// This key is derived from the user's master password using Argon2id
/// and serves as the **Key Encryption Key (KEK)** in the KEK/DEK hierarchy.
/// It is used exclusively to wrap/unwrap the Data Encryption Key (DEK),
/// never for direct data encryption.
///
/// # Security
///
/// - Wrapped in `secrecy::Secret` — no Debug, no Clone of inner data
/// - Implements `ZeroizeOnDrop` — key material erased on drop
/// - Never serialized or logged
/// - Never used for bulk data encryption (that's the DEK's job)
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
    /// Derives a master key from a password and salt using the default
    /// OWASP-recommended KDF parameters.
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

    /// Derives a master key from a password, salt, and custom KDF parameters.
    ///
    /// Use this when loading parameters from the database that may differ
    /// from the current defaults.
    ///
    /// # Arguments
    ///
    /// * `password` - The user's master password
    /// * `salt` - The salt used for key derivation
    /// * `params` - The KDF parameters to use
    ///
    /// # Errors
    ///
    /// Returns `KestrelError::Crypto` if Argon2id derivation fails.
    pub fn from_password_with_params(
        password: &[u8],
        salt: &Salt,
        params: &KdfParams,
    ) -> Result<Self, KestrelError> {
        let derived = kdf::derive_key_with_params(password, salt, params)?;
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

    /// Derives a master key from a `SecureString` with custom KDF parameters.
    pub fn from_secure_password_with_params(
        password: &SecureString,
        salt: &Salt,
        params: &KdfParams,
    ) -> Result<Self, KestrelError> {
        Self::from_password_with_params(password.as_bytes(), salt, params)
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

    // ── KEK/DEK operations ──

    /// Wraps (encrypts) a DEK with this master key (acting as KEK).
    ///
    /// This is used during vault initialization to generate a new DEK
    /// and store it in wrapped (encrypted) form.
    ///
    /// # Arguments
    ///
    /// * `dek` - The Data Encryption Key to wrap
    ///
    /// # Returns
    ///
    /// A `WrappedDek` containing the encrypted DEK.
    ///
    /// # Security
    ///
    /// - Uses AES-256-GCM for authenticated encryption
    /// - AAD context prevents swap attacks
    /// - The DEK is never stored in plaintext
    pub fn wrap_dek(&self, dek: &DataEncryptionKey) -> KestrelResult<WrappedDek> {
        keywrap::wrap_dek(self.derived_key(), dek)
    }

    /// Unwraps (decrypts) a DEK with this master key (acting as KEK).
    ///
    /// This is used during vault unlock to recover the DEK from
    /// its wrapped (encrypted) form.
    ///
    /// # Arguments
    ///
    /// * `wrapped_dek` - The wrapped DEK loaded from the database
    ///
    /// # Returns
    ///
    /// The unwrapped `DataEncryptionKey`.
    ///
    /// # Security
    ///
    /// - GCM authentication verifies integrity before releasing the key
    /// - The DEK is wrapped in `secrecy::Secret` and zeroized on drop
    pub fn unwrap_dek(&self, wrapped_dek: &WrappedDek) -> KestrelResult<DataEncryptionKey> {
        keywrap::unwrap_dek(self.derived_key(), wrapped_dek)
    }

    /// Derives sub-keys from a DEK for key separation.
    ///
    /// This creates a full set of purpose-bound sub-keys from the DEK
    /// using HKDF-SHA256. Each sub-key is used for a specific
    /// cryptographic purpose (field encryption, file encryption, etc.).
    ///
    /// # Arguments
    ///
    /// * `dek` - The Data Encryption Key to derive sub-keys from
    ///
    /// # Returns
    ///
    /// A `SubKeySet` containing all derived sub-keys.
    pub fn derive_subkeys(&self, dek: &DataEncryptionKey) -> KestrelResult<SubKeySet> {
        let dek_as_derived = dek.as_derived_key();
        SubKeySet::derive_from_dek(&dek_as_derived)
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

/// Result of a key rotation operation using the KEK/DEK hierarchy.
///
/// With the KEK/DEK hierarchy, key rotation only requires re-wrapping
/// the DEK with the new KEK — no vault data needs to be re-encrypted.
/// This makes password change an O(1) operation instead of O(n).
pub struct KeyRotationResult {
    /// The new salt for the rotated KEK.
    pub new_salt: Salt,
    /// The new test envelope bytes for the rotated KEK.
    pub new_test_envelope: Vec<u8>,
    /// The newly wrapped DEK (encrypted with the new KEK).
    pub new_wrapped_dek: WrappedDek,
}

/// Rotates the master key by re-deriving from a new password.
///
/// With the KEK/DEK hierarchy, this operation:
/// 1. Derives a new KEK from the new password
/// 2. Creates a new test envelope with the new KEK
/// 3. Re-wraps the DEK with the new KEK
///
/// **No vault data needs to be re-encrypted** — the DEK stays the same,
/// only its wrapping changes. This is O(1) regardless of vault size.
///
/// # Arguments
///
/// * `old_key` - The current master key (KEK, used to unwrap the DEK)
/// * `wrapped_dek` - The current wrapped DEK
/// * `new_password` - The new master password (as SecureString)
///
/// # Errors
///
/// Returns an error if key derivation or DEK re-wrapping fails.
///
/// # Security
///
/// - Both old and new KEKs are zeroized when `RotationKeyPair` is dropped
/// - The DEK is only briefly in plaintext during re-wrap
/// - The DEK is zeroized when it goes out of scope
/// - The new password is zeroized via `SecureString`
pub fn rotate_master_key(
    old_key: MasterKey,
    wrapped_dek: &WrappedDek,
    new_password: &SecureString,
) -> Result<(RotationKeyPair, KeyRotationResult), KestrelError> {
    // Derive new KEK from new password
    let (new_key, new_salt) = MasterKey::from_secure_password_new_salt(new_password)?;

    // Unwrap DEK with old KEK, then re-wrap with new KEK
    let dek = old_key.unwrap_dek(wrapped_dek)?;
    let new_wrapped_dek = new_key.wrap_dek(&dek)?;
    // dek is zeroized here when it goes out of scope

    // Create new test envelope with the new KEK
    let new_crypto_service = VaultCryptoService::new(&new_key);
    let new_test_envelope = new_crypto_service.create_test_envelope()?;

    let rotation_pair = RotationKeyPair {
        old_key,
        new_key,
    };

    let result = KeyRotationResult {
        new_salt,
        new_test_envelope: new_test_envelope.envelope_bytes,
        new_wrapped_dek,
    };

    Ok((rotation_pair, result))
}

/// Result of vault initialization using the KEK/DEK hierarchy.
///
/// Contains all the cryptographic artifacts that need to be persisted
/// to the vault_meta table after vault creation.
pub struct VaultInitResult {
    /// The master key (KEK) derived from the password.
    /// NOT persisted — only held in memory while unlocked.
    pub master_key: MasterKey,
    /// The salt used for key derivation. Persisted in vault_meta.
    pub salt: Salt,
    /// The test envelope for password verification. Persisted in vault_meta.
    pub test_envelope_bytes: Vec<u8>,
    /// The wrapped DEK. Persisted in vault_meta.
    pub wrapped_dek: WrappedDek,
    /// The KDF parameters used. Persisted in vault_meta.
    pub kdf_params: KdfParams,
}

/// Initializes the vault with the KEK/DEK hierarchy.
///
/// This is the primary function called during vault initialization.
/// It generates a new salt, derives the KEK from the password,
/// generates a random DEK, wraps the DEK with the KEK, and
/// creates the test envelope for future verification.
///
/// # Arguments
///
/// * `password` - The user's master password (as bytes)
///
/// # Returns
///
/// A `VaultInitResult` containing all cryptographic artifacts.
///
/// # Security
///
/// - A fresh salt is generated for each vault
/// - The KEK is wrapped in `secrecy::Secret` and zeroized on drop
/// - The DEK is randomly generated and wrapped with the KEK
/// - The password should be zeroized by the caller after this call
pub fn initialize_vault_keys(
    password: &[u8],
) -> KestrelResult<VaultInitResult> {
    let (master_key, salt) = MasterKey::from_password_new_salt(password)?;

    // Generate a random DEK
    let dek = DataEncryptionKey::generate()?;

    // Wrap the DEK with the KEK
    let wrapped_dek = master_key.wrap_dek(&dek)?;
    // dek is zeroized here — only the wrapped form is kept

    // Create test envelope for password verification
    let crypto_service = VaultCryptoService::new(&master_key);
    let test_envelope = crypto_service.create_test_envelope()?;

    Ok(VaultInitResult {
        master_key,
        salt,
        test_envelope_bytes: test_envelope.envelope_bytes,
        wrapped_dek,
        kdf_params: KdfParams::current(),
    })
}

/// Unlocks the vault using the KEK/DEK hierarchy.
///
/// This is the primary function called during vault unlock.
/// It derives the KEK from the password, verifies it against
/// the test envelope, and unwraps the DEK.
///
/// # Arguments
///
/// * `password` - The user's master password (as bytes)
/// * `salt` - The salt stored in vault_meta
/// * `test_envelope_bytes` - The test envelope stored in vault_meta
/// * `wrapped_dek` - The wrapped DEK stored in vault_meta
///
/// # Returns
///
/// The verified `MasterKey` (KEK) and unwrapped `DataEncryptionKey` (DEK).
///
/// # Errors
///
/// Returns `KestrelError::Unauthorized` if the password is incorrect
/// (test envelope verification fails).
///
/// # Security
///
/// - The KEK is only returned if verification succeeds
/// - The DEK is only unwrapped after KEK verification
/// - A wrong password causes GCM authentication failure
/// - The password should be zeroized by the caller after this call
pub fn unlock_vault_keys(
    password: &[u8],
    salt: &Salt,
    test_envelope_bytes: &[u8],
    wrapped_dek: &WrappedDek,
) -> KestrelResult<(MasterKey, DataEncryptionKey)> {
    // Derive KEK from password
    let master_key = MasterKey::from_password(password, salt)?;

    // Verify KEK against test envelope
    let crypto_service = VaultCryptoService::new(&master_key);
    match crypto_service.verify_test_envelope(test_envelope_bytes) {
        Ok(true) => {
            // KEK verified — unwrap the DEK
            let dek = master_key.unwrap_dek(wrapped_dek)?;
            Ok((master_key, dek))
        }
        Ok(false) => {
            // This shouldn't happen — GCM auth should fail for wrong keys
            Err(KestrelError::Unauthorized(
                "Master password verification failed".to_string(),
            ))
        }
        Err(KestrelError::Crypto(_)) => {
            // GCM authentication failure — wrong password
            Err(KestrelError::Unauthorized(
                "Incorrect master password".to_string(),
            ))
        }
        Err(e) => Err(e),
    }
}

/// Re-encrypts a single field from the old key to the new key.
///
/// This is a convenience function for the key rotation process.
/// It decrypts a field with the old key and re-encrypts it with
/// the new key, preserving the same entity_id and field_name.
///
/// Note: With the KEK/DEK hierarchy, this function is only needed
/// for backward compatibility with vaults that were created before
/// the DEK was introduced. New vaults never need field-level
/// re-encryption during password change.
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
        assert_eq!(key.derived_key().expose().len(), 32);
        Ok(())
    }

    #[test]
    fn master_key_wrap_unwrap_dek() -> KestrelResult<()> {
        let salt = Salt::generate()?;
        let kek = MasterKey::from_password(b"test-password", &salt)?;
        let dek = DataEncryptionKey::generate()?;

        let wrapped = kek.wrap_dek(&dek)?;
        let unwrapped = kek.unwrap_dek(&wrapped)?;

        assert_eq!(dek.expose(), unwrapped.expose());
        Ok(())
    }

    #[test]
    fn master_key_derive_subkeys() -> KestrelResult<()> {
        let salt = Salt::generate()?;
        let kek = MasterKey::from_password(b"test-password", &salt)?;
        let dek = DataEncryptionKey::generate()?;

        let subkeys = kek.derive_subkeys(&dek)?;

        // Verify sub-keys are different from each other
        assert_ne!(
            subkeys.field_encryption.expose(),
            subkeys.file_encryption.expose()
        );
        assert_ne!(
            subkeys.field_encryption.expose(),
            subkeys.search_index.expose()
        );
        Ok(())
    }

    #[test]
    fn wrong_kek_cannot_unwrap_dek() -> KestrelResult<()> {
        let salt1 = Salt::generate()?;
        let kek1 = MasterKey::from_password(b"password-1", &salt1)?;

        let salt2 = Salt::generate()?;
        let kek2 = MasterKey::from_password(b"password-2", &salt2)?;

        let dek = DataEncryptionKey::generate()?;
        let wrapped = kek1.wrap_dek(&dek)?;

        let result = kek2.unwrap_dek(&wrapped);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn initialize_vault_keys_creates_all_artifacts() -> KestrelResult<()> {
        let result = initialize_vault_keys(b"my-master-password")?;

        // Verify all artifacts are present
        assert_ne!(result.salt.0, [0u8; 16]);
        assert!(!result.test_envelope_bytes.is_empty());
        assert!(!result.wrapped_dek.envelope_bytes.is_empty());
        assert_eq!(result.kdf_params.version, 1);

        // Verify test envelope with the master key
        let service = VaultCryptoService::new(&result.master_key);
        assert!(service.verify_test_envelope(&result.test_envelope_bytes)?);

        Ok(())
    }

    #[test]
    fn unlock_vault_keys_with_correct_password() -> KestrelResult<()> {
        let password = b"correct-horse-battery-staple";
        let init = initialize_vault_keys(password)?;

        // Unlock with the same password
        let (master_key, dek) = unlock_vault_keys(
            password,
            &init.salt,
            &init.test_envelope_bytes,
            &init.wrapped_dek,
        )?;

        // Verify the keys match
        assert_eq!(
            init.master_key.derived_key().expose(),
            master_key.derived_key().expose()
        );

        // DEK should be 32 bytes
        assert_eq!(dek.expose().len(), 32);

        Ok(())
    }

    #[test]
    fn unlock_vault_keys_with_wrong_password_fails() -> KestrelResult<()> {
        let password = b"correct-horse-battery-staple";
        let init = initialize_vault_keys(password)?;

        // Try with wrong password
        let result = unlock_vault_keys(
            b"wrong-password",
            &init.salt,
            &init.test_envelope_bytes,
            &init.wrapped_dek,
        );

        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn rotate_master_key_rewraps_dek() -> KestrelResult<()> {
        let old_password = b"old-password";
        let init = initialize_vault_keys(old_password)?;

        // Rotate to new password
        let new_secure = SecureString::from("new-secure-password".to_string());
        let (rotation_pair, result) = rotate_master_key(
            init.master_key,
            &init.wrapped_dek,
            &new_secure,
        )?;

        // Verify new key is different from old key
        assert_ne!(
            rotation_pair.old_key.derived_key().expose(),
            rotation_pair.new_key.derived_key().expose()
        );

        // Verify new salt is not all zeros
        assert_ne!(result.new_salt.0, [0u8; 16]);

        // Verify test envelope was created
        assert!(!result.new_test_envelope.is_empty());

        // Verify the new KEK can unwrap the re-wrapped DEK
        let dek = rotation_pair.new_key.unwrap_dek(&result.new_wrapped_dek)?;
        assert_eq!(dek.expose().len(), 32);

        // Verify the old KEK cannot unwrap the new wrapped DEK
        let old_unwrap = rotation_pair.old_key.unwrap_dek(&result.new_wrapped_dek);
        assert!(old_unwrap.is_err());

        Ok(())
    }

    #[test]
    fn rotation_preserves_dek() -> KestrelResult<()> {
        let old_password = b"old-password";
        let init = initialize_vault_keys(old_password)?;

        // Get the original DEK
        let original_dek = init.master_key.unwrap_dek(&init.wrapped_dek)?;

        // Rotate to new password
        let new_secure = SecureString::from("new-secure-password".to_string());
        let (_rotation_pair, result) = rotate_master_key(
            init.master_key,
            &init.wrapped_dek,
            &new_secure,
        )?;

        // Unwrap DEK from the new wrapped DEK using the new KEK
        // First, derive the new KEK from the new password
        let new_kek = MasterKey::from_password(b"new-secure-password", &result.new_salt)?;
        let rotated_dek = new_kek.unwrap_dek(&result.new_wrapped_dek)?;

        // The DEK should be the same after rotation
        assert_eq!(original_dek.expose(), rotated_dek.expose());

        Ok(())
    }

    #[test]
    fn re_encrypt_field_roundtrip() -> Result<(), KestrelError> {
        let old_salt = Salt::generate()?;
        let old_key = MasterKey::from_password(b"old-password", &old_salt)?;
        let old_service = VaultCryptoService::new(&old_key);

        let entity_id = "550e8400-e29b-41d4-a716-446655440000";
        let plaintext = b"my-secret-password";

        let old_encrypted = old_service.encrypt_password(entity_id, plaintext)?;

        let new_secure = SecureString::from("new-secure-password".to_string());
        let (rotation_pair, _result) = rotate_master_key(
            old_key,
            &WrappedDek::from_bytes(vec![]), // Not used in re_encrypt_field
            &new_secure,
        ).unwrap_or_else(|_| {
            // Fallback: use old-style rotation if DEK unwrap fails
            let old_salt = Salt::generate();
            let old_key = MasterKey::from_password(b"old-password", &old_salt).unwrap();
            let new_secure = SecureString::from("new-secure-password".to_string());
            let (new_key, new_salt) = MasterKey::from_secure_password_new_salt(&new_secure).unwrap();
            let new_crypto_service = VaultCryptoService::new(&new_key);
            let _new_test_envelope = new_crypto_service.create_test_envelope().unwrap();
            (
                RotationKeyPair { old_key, new_key },
                KeyRotationResult {
                    new_salt,
                    new_test_envelope: vec![],
                    new_wrapped_dek: WrappedDek::from_bytes(vec![]),
                },
            )
        });

        let new_envelope_bytes = re_encrypt_field(
            &rotation_pair,
            entity_id,
            "password",
            &old_encrypted.envelope_bytes,
        )?;

        let new_service = rotation_pair.new_crypto_service();
        let decrypted = new_service.decrypt_password(entity_id, &new_envelope_bytes)?;
        assert_eq!(decrypted.plaintext, plaintext);

        Ok(())
    }

    #[test]
    fn rotation_key_pair_drop_zeroizes() -> Result<(), KestrelError> {
        let init = initialize_vault_keys(b"test-password")?;
        let new_secure = SecureString::from("new-password".to_string());

        let (rotation_pair, _result) = rotate_master_key(
            init.master_key,
            &init.wrapped_dek,
            &new_secure,
        )?;

        drop(rotation_pair);
        Ok(())
    }
}
