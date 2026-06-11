//! Vault crypto service for KESTREL Vault.
//!
//! This module provides the high-level encryption/decryption operations
//! used by the vault service layer. It bridges the low-level crypto
//! primitives (envelope encryption, AAD context) with the domain types
//! (VaultEntry, encrypted fields).
//!
//! # Architecture (KEK/DEK Hierarchy)
//!
//! ```text
//! ┌──────────────┐     ┌─────────────────────┐     ┌──────────────────┐
//! │ Command Layer │────▶│ VaultCryptoService  │────▶│ Envelope / Cipher │
//! │ (auth/vault)  │     │ (field-level ops)   │     │ (AES-256-GCM)    │
//! └──────────────┘     └─────────────────────┘     └──────────────────┘
//!                              │
//!                     ┌────────┴────────┐
//!                     │                 │
//!                KEK (MasterKey)    DEK (DataEncryptionKey)
//!                test envelope      field encryption
//!                key wrapping       sub-key derivation
//! ```
//!
//! # Two Service Modes
//!
//! 1. **KEK mode** (`VaultCryptoService::new_kek`): Uses the master key (KEK)
//!    for test envelope creation/verification and DEK wrap/unwrap.
//!    Never used for bulk data encryption.
//!
//! 2. **DEK mode** (`VaultCryptoService::new_dek`): Uses the data encryption
//!    key (DEK) or a sub-key for field-level encryption/decryption.
//!    This is the primary mode for vault operations.
//!
//! # Security
//!
//! - Every encrypted field is bound to its entity via AAD context
//! - The KEK is never used for data encryption (key separation)
//! - The DEK is never exposed outside this service
//! - All plaintext is zeroized after use
//! - Fresh nonces are generated for every encryption

use crate::crypto::envelope::{self, AadContext, EncryptedEnvelope};
use crate::crypto::key_management::MasterKey;
use crate::crypto::keywrap::DataEncryptionKey;
use crate::crypto::kdf::{DerivedKey, Salt};
use crate::crypto::subkeys::SubKey;
use crate::error::{KestrelError, KestrelResult};
use zeroize::Zeroize;

/// The known plaintext used for the test envelope during vault initialization.
///
/// This constant is used to verify the master password: the vault stores an
/// envelope encrypting this known value. On unlock, we decrypt and compare.
/// If the decryption succeeds and the plaintext matches, the password is correct.
///
/// # Security
///
/// This value is public and not secret. It serves as a verification token,
/// not as a secret. The security comes from the AES-256-GCM authentication
/// tag — a wrong key will cause decryption to fail entirely.
pub const TEST_ENVELOPE_PLAINTEXT: &[u8] = b"KESTREL_VAULT_VERIFICATION_V1";

/// Field names used in AAD contexts.
///
/// These are the standardized field names that bind encrypted data
/// to its intended use. Changing these would break existing envelopes.
pub mod field_names {
    /// The password field of a vault entry.
    pub const PASSWORD: &str = "password";
    /// The notes field of a vault entry.
    pub const NOTES: &str = "notes";
    /// The TOTP secret field of a vault entry.
    pub const TOTP_SECRET: &str = "totp_secret";
    /// The URL field of a vault entry (encrypted for privacy).
    pub const URL: &str = "url";
    /// The tags field of a vault entry (encrypted for privacy).
    pub const TAGS: &str = "tags";
    /// The test envelope field (for vault verification).
    pub const TEST_ENVELOPE: &str = "test_envelope";
}

/// Result of encrypting a vault field.
///
/// Contains the serialized envelope bytes ready for database storage.
/// The AAD context is embedded in the envelope structure.
#[derive(Debug, Clone)]
pub struct EncryptedField {
    /// The serialized envelope bytes for database storage.
    pub envelope_bytes: Vec<u8>,
}

/// Result of decrypting a vault field.
///
/// Contains the plaintext bytes. The caller is responsible for
/// converting to the appropriate type and zeroizing when done.
#[derive(Debug)]
pub struct DecryptedField {
    /// The decrypted plaintext bytes.
    pub plaintext: Vec<u8>,
}

impl Drop for DecryptedField {
    fn drop(&mut self) {
        self.plaintext.zeroize();
    }
}

/// The vault crypto service.
///
/// This service provides field-level encryption and decryption operations
/// for vault data. It supports two modes:
///
/// 1. **KEK mode**: Uses the master key for test envelope operations
///    and DEK wrap/unwrap. Created with `VaultCryptoService::new()`.
///
/// 2. **DEK mode**: Uses the data encryption key for field-level
///    encryption/decryption. Created with `VaultCryptoService::new_dek()`.
///
/// # Thread Safety
///
/// This struct holds references to keys and is NOT thread-safe
/// by itself. The caller must wrap it in appropriate synchronization
/// primitives.
///
/// # Usage
///
/// ```ignore
/// // KEK mode (for test envelope and DEK wrapping)
/// let kek_service = VaultCryptoService::new(&master_key);
/// let test_envelope = kek_service.create_test_envelope()?;
///
/// // DEK mode (for field-level encryption)
/// let dek_service = VaultCryptoService::new_dek(&dek);
/// let encrypted = dek_service.encrypt_field("entry-uuid-123", "password", b"my-secret")?;
/// let decrypted = dek_service.decrypt_field("entry-uuid-123", "password", &encrypted.envelope_bytes)?;
/// ```
pub enum VaultCryptoService<'a> {
    /// KEK mode: Uses the master key for test envelope and DEK wrap/unwrap.
    Kek(&'a MasterKey),
    /// DEK mode: Uses the data encryption key for field-level encryption.
    Dek(&'a DataEncryptionKey),
    /// SubKey mode: Uses a specific sub-key for purpose-bound encryption.
    SubKey(&'a SubKey),
}

impl<'a> VaultCryptoService<'a> {
    /// Creates a new vault crypto service in KEK mode.
    ///
    /// The master key must be valid and correspond to the current vault.
    /// KEK mode is used for test envelope creation/verification.
    pub fn new(key: &'a MasterKey) -> Self {
        VaultCryptoService::Kek(key)
    }

    /// Creates a new vault crypto service in DEK mode.
    ///
    /// DEK mode is used for field-level encryption/decryption
    /// of vault data. This is the primary mode for vault operations.
    pub fn new_dek(dek: &'a DataEncryptionKey) -> Self {
        VaultCryptoService::Dek(dek)
    }

    /// Creates a vault crypto service from a sub-key.
    ///
    /// SubKey mode is used for purpose-bound encryption
    /// (e.g., field encryption, file encryption).
    pub fn from_subkey(subkey: &'a SubKey) -> Self {
        VaultCryptoService::SubKey(subkey)
    }

    /// Returns the derived key for encryption/decryption operations.
    ///
    /// In KEK mode, returns the master key's derived key.
    /// In DEK mode, returns the DEK as a DerivedKey.
    /// In SubKey mode, returns the sub-key as a DerivedKey.
    fn encryption_key(&self) -> DerivedKey {
        match self {
            VaultCryptoService::Kek(key) => key.derived_key().clone(),
            VaultCryptoService::Dek(dek) => dek.as_derived_key(),
            VaultCryptoService::SubKey(sk) => sk.as_derived_key(),
        }
    }

    /// Encrypts a single vault field.
    ///
    /// Uses envelope encryption with AAD context binding the entity ID
    /// and field name. This prevents swap attacks where ciphertext from
    /// one field is moved to another, or from one entry to another.
    ///
    /// # Arguments
    ///
    /// * `entity_id` - The UUID of the entity (e.g., vault entry ID)
    /// * `field_name` - The name of the field being encrypted
    /// * `plaintext` - The data to encrypt
    ///
    /// # Returns
    ///
    /// An `EncryptedField` containing the serialized envelope bytes
    /// ready for database storage.
    ///
    /// # Errors
    ///
    /// Returns `KestrelError::Crypto` if encryption fails.
    pub fn encrypt_field(
        &self,
        entity_id: &str,
        field_name: &str,
        plaintext: &[u8],
    ) -> KestrelResult<EncryptedField> {
        let key = self.encryption_key();
        let envelope = envelope::seal_envelope(
            &key,
            plaintext,
            entity_id,
            field_name,
        )?;

        Ok(EncryptedField {
            envelope_bytes: envelope.to_bytes(),
        })
    }

    /// Decrypts a single vault field.
    ///
    /// Reconstructs the envelope from the stored bytes, verifies the
    /// AAD context, and returns the plaintext. If the key is wrong,
    /// the ciphertext has been tampered with, or the AAD context
    /// doesn't match, decryption will fail.
    ///
    /// # Arguments
    ///
    /// * `entity_id` - The UUID of the entity (must match encryption)
    /// * `field_name` - The name of the field (must match encryption)
    /// * `envelope_bytes` - The serialized envelope from the database
    ///
    /// # Returns
    ///
    /// A `DecryptedField` containing the plaintext bytes. The plaintext
    /// is automatically zeroized when the `DecryptedField` is dropped.
    ///
    /// # Errors
    ///
    /// Returns `KestrelError::Crypto` if:
    /// - The key is incorrect (wrong master password)
    /// - The ciphertext has been tampered with
    /// - The AAD context doesn't match (swap attack)
    pub fn decrypt_field(
        &self,
        entity_id: &str,
        field_name: &str,
        envelope_bytes: &[u8],
    ) -> KestrelResult<DecryptedField> {
        let key = self.encryption_key();
        let aad_context = AadContext::new(entity_id, field_name);
        let envelope = EncryptedEnvelope::from_bytes(envelope_bytes, aad_context)?;

        let plaintext = envelope::open_envelope(&key, &envelope)?;

        Ok(DecryptedField { plaintext })
    }

    /// Creates the test envelope for vault verification.
    ///
    /// The test envelope encrypts a known plaintext value. On unlock,
    /// we attempt to decrypt this envelope — success proves the master
    /// password is correct without storing it.
    ///
    /// # Security
    ///
    /// The test envelope uses a special entity ID and field name to
    /// distinguish it from vault entry envelopes. It cannot be confused
    /// with any vault entry envelope because the AAD context is different.
    pub fn create_test_envelope(&self) -> KestrelResult<EncryptedField> {
        self.encrypt_field(
            "vault_meta",
            field_names::TEST_ENVELOPE,
            TEST_ENVELOPE_PLAINTEXT,
        )
    }

    /// Verifies the master key against a stored test envelope.
    ///
    /// Attempts to decrypt the test envelope and compare the plaintext
    /// against the expected value. Success means the master password
    /// is correct.
    ///
    /// # Security
    ///
    /// This does NOT leak timing information about the plaintext
    /// comparison because AES-256-GCM authentication fails entirely
    /// for wrong keys — we never reach the comparison step.
    pub fn verify_test_envelope(&self, envelope_bytes: &[u8]) -> KestrelResult<bool> {
        let decrypted = self.decrypt_field(
            "vault_meta",
            field_names::TEST_ENVELOPE,
            envelope_bytes,
        )?;

        Ok(decrypted.plaintext == TEST_ENVELOPE_PLAINTEXT)
    }

    /// Encrypts the password field of a vault entry.
    ///
    /// Convenience wrapper around `encrypt_field` with the password
    /// field name pre-set.
    pub fn encrypt_password(
        &self,
        entry_id: &str,
        password: &[u8],
    ) -> KestrelResult<EncryptedField> {
        self.encrypt_field(entry_id, field_names::PASSWORD, password)
    }

    /// Decrypts the password field of a vault entry.
    ///
    /// Convenience wrapper around `decrypt_field` with the password
    /// field name pre-set.
    pub fn decrypt_password(
        &self,
        entry_id: &str,
        envelope_bytes: &[u8],
    ) -> KestrelResult<DecryptedField> {
        self.decrypt_field(entry_id, field_names::PASSWORD, envelope_bytes)
    }

    /// Encrypts the notes field of a vault entry.
    pub fn encrypt_notes(
        &self,
        entry_id: &str,
        notes: &[u8],
    ) -> KestrelResult<EncryptedField> {
        self.encrypt_field(entry_id, field_names::NOTES, notes)
    }

    /// Decrypts the notes field of a vault entry.
    pub fn decrypt_notes(
        &self,
        entry_id: &str,
        envelope_bytes: &[u8],
    ) -> KestrelResult<DecryptedField> {
        self.decrypt_field(entry_id, field_names::NOTES, envelope_bytes)
    }

    /// Encrypts the TOTP secret field of a vault entry.
    pub fn encrypt_totp_secret(
        &self,
        entry_id: &str,
        secret: &[u8],
    ) -> KestrelResult<EncryptedField> {
        self.encrypt_field(entry_id, field_names::TOTP_SECRET, secret)
    }

    /// Decrypts the TOTP secret field of a vault entry.
    pub fn decrypt_totp_secret(
        &self,
        entry_id: &str,
        envelope_bytes: &[u8],
    ) -> KestrelResult<DecryptedField> {
        self.decrypt_field(entry_id, field_names::TOTP_SECRET, envelope_bytes)
    }
}

/// Derives a master key and creates the initial vault metadata.
///
/// This is the primary function called during vault initialization.
/// It generates a new salt, derives the master key from the password,
/// and creates the test envelope for future verification.
///
/// # Arguments
///
/// * `password` - The user's master password (as bytes)
///
/// # Returns
///
/// A tuple of (MasterKey, Salt, test_envelope_bytes).
///
/// # Security
///
/// - A fresh salt is generated for each vault
/// - The master key is wrapped in `secrecy::Secret` and zeroized on drop
/// - The password should be zeroized by the caller after this call
pub fn initialize_vault_crypto(
    password: &[u8],
) -> KestrelResult<(MasterKey, Salt, Vec<u8>)> {
    let (master_key, salt) = MasterKey::from_password_new_salt(password)?;

    let crypto_service = VaultCryptoService::new(&master_key);
    let test_envelope = crypto_service.create_test_envelope()?;

    Ok((master_key, salt, test_envelope.envelope_bytes))
}

/// Derives a master key from a password and existing salt, then
/// verifies it against the stored test envelope.
///
/// This is the primary function called during vault unlock.
/// It derives the key from the password and salt, then attempts
/// to verify the test envelope. Success means the password is correct.
///
/// # Arguments
///
/// * `password` - The user's master password (as bytes)
/// * `salt` - The salt stored in vault_meta
/// * `test_envelope_bytes` - The test envelope stored in vault_meta
///
/// # Returns
///
/// The verified `MasterKey` on success.
///
/// # Errors
///
/// Returns `KestrelError::Unauthorized` if the password is incorrect
/// (test envelope verification fails).
///
/// # Security
///
/// - The master key is only returned if verification succeeds
/// - A wrong password causes GCM authentication failure
/// - The password should be zeroized by the caller after this call
pub fn unlock_vault_crypto(
    password: &[u8],
    salt: &Salt,
    test_envelope_bytes: &[u8],
) -> KestrelResult<MasterKey> {
    let master_key = MasterKey::from_password(password, salt)?;

    let crypto_service = VaultCryptoService::new(&master_key);
    match crypto_service.verify_test_envelope(test_envelope_bytes) {
        Ok(true) => Ok(master_key),
        Ok(false) => {
            // This shouldn't happen — GCM auth should fail for wrong keys.
            // But handle it defensively.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::Salt;

    /// Helper: creates a test master key.
    fn test_master_key() -> MasterKey {
        let salt = Salt([0x42u8; 16]);
        MasterKey::from_password(b"test-master-password", &salt).unwrap()
    }

    // ── VaultCryptoService tests ──

    #[test]
    fn encrypt_decrypt_password_roundtrip() {
        let key = test_master_key();
        let service = VaultCryptoService::new(&key);
        let entry_id = "550e8400-e29b-41d4-a716-446655440000";

        let encrypted = service
            .encrypt_password(entry_id, b"my-secret-password")
            .unwrap();

        let decrypted = service
            .decrypt_password(entry_id, &encrypted.envelope_bytes)
            .unwrap();

        assert_eq!(decrypted.plaintext, b"my-secret-password");
    }

    #[test]
    fn encrypt_decrypt_notes_roundtrip() {
        let key = test_master_key();
        let service = VaultCryptoService::new(&key);
        let entry_id = "550e8400-e29b-41d4-a716-446655440000";

        let encrypted = service
            .encrypt_notes(entry_id, b"these are my secret notes")
            .unwrap();

        let decrypted = service
            .decrypt_notes(entry_id, &encrypted.envelope_bytes)
            .unwrap();

        assert_eq!(decrypted.plaintext, b"these are my secret notes");
    }

    #[test]
    fn encrypt_decrypt_totp_roundtrip() {
        let key = test_master_key();
        let service = VaultCryptoService::new(&key);
        let entry_id = "550e8400-e29b-41d4-a716-446655440000";

        let encrypted = service
            .encrypt_totp_secret(entry_id, b"JBSWY3DPEHPK3PXP")
            .unwrap();

        let decrypted = service
            .decrypt_totp_secret(entry_id, &encrypted.envelope_bytes)
            .unwrap();

        assert_eq!(decrypted.plaintext, b"JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn wrong_entry_id_fails_decryption() {
        let key = test_master_key();
        let service = VaultCryptoService::new(&key);

        let encrypted = service
            .encrypt_password("entry-1", b"secret")
            .unwrap();

        // Try to decrypt with wrong entry ID (swap attack)
        let result = service.decrypt_password("entry-2", &encrypted.envelope_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_field_name_fails_decryption() {
        let key = test_master_key();
        let service = VaultCryptoService::new(&key);
        let entry_id = "550e8400-e29b-41d4-a716-446655440000";

        let encrypted = service
            .encrypt_password(entry_id, b"secret")
            .unwrap();

        // Try to decrypt as notes instead of password (swap attack)
        let result = service.decrypt_notes(entry_id, &encrypted.envelope_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn tampered_ciphertext_fails_decryption() {
        let key = test_master_key();
        let service = VaultCryptoService::new(&key);
        let entry_id = "550e8400-e29b-41d4-a716-446655440000";

        let encrypted = service
            .encrypt_password(entry_id, b"secret")
            .unwrap();

        let mut tampered = encrypted.envelope_bytes.clone();
        if tampered.len() > 29 {
            // Tamper with a ciphertext byte
            tampered[tampered.len() - 1] ^= 0xFF;
        }

        let result = service.decrypt_password(entry_id, &tampered);
        assert!(result.is_err());
    }

    // ── Test envelope tests ──

    #[test]
    fn test_envelope_create_and_verify() {
        let key = test_master_key();
        let service = VaultCryptoService::new(&key);

        let encrypted = service.create_test_envelope().unwrap();

        let is_valid = service
            .verify_test_envelope(&encrypted.envelope_bytes)
            .unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_envelope_wrong_key_fails() {
        let salt1 = Salt([0x42u8; 16]);
        let salt2 = Salt([0x99u8; 16]);
        let key1 = MasterKey::from_password(b"password-1", &salt1).unwrap();
        let key2 = MasterKey::from_password(b"password-2", &salt2).unwrap();

        let service1 = VaultCryptoService::new(&key1);
        let encrypted = service1.create_test_envelope().unwrap();

        let service2 = VaultCryptoService::new(&key2);
        let result = service2.verify_test_envelope(&encrypted.envelope_bytes);
        assert!(result.is_err());
    }

    // ── initialize_vault_crypto tests ──

    #[test]
    fn initialize_vault_crypto_produces_valid_envelope() {
        let (master_key, salt, test_envelope) =
            initialize_vault_crypto(b"my-master-password").unwrap();

        // Verify the test envelope with the same key
        let service = VaultCryptoService::new(&master_key);
        let is_valid = service.verify_test_envelope(&test_envelope).unwrap();
        assert!(is_valid);

        // Salt should not be all zeros
        assert_ne!(salt.0, [0u8; 16]);
    }

    // ── unlock_vault_crypto tests ──

    #[test]
    fn unlock_vault_crypto_succeeds_with_correct_password() {
        let password = b"correct-horse-battery-staple";
        let (master_key, salt, test_envelope) =
            initialize_vault_crypto(password).unwrap();

        // Unlock with the same password
        let unlocked_key = unlock_vault_crypto(password, &salt, &test_envelope).unwrap();

        // The keys should be identical
        assert_eq!(
            master_key.derived_key().expose(),
            unlocked_key.derived_key().expose()
        );
    }

    #[test]
    fn unlock_vault_crypto_fails_with_wrong_password() {
        let password = b"correct-horse-battery-staple";
        let (_, salt, test_envelope) = initialize_vault_crypto(password).unwrap();

        // Try to unlock with wrong password
        let result = unlock_vault_crypto(b"wrong-password", &salt, &test_envelope);
        assert!(result.is_err());
    }

    // ── DecryptedField zeroization test ──

    #[test]
    fn decrypted_field_zeroizes_on_drop() {
        let key = test_master_key();
        let service = VaultCryptoService::new(&key);
        let entry_id = "550e8400-e29b-41d4-a716-446655440000";

        let encrypted = service
            .encrypt_password(entry_id, b"secret-data")
            .unwrap();

        {
            let _decrypted = service
                .decrypt_password(entry_id, &encrypted.envelope_bytes)
                .unwrap();
            // decrypted goes out of scope here and is zeroized
        }

        // We can't easily verify zeroization from outside,
        // but the Drop impl should have run. This test
        // ensures the code path exists without panicking.
    }

    // ── Generic field encryption test ──

    #[test]
    fn encrypt_decrypt_generic_field() {
        let key = test_master_key();
        let service = VaultCryptoService::new(&key);

        let encrypted = service
            .encrypt_field("custom-entity", "custom_field", b"custom data")
            .unwrap();

        let decrypted = service
            .decrypt_field("custom-entity", "custom_field", &encrypted.envelope_bytes)
            .unwrap();

        assert_eq!(decrypted.plaintext, b"custom data");
    }

    #[test]
    fn empty_plaintext_encrypts_successfully() {
        let key = test_master_key();
        let service = VaultCryptoService::new(&key);

        let encrypted = service
            .encrypt_field("entity-1", "empty_field", b"")
            .unwrap();

        let decrypted = service
            .decrypt_field("entity-1", "empty_field", &encrypted.envelope_bytes)
            .unwrap();

        assert_eq!(decrypted.plaintext, b"");
    }

    #[test]
    fn large_plaintext_encrypts_successfully() {
        let key = test_master_key();
        let service = VaultCryptoService::new(&key);

        let large_data = vec![0x41u8; 10_000]; // 10 KB
        let encrypted = service
            .encrypt_field("entity-1", "large_field", &large_data)
            .unwrap();

        let decrypted = service
            .decrypt_field("entity-1", "large_field", &encrypted.envelope_bytes)
            .unwrap();

        assert_eq!(decrypted.plaintext, large_data);
    }
}
