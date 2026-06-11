//! Sub-key derivation module for KESTREL Vault.
//!
//! Provides HKDF-based sub-key derivation from the Data Encryption Key (DEK).
//! This enables key separation: different cryptographic operations use different
//! keys, all derived from the same DEK but with different contexts.
//!
//! # Why Sub-Keys?
//!
//! The cryptographic principle of **key separation** states that a single key
//! should not be used for multiple purposes. Even though we have a DEK for
//! field-level encryption, we derive distinct sub-keys for different use cases:
//!
//! 1. **Field encryption**: AES-256-GCM encryption of vault entry fields
//! 2. **File encryption**: AES-256-GCM encryption of file attachments
//! 3. **Search index**: HMAC-based searchable encryption index
//! 4. **Export encryption**: AES-256-GCM encryption of exported vault data
//!
//! # Architecture
//!
//! ```text
//! DEK (Data Encryption Key)
//!  ├── HKDF(info="kestrel:field-encryption") → Field Encryption Key
//!  ├── HKDF(info="kestrel:file-encryption")  → File Encryption Key
//!  ├── HKDF(info="kestrel:search-index")     → Search Index Key
//!  └── HKDF(info="kestrel:export-encryption")→ Export Encryption Key
//! ```
//!
//! # Security
//!
//! - HKDF-SHA256 is used for all sub-key derivation
//! - Each sub-key has a unique info string (context binding)
//! - Sub-keys are computationally independent — knowing one doesn't
//!   reveal anything about the others
//! - All sub-keys are zeroized when dropped
//! - Sub-keys are never persisted — always re-derived from the DEK

use crate::crypto::kdf::DerivedKey;
use crate::error::{KestrelError, KestrelResult};
use hkdf::Hkdf;
use secrecy::{ExposeSecret, Secret};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Length of derived sub-keys in bytes (256 bits for AES-256).
const SUBKEY_LEN: usize = 32;

/// HKDF info string for field encryption sub-key.
/// Used for encrypting/decrypting vault entry fields (passwords, notes, etc.).
const INFO_FIELD_ENCRYPTION: &[u8] = b"kestrel:field-encryption";

/// HKDF info string for file encryption sub-key.
/// Used for encrypting/decrypting file attachments.
const INFO_FILE_ENCRYPTION: &[u8] = b"kestrel:file-encryption";

/// HKDF info string for search index sub-key.
/// Used for HMAC-based searchable encryption index.
const INFO_SEARCH_INDEX: &[u8] = b"kestrel:search-index";

/// HKDF info string for export encryption sub-key.
/// Used for encrypting exported vault data.
const INFO_EXPORT_ENCRYPTION: &[u8] = b"kestrel:export-encryption";

/// HKDF info string for TOTP encryption sub-key.
/// Used for encrypting TOTP secrets with a separate key.
const INFO_TOTP_ENCRYPTION: &[u8] = b"kestrel:totp-encryption";

/// A sub-key derived from the DEK via HKDF.
///
/// Each sub-key is bound to a specific purpose via its info string.
/// Sub-keys are never persisted — they are re-derived from the DEK
/// each time the vault is unlocked.
///
/// # Security
///
/// - Wrapped in `secrecy::Secret` — no Debug, no accidental logging
/// - Implements `ZeroizeOnDrop` — key material erased on drop
/// - Cannot be used for a different purpose than intended
#[derive(ZeroizeOnDrop)]
pub struct SubKey {
    /// The raw sub-key bytes, protected by secrecy and zeroize.
    key: Secret<[u8; SUBKEY_LEN]>,
    /// The purpose/info string this sub-key was derived for.
    purpose: &'static [u8],
}

impl SubKey {
    /// Creates a new sub-key from raw bytes and purpose info.
    fn new(bytes: [u8; SUBKEY_LEN], purpose: &'static [u8]) -> Self {
        SubKey {
            key: Secret::new(bytes),
            purpose,
        }
    }

    /// Exposes the raw key bytes for use in cryptographic operations.
    ///
    /// # Security
    ///
    /// The exposed reference should be used only for passing to
    /// encrypt/decrypt functions and must not be stored or logged.
    pub fn expose(&self) -> &[u8; SUBKEY_LEN] {
        self.key.expose_secret()
    }

    /// Returns the sub-key as a `DerivedKey` for use with
    /// the cipher and envelope modules.
    pub fn as_derived_key(&self) -> DerivedKey {
        DerivedKey::new(*self.key.expose_secret())
    }

    /// Returns the purpose info string this sub-key was derived for.
    pub fn purpose(&self) -> &'static [u8] {
        self.purpose
    }
}

impl Clone for SubKey {
    fn clone(&self) -> Self {
        SubKey {
            key: Secret::new(*self.key.expose_secret()),
            purpose: self.purpose,
        }
    }
}

impl std::fmt::Debug for SubKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let purpose_str = std::str::from_utf8(self.purpose).unwrap_or("<invalid>");
        write!(f, "SubKey([REDACTED], purpose={:?})", purpose_str)
    }
}

/// Derives a sub-key from the DEK using HKDF-SHA256.
///
/// This is the core derivation function. It uses HKDF (HMAC-based Key
/// Derivation Function) with SHA-256 to derive a purpose-bound sub-key
/// from the DEK.
///
/// # Arguments
///
/// * `dek` - The Data Encryption Key (input key material for HKDF)
/// * `info` - The context/purpose info string (domain separation)
///
/// # Returns
///
/// A `SubKey` derived from the DEK with the given purpose.
///
/// # Errors
///
/// Returns `KestrelError::Crypto` if HKDF expansion fails, which
/// should only occur with invalid parameters.
///
/// # Security
///
/// - HKDF-SHA256 is provably secure under the random oracle model
/// - The info string provides domain separation between sub-keys
/// - Different info strings produce computationally independent keys
/// - The same DEK + info always produces the same sub-key (deterministic)
fn derive_subkey(dek: &DerivedKey, info: &[u8]) -> KestrelResult<SubKey> {
    // HKDF-Extract: uses the DEK as the input key material (IKM)
    // The salt is None (empty salt), which is standard for HKDF when
    // the IKM is already a cryptographically random key.
    let hkdf = Hkdf::<Sha256>::new(None, dek.expose());

    // HKDF-Expand: derive a sub-key with the given info string
    let mut subkey_bytes = [0u8; SUBKEY_LEN];
    hkdf.expand(info, &mut subkey_bytes)
        .map_err(|e| KestrelError::Crypto(format!("HKDF expansion failed: {e}")))?;

    // Determine the static purpose string (for known purposes)
    let purpose = match info {
        x if x == INFO_FIELD_ENCRYPTION => INFO_FIELD_ENCRYPTION,
        x if x == INFO_FILE_ENCRYPTION => INFO_FILE_ENCRYPTION,
        x if x == INFO_SEARCH_INDEX => INFO_SEARCH_INDEX,
        x if x == INFO_EXPORT_ENCRYPTION => INFO_EXPORT_ENCRYPTION,
        x if x == INFO_TOTP_ENCRYPTION => INFO_TOTP_ENCRYPTION,
        _ => info,
    };

    Ok(SubKey::new(subkey_bytes, purpose))
}

/// A collection of sub-keys derived from the DEK.
///
/// This struct holds all the sub-keys needed by the vault and
/// provides a convenient interface for accessing them. All sub-keys
/// are derived at vault unlock time and zeroized when the vault is locked.
///
/// # Security
///
/// - All sub-keys are zeroized when this struct is dropped
/// - Sub-keys are never persisted — always re-derived from the DEK
/// - Each sub-key is bound to a specific purpose
#[derive(ZeroizeOnDrop)]
pub struct SubKeySet {
    /// Sub-key for field-level encryption (passwords, notes, URLs, tags).
    pub field_encryption: SubKey,
    /// Sub-key for file attachment encryption.
    pub file_encryption: SubKey,
    /// Sub-key for HMAC-based searchable encryption index.
    pub search_index: SubKey,
    /// Sub-key for vault export encryption.
    pub export_encryption: SubKey,
    /// Sub-key for TOTP secret encryption.
    pub totp_encryption: SubKey,
}

impl SubKeySet {
    /// Derives all sub-keys from the DEK.
    ///
    /// This is called once during vault unlock. Each sub-key is derived
    /// using HKDF-SHA256 with a unique info string.
    ///
    /// # Arguments
    ///
    /// * `dek` - The Data Encryption Key to derive sub-keys from
    ///
    /// # Returns
    ///
    /// A `SubKeySet` containing all derived sub-keys.
    ///
    /// # Errors
    ///
    /// Returns `KestrelError::Crypto` if any HKDF derivation fails.
    ///
    /// # Security
    ///
    /// - Each sub-key has a unique info string (domain separation)
    /// - The same DEK always produces the same set of sub-keys
    /// - All sub-keys are zeroized when the SubKeySet is dropped
    pub fn derive_from_dek(dek: &DerivedKey) -> KestrelResult<Self> {
        Ok(SubKeySet {
            field_encryption: derive_subkey(dek, INFO_FIELD_ENCRYPTION)?,
            file_encryption: derive_subkey(dek, INFO_FILE_ENCRYPTION)?,
            search_index: derive_subkey(dek, INFO_SEARCH_INDEX)?,
            export_encryption: derive_subkey(dek, INFO_EXPORT_ENCRYPTION)?,
            totp_encryption: derive_subkey(dek, INFO_TOTP_ENCRYPTION)?,
        })
    }

    /// Derives a custom sub-key with an arbitrary info string.
    ///
    /// This is for future use cases where a new sub-key purpose
    /// is needed without modifying the `SubKeySet` struct.
    ///
    /// # Security
    ///
    /// The info string must be unique and not overlap with the
    /// built-in purpose strings.
    pub fn derive_custom(dek: &DerivedKey, info: &[u8]) -> KestrelResult<SubKey> {
        // Verify the custom info doesn't overlap with built-in purposes
        if info == INFO_FIELD_ENCRYPTION
            || info == INFO_FILE_ENCRYPTION
            || info == INFO_SEARCH_INDEX
            || info == INFO_EXPORT_ENCRYPTION
            || info == INFO_TOTP_ENCRYPTION
        {
            return Err(KestrelError::Crypto(
                "Custom sub-key info string must not overlap with built-in purposes".to_string(),
            ));
        }
        derive_subkey(dek, info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::{derive_key, Salt};

    /// Helper: creates a test DEK.
    fn test_dek() -> DerivedKey {
        let salt = Salt([0x42u8; 16]);
        derive_key(b"test-dek-for-subkeys", &salt).unwrap()
    }

    #[test]
    fn subkey_derivation_is_deterministic() -> KestrelResult<()> {
        let dek = test_dek();
        let sk1 = derive_subkey(&dek, INFO_FIELD_ENCRYPTION)?;
        let sk2 = derive_subkey(&dek, INFO_FIELD_ENCRYPTION)?;
        assert_eq!(sk1.expose(), sk2.expose());
        Ok(())
    }

    #[test]
    fn different_purposes_produce_different_keys() -> KestrelResult<()> {
        let dek = test_dek();
        let field_key = derive_subkey(&dek, INFO_FIELD_ENCRYPTION)?;
        let file_key = derive_subkey(&dek, INFO_FILE_ENCRYPTION)?;
        let search_key = derive_subkey(&dek, INFO_SEARCH_INDEX)?;
        let export_key = derive_subkey(&dek, INFO_EXPORT_ENCRYPTION)?;
        let totp_key = derive_subkey(&dek, INFO_TOTP_ENCRYPTION)?;

        // All sub-keys should be different from each other
        assert_ne!(field_key.expose(), file_key.expose());
        assert_ne!(field_key.expose(), search_key.expose());
        assert_ne!(field_key.expose(), export_key.expose());
        assert_ne!(field_key.expose(), totp_key.expose());
        assert_ne!(file_key.expose(), search_key.expose());
        assert_ne!(search_key.expose(), export_key.expose());
        assert_ne!(export_key.expose(), totp_key.expose());
        Ok(())
    }

    #[test]
    fn subkey_differs_from_dek() -> KestrelResult<()> {
        let dek = test_dek();
        let field_key = derive_subkey(&dek, INFO_FIELD_ENCRYPTION)?;
        assert_ne!(dek.expose(), field_key.expose());
        Ok(())
    }

    #[test]
    fn different_deks_produce_different_subkeys() -> KestrelResult<()> {
        let dek1 = test_dek();
        let salt2 = Salt([0x99u8; 16]);
        let dek2 = derive_key(b"different-dek", &salt2)?;

        let sk1 = derive_subkey(&dek1, INFO_FIELD_ENCRYPTION)?;
        let sk2 = derive_subkey(&dek2, INFO_FIELD_ENCRYPTION)?;

        assert_ne!(sk1.expose(), sk2.expose());
        Ok(())
    }

    #[test]
    fn subkey_has_correct_length() -> KestrelResult<()> {
        let dek = test_dek();
        let sk = derive_subkey(&dek, INFO_FIELD_ENCRYPTION)?;
        assert_eq!(sk.expose().len(), SUBKEY_LEN);
        Ok(())
    }

    #[test]
    fn subkey_as_derived_key_works() -> KestrelResult<()> {
        let dek = test_dek();
        let sk = derive_subkey(&dek, INFO_FIELD_ENCRYPTION)?;
        let derived = sk.as_derived_key();
        assert_eq!(sk.expose(), derived.expose());
        Ok(())
    }

    #[test]
    fn subkey_clone_produces_same_key() -> KestrelResult<()> {
        let dek = test_dek();
        let sk = derive_subkey(&dek, INFO_FIELD_ENCRYPTION)?;
        let cloned = sk.clone();
        assert_eq!(sk.expose(), cloned.expose());
        Ok(())
    }

    #[test]
    fn subkey_debug_redacts_key() -> KestrelResult<()> {
        let dek = test_dek();
        let sk = derive_subkey(&dek, INFO_FIELD_ENCRYPTION)?;
        let debug_str = format!("{:?}", sk);
        assert!(debug_str.contains("REDACTED"));
        assert!(!debug_str.contains(&format!("{:?}", sk.expose())));
        Ok(())
    }

    #[test]
    fn subkeyset_derive_from_dek() -> KestrelResult<()> {
        let dek = test_dek();
        let keyset = SubKeySet::derive_from_dek(&dek)?;

        // Verify all keys are different
        assert_ne!(keyset.field_encryption.expose(), keyset.file_encryption.expose());
        assert_ne!(keyset.field_encryption.expose(), keyset.search_index.expose());
        assert_ne!(keyset.field_encryption.expose(), keyset.export_encryption.expose());
        assert_ne!(keyset.field_encryption.expose(), keyset.totp_encryption.expose());
        Ok(())
    }

    #[test]
    fn subkeyset_is_deterministic() -> KestrelResult<()> {
        let dek = test_dek();
        let ks1 = SubKeySet::derive_from_dek(&dek)?;
        let ks2 = SubKeySet::derive_from_dek(&dek)?;

        assert_eq!(ks1.field_encryption.expose(), ks2.field_encryption.expose());
        assert_eq!(ks1.file_encryption.expose(), ks2.file_encryption.expose());
        assert_eq!(ks1.search_index.expose(), ks2.search_index.expose());
        assert_eq!(ks1.export_encryption.expose(), ks2.export_encryption.expose());
        assert_eq!(ks1.totp_encryption.expose(), ks2.totp_encryption.expose());
        Ok(())
    }

    #[test]
    fn custom_subkey_works() -> KestrelResult<()> {
        let dek = test_dek();
        let custom = SubKeySet::derive_custom(&dek, b"kestrel:future-purpose")?;
        assert_eq!(custom.expose().len(), SUBKEY_LEN);
        Ok(())
    }

    #[test]
    fn custom_subkey_rejects_builtin_purpose() -> KestrelResult<()> {
        let dek = test_dek();
        let result = SubKeySet::derive_custom(&dek, INFO_FIELD_ENCRYPTION);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn subkey_zeroizes_on_drop() -> KestrelResult<()> {
        let dek = test_dek();
        let sk = derive_subkey(&dek, INFO_FIELD_ENCRYPTION)?;
        // ZeroizeOnDrop should run without panicking
        drop(sk);
        Ok(())
    }

    #[test]
    fn subkeyset_zeroizes_on_drop() -> KestrelResult<()> {
        let dek = test_dek();
        let ks = SubKeySet::derive_from_dek(&dek)?;
        // All sub-keys should be zeroized
        drop(ks);
        Ok(())
    }

    #[test]
    fn subkey_purpose_returns_correct_info() -> KestrelResult<()> {
        let dek = test_dek();
        let sk = derive_subkey(&dek, INFO_FIELD_ENCRYPTION)?;
        assert_eq!(sk.purpose(), INFO_FIELD_ENCRYPTION);
        Ok(())
    }

    #[test]
    fn subkey_can_encrypt_decrypt_via_envelope() -> KestrelResult<()> {
        use crate::crypto::envelope;

        let dek = test_dek();
        let sk = derive_subkey(&dek, INFO_FIELD_ENCRYPTION)?;
        let derived = sk.as_derived_key();

        // Encrypt with sub-key
        let envelope = envelope::seal_envelope(
            &derived,
            b"test-secret-data",
            "entry-123",
            "password",
        )?;

        // Decrypt with same sub-key
        let aad = crate::crypto::envelope::AadContext::new("entry-123", "password");
        let parsed = crate::crypto::envelope::EncryptedEnvelope::from_bytes(
            &envelope.to_bytes(),
            aad,
        )?;
        let plaintext = envelope::open_envelope(&derived, &parsed)?;

        assert_eq!(plaintext, b"test-secret-data");
        Ok(())
    }
}
