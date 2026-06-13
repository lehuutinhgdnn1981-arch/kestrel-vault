//! Encryption envelope format for KESTREL Vault.
//!
//! Defines the standard binary format for all encrypted data stored in
//! the database. Every sensitive field (passwords, notes, file contents)
//! is wrapped in an `EncryptedEnvelope` before persistence.
//!
//! # Envelope Format (Version 1)
//!
//! ```text
//! [version: 1 byte][nonce: 12 bytes][ciphertext: N bytes][tag: 16 bytes]
//! ```
//!
//! - **version**: Format version byte (currently `0x01`)
//! - **nonce**: 96-bit random nonce from AES-256-GCM
//! - **ciphertext**: Encrypted payload (variable length)
//! - **tag**: 16-byte GCM authentication tag
//!
//! # Additional Authenticated Data (AAD)
//!
//! Each envelope binds an AAD context composed of:
//! - Entity ID (e.g., entry UUID)
//! - Field name (e.g., "password", "notes", "content")
//!
//! This ensures:
//! 1. Ciphertext from one field cannot be swapped into another
//! 2. Ciphertext from one entry cannot be swapped into another
//! 3. Any tampering is detected by GCM authentication

use crate::crypto::cipher::{self, Ciphertext, Nonce};
use crate::crypto::kdf::DerivedKey;
use crate::error::{KestrelError, KestrelResult};
use zeroize::Zeroize;

/// Current envelope format version.
pub const ENVELOPE_VERSION_1: u8 = 0x01;

/// Size of the nonce in bytes (96 bits for AES-256-GCM).
const NONCE_SIZE: usize = 12;

/// Size of the GCM authentication tag in bytes.
const TAG_SIZE: usize = 16;

/// Minimum envelope size: version(1) + nonce(12) + tag(16) = 29 bytes.
const MIN_ENVELOPE_SIZE: usize = 1 + NONCE_SIZE + TAG_SIZE;

/// Envelope format version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeVersion {
    /// Version 1: [version][nonce][ciphertext+tag]
    V1,
}

impl EnvelopeVersion {
    /// Returns the byte representation of this version.
    pub fn as_byte(self) -> u8 {
        match self {
            EnvelopeVersion::V1 => ENVELOPE_VERSION_1,
        }
    }

    /// Parses a version byte.
    ///
    /// # Errors
    ///
    /// Returns `KestrelError::Crypto` if the version byte is unknown.
    pub fn from_byte(byte: u8) -> KestrelResult<Self> {
        match byte {
            ENVELOPE_VERSION_1 => Ok(EnvelopeVersion::V1),
            _ => Err(KestrelError::Crypto(format!(
                "Unknown envelope version: {byte:#04x}"
            ))),
        }
    }
}

/// Additional Authenticated Data context for envelope encryption.
///
/// Binds the entity ID and field name to the ciphertext, preventing
/// swap attacks where ciphertext from one field or entry is moved
/// to another.
#[derive(Debug, Clone)]
pub struct AadContext {
    /// The entity identifier (e.g., entry UUID as string).
    entity_id: String,
    /// The field name being encrypted (e.g., "password", "notes").
    field_name: String,
}

impl AadContext {
    /// Creates a new AAD context.
    ///
    /// # Arguments
    ///
    /// * `entity_id` - The UUID of the entity being encrypted
    /// * `field_name` - The name of the field being encrypted
    pub fn new(entity_id: impl Into<String>, field_name: impl Into<String>) -> Self {
        AadContext {
            entity_id: entity_id.into(),
            field_name: field_name.into(),
        }
    }

    /// Serializes the AAD context to bytes for use in AES-256-GCM.
    ///
    /// Format: `{entity_id}:{field_name}` as UTF-8 bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        format!("{}:{}", self.entity_id, self.field_name).into_bytes()
    }
}

/// An encrypted envelope containing versioned, authenticated ciphertext.
///
/// This is the primary data structure for storing encrypted data in
/// the database. It includes the format version, nonce, and the
/// combined ciphertext+tag blob.
///
/// # Serialization
///
/// The `to_bytes()` / `from_bytes()` methods handle conversion to/from
/// the binary format used for database storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedEnvelope {
    /// The envelope format version.
    version: EnvelopeVersion,
    /// The nonce used for this encryption operation.
    nonce: Nonce,
    /// The ciphertext with appended GCM authentication tag.
    ciphertext_with_tag: Vec<u8>,
    /// The AAD context (not serialized — reconstructed on load).
    aad_context: AadContext,
}

impl EncryptedEnvelope {
    /// Creates a new encrypted envelope from its components.
    pub fn new(
        version: EnvelopeVersion,
        nonce: Nonce,
        ciphertext_with_tag: Vec<u8>,
        aad_context: AadContext,
    ) -> Self {
        EncryptedEnvelope {
            version,
            nonce,
            ciphertext_with_tag,
            aad_context,
        }
    }

    /// Returns the envelope version.
    pub fn version(&self) -> EnvelopeVersion {
        self.version
    }

    /// Returns a reference to the nonce.
    pub fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    /// Returns the ciphertext+tag bytes.
    pub fn ciphertext_with_tag(&self) -> &[u8] {
        &self.ciphertext_with_tag
    }

    /// Serializes the envelope to bytes for database storage.
    ///
    /// Format: [version: 1 byte][nonce: 12 bytes][ciphertext+tag: N bytes]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + NONCE_SIZE + self.ciphertext_with_tag.len());
        buf.push(self.version.as_byte());
        buf.extend_from_slice(&self.nonce.0);
        buf.extend_from_slice(&self.ciphertext_with_tag);
        buf
    }

    /// Deserializes an envelope from bytes loaded from the database.
    ///
    /// # Arguments
    ///
    /// * `data` - The raw bytes from the database
    /// * `aad_context` - The AAD context to bind to this envelope
    ///
    /// # Errors
    ///
    /// Returns `KestrelError::Crypto` if:
    /// - The data is too short to be a valid envelope
    /// - The version byte is unknown
    pub fn from_bytes(data: &[u8], aad_context: AadContext) -> KestrelResult<Self> {
        if data.len() < MIN_ENVELOPE_SIZE {
            return Err(KestrelError::Crypto(format!(
                "Envelope too short: {} bytes (minimum {MIN_ENVELOPE_SIZE})",
                data.len()
            )));
        }

        let version = EnvelopeVersion::from_byte(data[0])?;

        let nonce_bytes: [u8; NONCE_SIZE] = data[1..1 + NONCE_SIZE]
            .try_into()
            .map_err(|_| KestrelError::Crypto("Failed to extract nonce".to_string()))?;

        let ciphertext_with_tag = data[1 + NONCE_SIZE..].to_vec();

        Ok(EncryptedEnvelope {
            version,
            nonce: Nonce(nonce_bytes),
            ciphertext_with_tag,
            aad_context,
        })
    }
}

/// Seals plaintext into an encrypted envelope.
///
/// This is the primary encryption function for all vault data. It:
/// 1. Generates a fresh random nonce
/// 2. Encrypts the plaintext with AES-256-GCM using the provided AAD
/// 3. Wraps everything in an `EncryptedEnvelope`
///
/// # Arguments
///
/// * `key` - The derived encryption key
/// * `plaintext` - The data to encrypt
/// * `entity_id` - The UUID of the entity (for AAD binding)
/// * `field_name` - The name of the field (for AAD binding)
///
/// # Errors
///
/// Returns `KestrelError::Crypto` if encryption fails.
///
/// # Security
///
/// - A fresh nonce is generated for every call
/// - The AAD context prevents swap attacks
/// - The GCM tag ensures integrity and authenticity
pub fn seal_envelope(
    key: &DerivedKey,
    plaintext: &[u8],
    entity_id: impl Into<String>,
    field_name: impl Into<String>,
) -> KestrelResult<EncryptedEnvelope> {
    let aad_context = AadContext::new(entity_id, field_name);
    let aad_bytes = aad_context.to_bytes();

    let (nonce, ciphertext) = cipher::encrypt(key, plaintext, &aad_bytes)?;

    Ok(EncryptedEnvelope {
        version: EnvelopeVersion::V1,
        nonce,
        ciphertext_with_tag: ciphertext.0,
        aad_context,
    })
}

/// Opens (decrypts) an encrypted envelope.
///
/// This is the primary decryption function. It:
/// 1. Parses the envelope format
/// 2. Reconstructs the AAD context
/// 3. Decrypts with AES-256-GCM, verifying the authentication tag
///
/// # Arguments
///
/// * `key` - The derived encryption key
/// * `envelope` - The encrypted envelope to open
///
/// # Errors
///
/// Returns `KestrelError::Crypto` if:
/// - The key is incorrect
/// - The ciphertext has been tampered with
/// - The AAD context does not match
///
/// # Security
///
/// The GCM tag is verified before any plaintext is released,
/// preventing chosen-ciphertext attacks.
pub fn open_envelope(
    key: &DerivedKey,
    envelope: &EncryptedEnvelope,
) -> KestrelResult<Vec<u8>> {
    let aad_bytes = envelope.aad_context.to_bytes();
    let ciphertext = Ciphertext(envelope.ciphertext_with_tag.clone());

    cipher::decrypt(key, &envelope.nonce, &ciphertext, &aad_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::{derive_key, Salt};

    fn test_key() -> DerivedKey {
        let salt = Salt([0x42u8; 16]);
        derive_key(b"test-envelope-key", &salt).unwrap()
    }

    #[test]
    fn seal_open_roundtrip() -> KestrelResult<()> {
        let key = test_key();
        let plaintext = b"my-secret-password";
        let entity_id = "550e8400-e29b-41d4-a716-446655440000";
        let field_name = "password";

        let envelope =
            seal_envelope(&key, plaintext, entity_id, field_name)?;

        let decrypted = open_envelope(&key, &envelope)?;
        assert_eq!(decrypted, plaintext);
        Ok(())
    }

    #[test]
    fn serialization_roundtrip() -> KestrelResult<()> {
        let key = test_key();
        let envelope = seal_envelope(&key, b"secret-data", "entry-1", "notes")?;
        let bytes = envelope.to_bytes();

        let aad = AadContext::new("entry-1", "notes");
        let restored = EncryptedEnvelope::from_bytes(&bytes, aad)?;

        let decrypted = open_envelope(&key, &restored)?;
        assert_eq!(decrypted, b"secret-data");
        Ok(())
    }

    #[test]
    fn wrong_aad_fails_decryption() -> KestrelResult<()> {
        let key = test_key();
        let envelope = seal_envelope(&key, b"secret", "entry-1", "password")?;

        // Reconstruct with wrong AAD
        let wrong_aad = AadContext::new("entry-1", "notes");
        let mut tampered = envelope.clone();
        tampered.aad_context = wrong_aad;

        let result = open_envelope(&key, &tampered);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn cross_entry_swap_fails() -> KestrelResult<()> {
        let key = test_key();
        let envelope = seal_envelope(&key, b"secret", "entry-1", "password")?;

        // Swap entity ID in AAD
        let swapped_aad = AadContext::new("entry-2", "password");
        let mut swapped = envelope.clone();
        swapped.aad_context = swapped_aad;

        let result = open_envelope(&key, &swapped);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn tampered_ciphertext_fails() -> KestrelResult<()> {
        let key = test_key();
        let envelope = seal_envelope(&key, b"secret-data", "entry-1", "password")?;
        let mut bytes = envelope.to_bytes();

        // Tamper with a ciphertext byte (after version + nonce)
        if bytes.len() > MIN_ENVELOPE_SIZE {
            bytes[MIN_ENVELOPE_SIZE] ^= 0xFF;
        }

        let aad = AadContext::new("entry-1", "password");
        let restored = EncryptedEnvelope::from_bytes(&bytes, aad)?;
        let result = open_envelope(&key, &restored);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn invalid_version_rejected() -> KestrelResult<()> {
        let key = test_key();
        let envelope = seal_envelope(&key, b"secret", "entry-1", "password")?;
        let mut bytes = envelope.to_bytes();
        bytes[0] = 0xFF; // Invalid version

        let aad = AadContext::new("entry-1", "password");
        let result = EncryptedEnvelope::from_bytes(&bytes, aad);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn too_short_envelope_rejected() {
        let aad = AadContext::new("entry-1", "password");
        let result = EncryptedEnvelope::from_bytes(&[0x01, 0x02], aad);
        assert!(result.is_err());
    }

    #[test]
    fn aad_context_serialization() {
        let aad = AadContext::new("entry-123", "password");
        let bytes = aad.to_bytes();
        assert_eq!(bytes, b"entry-123:password");
    }

    #[test]
    fn envelope_version_roundtrip() -> KestrelResult<()> {
        let v = EnvelopeVersion::V1;
        let byte = v.as_byte();
        let restored = EnvelopeVersion::from_byte(byte)?;
        assert_eq!(v, restored);
        Ok(())
    }
}
