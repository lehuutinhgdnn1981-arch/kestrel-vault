//! Cryptographic operations module for KESTREL Vault.
//!
//! This module provides all cryptographic primitives used throughout the
//! application, following strict security principles and the KEK/DEK
//! key hierarchy pattern.
//!
//! # Security Principles
//!
//! - **AES-256-GCM only**: No ECB, no CBC, no unauthenticated modes
//! - **Argon2id for key derivation**: Memory-hard, resistant to GPU/ASIC attacks
//! - **KEK/DEK hierarchy**: Key Encryption Key wraps Data Encryption Key
//! - **HKDF sub-key derivation**: Purpose-bound sub-keys for key separation
//! - **Zeroize on drop**: All secret material is cleared from memory when no longer needed
//! - **Secrecy wrapping**: Sensitive values use `secrecy::Secret` to prevent accidental logging
//! - **Strong types**: Newtype pattern prevents mixing keys, nonces, and ciphertext
//! - **No custom crypto**: All primitives are from well-audited crates
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
//! # Submodules
//!
//! - `cipher`: Authenticated encryption (AES-256-GCM)
//! - `envelope`: Versioned binary envelope format with AAD context
//! - `kdf`: Key derivation functions (Argon2id)
//! - `kdf_params`: Configurable KDF parameters with versioning
//! - `key_management`: Master key handling, KEK/DEK rotation
//! - `keywrap`: Key wrapping (KEK wraps DEK)
//! - `random`: Secure random number generation
//! - `secure_string`: Zeroizing string wrapper for password handling
//! - `subkeys`: HKDF-based sub-key derivation from DEK
//! - `vault_crypto`: High-level vault encryption/decryption service

pub mod cipher;
pub mod envelope;
pub mod kdf;
pub mod kdf_params;
pub mod key_management;
pub mod keywrap;
pub mod random;
pub mod secure_string;
pub mod subkeys;
pub mod vault_crypto;

// Re-export key types for convenience
pub use cipher::{decrypt, encrypt, AeadTag, Ciphertext, Nonce};
pub use envelope::{AadContext, EncryptedEnvelope, EnvelopeVersion, seal_envelope, open_envelope};
pub use kdf::{derive_key, derive_key_with_params, DerivedKey, Salt};
pub use kdf_params::KdfParams;
pub use key_management::{
    MasterKey, RotationKeyPair, KeyRotationResult, VaultInitResult,
    initialize_vault_keys, unlock_vault_keys, rotate_master_key, re_encrypt_field,
};
pub use keywrap::{DataEncryptionKey, WrappedDek, wrap_dek, unwrap_dek, rewrap_dek};
pub use random::{random_bytes, random_nonce, random_salt, random_uuid};
pub use secure_string::SecureString;
pub use subkeys::{SubKey, SubKeySet};
pub use vault_crypto::{VaultCryptoService, initialize_vault_crypto, unlock_vault_crypto};
