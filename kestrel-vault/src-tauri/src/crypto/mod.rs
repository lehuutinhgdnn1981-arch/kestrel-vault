//! Cryptographic operations module for KESTREL Vault.
//!
//! This module provides all cryptographic primitives used throughout the
//! application, following strict security principles:
//!
//! # Security Principles
//!
//! - **AES-256-GCM only**: No ECB, no CBC, no unauthenticated modes
//! - **Argon2id for key derivation**: Memory-hard, resistant to GPU/ASIC attacks
//! - **Zeroize on drop**: All secret material is cleared from memory when no longer needed
//! - **Secrecy wrapping**: Sensitive values use `secrecy::Secret` to prevent accidental logging
//! - **Strong types**: Newtype pattern prevents mixing keys, nonces, and ciphertext
//! - **No custom crypto**: All primitives are from well-audited crates
//!
//! # Submodules
//!
//! - `kdf`: Key derivation functions (Argon2id)
//! - `cipher`: Authenticated encryption (AES-256-GCM)
//! - `key_management`: Master key handling, rotation, and derivation
//! - `random`: Secure random number generation

pub mod cipher;
pub mod envelope;
pub mod kdf;
pub mod key_management;
pub mod random;
pub mod vault_crypto;

// Re-export key types for convenience
pub use cipher::{decrypt, encrypt, AeadTag, Ciphertext, Nonce};
pub use envelope::{AadContext, EncryptedEnvelope, EnvelopeVersion, seal_envelope, open_envelope};
pub use kdf::{derive_key, DerivedKey, Salt};
pub use key_management::MasterKey;
pub use random::{random_bytes, random_nonce, random_salt, random_uuid};
pub use vault_crypto::{VaultCryptoService, initialize_vault_crypto, unlock_vault_crypto};
