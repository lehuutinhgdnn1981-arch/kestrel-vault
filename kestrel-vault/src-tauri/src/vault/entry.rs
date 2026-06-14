//! Vault entry types for KESTREL Vault.
//!
//! Defines the core data structures for password vault entries.
//! All sensitive fields (passwords, notes, URLs, tags, TOTP secrets)
//! are stored as encrypted envelope bytes (`Vec<u8>`), never as
//! plaintext strings.
//!
//! # Encryption Strategy
//!
//! | Field                | Storage     | Encrypted | Rationale                    |
//! |----------------------|-------------|-----------|------------------------------|
//! | id                   | UUID string | No        | Primary key                  |
//! | title                | String      | No        | Search indexing              |
//! | username             | String      | No        | Search indexing              |
//! | encrypted_password   | Vec<u8>     | Yes (DEK) | Most sensitive               |
//! | encrypted_url        | Vec<u8>     | Yes (DEK) | Privacy                      |
//! | encrypted_notes      | Vec<u8>     | Yes (DEK) | May contain secrets          |
//! | encrypted_totp       | Vec<u8>     | Yes (DEK) | 2FA secret                   |
//! | encrypted_tags       | Vec<u8>     | Yes (DEK) | Metadata privacy             |
//! | folder_id            | UUID string | No        | Not sensitive                |
//!
//! # DEK vs KEK
//!
//! Field-level encryption uses the DEK (Data Encryption Key), NOT the
//! KEK (Key Encryption Key). The KEK is only used for:
//! - Test envelope creation/verification
//! - DEK wrap/unwrap
//!
//! All field encryption goes through VaultCryptoService::new_dek().

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A single entry in the password vault.
///
/// Each entry represents a set of credentials (username/password pair)
/// along with metadata like URL, notes, and organizational tags.
///
/// # Encryption
///
/// All `encrypted_*` fields contain envelope-format ciphertext:
/// `[version:1][nonce:12][ciphertext:N][tag:16]`
///
/// Each field has its own nonce embedded in the envelope.
/// The AAD context is `{entry_id}:{field_name}`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultEntry {
    /// Unique identifier for this entry.
    pub id: Uuid,
    /// User-visible title for this entry (plaintext for search).
    pub title: String,
    /// The username or email for this credential (plaintext for search).
    pub username: String,
    /// Encrypted password envelope bytes (AES-256-GCM via DEK).
    pub encrypted_password: Vec<u8>,
    /// Encrypted URL envelope bytes (AES-256-GCM via DEK).
    pub encrypted_url: Vec<u8>,
    /// Encrypted notes envelope bytes (AES-256-GCM via DEK).
    pub encrypted_notes: Vec<u8>,
    /// Encrypted TOTP secret envelope bytes (AES-256-GCM via DEK, nullable).
    pub encrypted_totp_secret: Option<Vec<u8>>,
    /// Encrypted tags envelope bytes (AES-256-GCM via DEK).
    pub encrypted_tags: Vec<u8>,
    /// The folder this entry belongs to.
    pub folder_id: Option<Uuid>,
    /// Timestamp when this entry was created.
    pub created_at: DateTime<Utc>,
    /// Timestamp when this entry was last modified.
    pub updated_at: DateTime<Utc>,
    /// Timestamp when this entry was last accessed.
    pub accessed_at: DateTime<Utc>,
}

impl VaultEntry {
    /// Creates a new vault entry with the given parameters.
    ///
    /// The `id` and timestamps are automatically generated.
    /// The `encrypted_*` fields must be set by the encryption
    /// layer using the DEK before persistence.
    pub fn new(
        title: String,
        username: String,
        encrypted_password: Vec<u8>,
    ) -> Self {
        let now = Utc::now();
        VaultEntry {
            id: Uuid::new_v4(),
            title,
            username,
            encrypted_password,
            encrypted_url: Vec::new(),
            encrypted_notes: Vec::new(),
            encrypted_totp_secret: None,
            encrypted_tags: Vec::new(),
            folder_id: None,
            created_at: now,
            updated_at: now,
            accessed_at: now,
        }
    }

    /// Returns true if this entry has a TOTP secret configured.
    pub fn has_totp(&self) -> bool {
        self.encrypted_totp_secret.is_some()
            && !self.encrypted_totp_secret.as_ref().map(|t| t.is_empty()).unwrap_or(true)
    }

    /// Returns true if this entry has notes.
    pub fn has_notes(&self) -> bool {
        !self.encrypted_notes.is_empty()
    }

    /// Returns true if this entry has a URL.
    pub fn has_url(&self) -> bool {
        !self.encrypted_url.is_empty()
    }
}

/// Request to create a new vault entry.
///
/// This is the input type for the create entry command.
/// The `password` field contains the plaintext password that
/// will be encrypted before storage.
///
/// # Security
///
/// The plaintext password in this struct must be zeroized
/// immediately after encryption. This struct should never be
/// logged or persisted.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateEntryRequest {
    /// Display title for the entry.
    pub title: String,
    /// Username or email for the credential.
    pub username: String,
    /// Plaintext password — encrypted before storage.
    pub password: String,
    /// Optional URL associated with this credential.
    pub url: Option<String>,
    /// Optional notes for this entry.
    pub notes: Option<String>,
    /// Optional folder to organize this entry.
    pub folder_id: Option<Uuid>,
    /// Tags for categorization.
    pub tags: Vec<String>,
}

/// Request to update an existing vault entry.
///
/// Only fields that are `Some` will be updated. `None` fields
/// retain their existing values.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpdateEntryRequest {
    /// New title, if changing.
    pub title: Option<String>,
    /// New username, if changing.
    pub username: Option<String>,
    /// New plaintext password, if changing. Encrypted before storage.
    pub password: Option<String>,
    /// New URL, if changing.
    pub url: Option<String>,
    /// New notes, if changing.
    pub notes: Option<String>,
    /// New folder assignment, if changing.
    pub folder_id: Option<Uuid>,
    /// New tags, if changing.
    pub tags: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_vault_entry() {
        let entry = VaultEntry::new(
            "GitHub".to_string(),
            "user@example.com".to_string(),
            vec![1, 2, 3, 4], // placeholder ciphertext
        );
        assert_eq!(entry.title, "GitHub");
        assert_eq!(entry.username, "user@example.com");
        assert!(entry.encrypted_url.is_empty());
        assert!(entry.folder_id.is_none());
        assert!(entry.encrypted_tags.is_empty());
        assert!(!entry.has_totp());
        assert!(!entry.has_notes());
    }

    #[test]
    fn vault_entry_has_uuid() {
        let entry = VaultEntry::new(
            "Test".to_string(),
            "user".to_string(),
            vec![],
        );
        assert!(!entry.id.is_nil());
    }

    #[test]
    fn has_totp_returns_false_for_empty() {
        let entry = VaultEntry::new("T".to_string(), "u".to_string(), vec![]);
        assert!(!entry.has_totp());
    }

    #[test]
    fn has_totp_returns_true_for_nonempty() {
        let mut entry = VaultEntry::new("T".to_string(), "u".to_string(), vec![]);
        entry.encrypted_totp_secret = Some(vec![1, 2, 3]);
        assert!(entry.has_totp());
    }

    #[test]
    fn has_notes_returns_true_for_nonempty() {
        let mut entry = VaultEntry::new("T".to_string(), "u".to_string(), vec![]);
        entry.encrypted_notes = vec![1, 2, 3];
        assert!(entry.has_notes());
    }
}
