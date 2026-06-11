//! Vault entry types for KESTREL Vault.
//!
//! Defines the core data structures for password vault entries.
//! All sensitive fields (passwords, secure notes) are stored as
//! encrypted ciphertext (`Vec<u8>`), never as plaintext strings.
//!
//! # Security
//!
//! - `encrypted_password` is AES-256-GCM ciphertext, never plaintext
//! - `notes` are also encrypted when they contain sensitive data
//! - Non-sensitive metadata (title, URL, tags) may be stored as plaintext
//!   for search indexing, but this is configurable

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
/// The `encrypted_password` field contains the AES-256-GCM ciphertext
/// of the user's password. It is never stored or transmitted as plaintext.
/// The `encrypted_notes` field follows the same pattern.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultEntry {
    /// Unique identifier for this entry.
    pub id: Uuid,
    /// User-visible title for this entry (e.g., "GitHub", "Bank of America").
    pub title: String,
    /// The username or email for this credential.
    pub username: String,
    /// The encrypted password ciphertext (AES-256-GCM).
    /// Never stored or logged as plaintext.
    pub encrypted_password: Vec<u8>,
    /// The nonce used for password encryption.
    /// Stored alongside ciphertext for decryption.
    pub password_nonce: Vec<u8>,
    /// Optional URL associated with this credential.
    pub url: Option<String>,
    /// Encrypted notes ciphertext (AES-256-GCM).
    /// May be empty if no notes are provided.
    pub encrypted_notes: Vec<u8>,
    /// The nonce used for notes encryption.
    pub notes_nonce: Vec<u8>,
    /// The folder this entry belongs to.
    pub folder_id: Option<Uuid>,
    /// Timestamp when this entry was created.
    pub created_at: DateTime<Utc>,
    /// Timestamp when this entry was last modified.
    pub updated_at: DateTime<Utc>,
    /// User-defined tags for categorization.
    pub tags: Vec<String>,
}

impl VaultEntry {
    /// Creates a new vault entry with the given parameters.
    ///
    /// The `id` and timestamps are automatically generated.
    /// The `encrypted_password` and `encrypted_notes` must be
    /// set by the encryption layer before persistence.
    ///
    /// # Arguments
    ///
    /// * `title` - Display title for the entry
    /// * `username` - The username or email
    /// * `encrypted_password` - AES-256-GCM encrypted password
    /// * `password_nonce` - Nonce used for password encryption
    ///
    /// # Note
    ///
    /// This constructor accepts already-encrypted data. Plaintext
    /// passwords should never be passed to this function.
    pub fn new(
        title: String,
        username: String,
        encrypted_password: Vec<u8>,
        password_nonce: Vec<u8>,
    ) -> Self {
        let now = Utc::now();
        VaultEntry {
            id: Uuid::new_v4(),
            title,
            username,
            encrypted_password,
            password_nonce,
            url: None,
            encrypted_notes: Vec::new(),
            notes_nonce: Vec::new(),
            folder_id: None,
            created_at: now,
            updated_at: now,
            tags: Vec::new(),
        }
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
            vec![5, 6, 7, 8], // placeholder nonce
        );
        assert_eq!(entry.title, "GitHub");
        assert_eq!(entry.username, "user@example.com");
        assert!(entry.url.is_none());
        assert!(entry.folder_id.is_none());
        assert!(entry.tags.is_empty());
    }

    #[test]
    fn vault_entry_has_uuid() {
        let entry = VaultEntry::new(
            "Test".to_string(),
            "user".to_string(),
            vec![],
            vec![],
        );
        assert!(!entry.id.is_nil());
    }
}
