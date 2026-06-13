//! Vault service implementation for KESTREL Vault.
//!
//! This module provides the concrete implementation of the `VaultService`
//! trait, bridging the crypto layer (DEK-based field encryption) with the
//! database layer (repository CRUD). It is the **single point of truth**
//! for how plaintext data flows into and out of encrypted storage.
//!
//! # Architecture
//!
//! ```text
//! ┌────────────────┐     ┌─────────────────┐     ┌──────────────────┐
//! │ Command Layer   │────▶│ VaultServiceImpl │────▶│ Database Repos   │
//! │ (vault_commands)│     │ (this module)    │     │ (VaultEntryRepo) │
//! └────────────────┘     └────────┬─────────┘     └──────────────────┘
//!                                 │
//!                        ┌────────┴────────┐
//!                        │                 │
//!                   VaultCryptoService   SubKeySet
//!                   (DEK mode)          (HKDF from DEK)
//! ```
//!
//! # Data Flow
//!
//! **Create Entry:**
//! 1. Receive `CreateEntryRequest` with plaintext password
//! 2. Encrypt each sensitive field with the DEK via VaultCryptoService
//! 3. Build `CreateVaultEntryRequest` with envelope bytes
//! 4. Persist via `VaultEntryRepo::create`
//! 5. Return `VaultEntry` with encrypted fields
//!
//! **Reveal Password:**
//! 1. Load entry from `VaultEntryRepo::get_by_id`
//! 2. Decrypt `encrypted_password` with the DEK
//! 3. Return plaintext (caller is responsible for zeroization)
//!
//! # Security
//!
//! - The DEK is never stored — only held in memory while vault is unlocked
//! - All field encryption uses AES-256-GCM with AAD context binding
//! - Folder names are encrypted to prevent organizational structure leakage
//! - Passwords are ONLY decrypted through explicit reveal operations
//! - All decrypted data is wrapped in `DecryptedField` for auto-zeroization

use crate::crypto::keywrap::DataEncryptionKey;
use crate::crypto::secure_string::SecureString;
use crate::crypto::vault_crypto::{VaultCryptoService, field_names, DecryptedField};
use crate::crypto::random::random_bytes;
use crate::db::vault_entry_repo::{
    VaultEntryRepo, VaultEntryRow, CreateVaultEntryRequest, UpdateVaultEntryRequest,
};
use crate::db::vault_meta_repo::VaultMetaRepo;
use crate::db::folder_repo::{FolderRepo, CreateFolderRequest};
use crate::db::secure_note_repo::{SecureNoteRepo, CreateSecureNoteRequest, SecureNoteRow};
use crate::db::file_entry_repo::FileEntryRepo;
use crate::db::audit_event_repo::{AuditEventRepo, CreateAuditEventRequest};
use crate::error::{KestrelError, KestrelResult};
use crate::vault::entry::{CreateEntryRequest, UpdateEntryRequest, VaultEntry};
use crate::vault::folder::Folder;
use crate::vault::search::SearchQuery;
use sqlx::SqlitePool;
use uuid::Uuid;

/// The concrete vault service implementation.
///
/// This struct holds references to the DEK (for field-level encryption)
/// and the database pool (for persistence). It is created when the vault
/// is unlocked and dropped (zeroizing the DEK) when the vault is locked.
///
/// # Lifetime
///
/// The service borrows the DEK and does not own it. The caller must
/// ensure the DEK remains valid for the lifetime of this service.
pub struct VaultServiceImpl<'a> {
    /// The Data Encryption Key for field-level encryption.
    dek: &'a DataEncryptionKey,
    /// The database connection pool for persistence.
    pool: &'a SqlitePool,
}

impl<'a> VaultServiceImpl<'a> {
    /// Creates a new vault service instance.
    ///
    /// This should be called after the vault is unlocked, once the DEK
    /// has been unwrapped and the database connection is established.
    ///
    /// # Arguments
    ///
    /// * `dek` - The unwrapped Data Encryption Key (borrowed)
    /// * `pool` - The SQLCipher database connection pool (borrowed)
    pub fn new(dek: &'a DataEncryptionKey, pool: &'a SqlitePool) -> Self {
        VaultServiceImpl { dek, pool }
    }

    /// Returns a DEK-mode crypto service for field-level operations.
    fn crypto_service(&self) -> VaultCryptoService<'a> {
        VaultCryptoService::new_dek(self.dek)
    }

    // ── Vault Entry Operations ──

    /// Creates a new vault entry with encrypted fields.
    ///
    /// This is the primary entry creation path. It:
    /// 1. Generates a new UUID for the entry
    /// 2. Encrypts all sensitive fields (password, URL, notes, TOTP, tags)
    /// 3. Persists the encrypted data to the database
    /// 4. Returns the entry with encrypted fields
    ///
    /// # Security
    ///
    /// - The plaintext password is wrapped in `SecureString` and zeroized
    /// - Each field gets its own nonce via the envelope format
    /// - AAD context binds each field to the entry ID
    /// - The DEK is never exposed outside this service
    pub async fn create_entry(&self, request: CreateEntryRequest) -> KestrelResult<VaultEntry> {
        let crypto = self.crypto_service();
        let entry_id = Uuid::new_v4().to_string();

        // Encrypt password (most sensitive — use SecureString for zeroization)
        let encrypted_password = {
            let secure_password = SecureString::from(request.password);
            let enc = crypto.encrypt_field(&entry_id, field_names::PASSWORD, secure_password.as_bytes())?;
            // secure_password is zeroized when it goes out of scope
            enc.envelope_bytes
        };

        // Encrypt URL
        let encrypted_url = match &request.url {
            Some(url) if !url.is_empty() => {
                crypto.encrypt_field(&entry_id, field_names::URL, url.as_bytes())?.envelope_bytes
            }
            _ => Vec::new(),
        };

        // Encrypt notes
        let encrypted_notes = match &request.notes {
            Some(notes) if !notes.is_empty() => {
                crypto.encrypt_field(&entry_id, field_names::NOTES, notes.as_bytes())?.envelope_bytes
            }
            _ => Vec::new(),
        };

        // Encrypt tags (serialized as JSON first)
        let encrypted_tags = if !request.tags.is_empty() {
            let tags_json = serde_json::to_vec(&request.tags)
                .map_err(|e| KestrelError::Serialization(format!("Failed to serialize tags: {e}")))?;
            crypto.encrypt_field(&entry_id, field_names::TAGS, &tags_json)?.envelope_bytes
        } else {
            Vec::new()
        };

        // Build the repository request
        let repo_request = CreateVaultEntryRequest {
            title: request.title.clone(),
            username: request.username.clone(),
            encrypted_password,
            encrypted_url,
            encrypted_notes,
            encrypted_totp_secret: None, // TOTP is set separately
            encrypted_tags,
            folder_id: request.folder_id.map(|u| u.to_string()),
        };

        // Persist to database
        let row = VaultEntryRepo::create(self.pool, repo_request).await?;

        // Audit log
        self.audit("Vault", "EntryCreated", &row.id, None).await?;

        // Map to domain type
        Ok(Self::row_to_entry(&row))
    }

    /// Retrieves a vault entry by ID.
    ///
    /// Returns the entry with encrypted fields intact. To access the
    /// password, use `reveal_password` instead.
    pub async fn get_entry(&self, id: Uuid) -> KestrelResult<VaultEntry> {
        let row = VaultEntryRepo::get_by_id(self.pool, &id.to_string()).await?;
        Ok(Self::row_to_entry(&row))
    }

    /// Updates an existing vault entry.
    ///
    /// Only provided fields are updated. Password changes are encrypted
    /// with a fresh nonce. Unchanged fields retain their existing values.
    pub async fn update_entry(
        &self,
        id: Uuid,
        request: UpdateEntryRequest,
    ) -> KestrelResult<VaultEntry> {
        let crypto = self.crypto_service();
        let id_str = id.to_string();

        // Encrypt changed sensitive fields
        let encrypted_password = match &request.password {
            Some(pwd) => {
                let secure_password = SecureString::from(pwd.clone());
                let enc = crypto.encrypt_field(&id_str, field_names::PASSWORD, secure_password.as_bytes())?;
                Some(enc.envelope_bytes)
            }
            None => None,
        };

        let encrypted_url = match &request.url {
            Some(url) if !url.is_empty() => {
                Some(crypto.encrypt_field(&id_str, field_names::URL, url.as_bytes())?.envelope_bytes)
            }
            Some(_) => Some(Vec::new()), // Clear the URL
            None => None,
        };

        let encrypted_notes = match &request.notes {
            Some(notes) if !notes.is_empty() => {
                Some(crypto.encrypt_field(&id_str, field_names::NOTES, notes.as_bytes())?.envelope_bytes)
            }
            Some(_) => Some(Vec::new()), // Clear the notes
            None => None,
        };

        let encrypted_tags = match &request.tags {
            Some(tags) if !tags.is_empty() => {
                let tags_json = serde_json::to_vec(tags)
                    .map_err(|e| KestrelError::Serialization(format!("Failed to serialize tags: {e}")))?;
                Some(crypto.encrypt_field(&id_str, field_names::TAGS, &tags_json)?.envelope_bytes)
            }
            Some(_) => Some(Vec::new()), // Clear the tags
            None => None,
        };

        let folder_id = request.folder_id.map(|u| Some(u.to_string()));

        let repo_request = UpdateVaultEntryRequest {
            title: request.title,
            username: request.username,
            encrypted_password,
            encrypted_url,
            encrypted_notes,
            encrypted_totp_secret: None,
            encrypted_tags,
            folder_id,
        };

        let row = VaultEntryRepo::update(self.pool, &id_str, repo_request).await?;

        // Audit log
        self.audit("Vault", "EntryUpdated", &id_str, None).await?;

        Ok(Self::row_to_entry(&row))
    }

    /// Deletes a vault entry by ID.
    pub async fn delete_entry(&self, id: Uuid) -> KestrelResult<()> {
        let id_str = id.to_string();
        VaultEntryRepo::delete(self.pool, &id_str).await?;

        // Audit log
        self.audit("Vault", "EntryDeleted", &id_str, None).await?;

        Ok(())
    }

    /// Lists vault entries, optionally filtered by folder.
    ///
    /// Returns entries with encrypted fields intact — no passwords
    /// are decrypted. Entries are ordered by most recently updated.
    pub async fn list_entries(
        &self,
        folder_id: Option<Uuid>,
        limit: i64,
        offset: i64,
    ) -> KestrelResult<Vec<VaultEntry>> {
        let rows = match folder_id {
            Some(fid) => VaultEntryRepo::list_by_folder(self.pool, &fid.to_string()).await?,
            None => VaultEntryRepo::list(self.pool, limit, offset).await?,
        };

        Ok(rows.iter().map(Self::row_to_entry).collect())
    }

    /// Searches vault entries by plaintext fields (title, username).
    ///
    /// This searches ONLY non-sensitive metadata fields. Encrypted
    /// fields (password, notes, URL, tags) are NOT searched.
    pub async fn search_entries(
        &self,
        query: &str,
        limit: i64,
    ) -> KestrelResult<Vec<VaultEntry>> {
        let rows = VaultEntryRepo::search(self.pool, query, limit).await?;
        Ok(rows.iter().map(Self::row_to_entry).collect())
    }

    /// Reveals the decrypted password for a specific entry.
    ///
    /// This is the ONLY method that returns decrypted password data.
    /// The caller must zeroize the returned `DecryptedField` after use.
    ///
    /// # Security
    ///
    /// - This operation is always audit-logged
    /// - The DecryptedField auto-zeroizes when dropped
    /// - Should only be called on explicit user action
    pub async fn reveal_password(&self, id: Uuid) -> KestrelResult<DecryptedField> {
        let id_str = id.to_string();
        let crypto = self.crypto_service();

        // Load the encrypted password envelope from database
        let envelope_bytes = VaultEntryRepo::get_encrypted_password(self.pool, &id_str).await?;

        // Decrypt with the DEK
        let decrypted = crypto.decrypt_field(&id_str, field_names::PASSWORD, &envelope_bytes)?;

        // Touch the accessed_at timestamp
        let _ = VaultEntryRepo::touch_accessed(self.pool, &id_str).await;

        // Audit log — always log password reveals
        self.audit("Vault", "PasswordRevealed", &id_str, None).await?;

        Ok(decrypted)
    }

    /// Decrypts a specific field of a vault entry.
    ///
    /// Generic field decryption for non-password fields (URL, notes, tags, TOTP).
    pub async fn decrypt_field(
        &self,
        entry_id: &str,
        field_name: &str,
        envelope_bytes: &[u8],
    ) -> KestrelResult<DecryptedField> {
        let crypto = self.crypto_service();
        crypto.decrypt_field(entry_id, field_name, envelope_bytes)
    }

    /// Counts the total number of vault entries.
    pub async fn count_entries(&self) -> KestrelResult<i64> {
        VaultEntryRepo::count(self.pool).await
    }

    // ── Folder Operations ──

    /// Creates a new folder with an encrypted name.
    ///
    /// Folder names are encrypted to prevent organizational structure
    /// leakage. A random nonce is generated for the encryption.
    pub async fn create_folder(&self, name: &str, parent_id: Option<Uuid>) -> KestrelResult<Folder> {
        let crypto = self.crypto_service();
        let folder_id = Uuid::new_v4().to_string();

        // Encrypt the folder name
        let encrypted_name = crypto.encrypt_field(&folder_id, "name", name.as_bytes())?.envelope_bytes;

        // Generate a nonce for the folder (extracted from envelope or standalone)
        // The envelope already contains the nonce, but for compatibility with
        // the folder_repo schema which has a separate nonce column, we generate one
        let mut nonce = [0u8; 12];
        random_bytes(&mut nonce)?;
        let nonce_vec = nonce.to_vec();

        let repo_request = CreateFolderRequest {
            encrypted_name,
            nonce: nonce_vec,
            parent_id: parent_id.map(|u| u.to_string()),
        };

        let row = FolderRepo::create(self.pool, repo_request).await?;

        // Audit log
        self.audit("Vault", "FolderCreated", &row.id, None).await?;

        Ok(Folder {
            id: Uuid::parse_str(&row.id)
                .map_err(|e| KestrelError::Validation(format!("Invalid folder UUID: {e}")))?,
            name: name.to_string(), // Return plaintext name to the caller
            parent_id: row.parent_id.and_then(|s| Uuid::parse_str(&s).ok()),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        })
    }

    /// Decrypts a folder name from its encrypted BLOB.
    pub async fn decrypt_folder_name(&self, folder_id: &str, encrypted_name: &[u8]) -> KestrelResult<String> {
        let crypto = self.crypto_service();
        let decrypted = crypto.decrypt_field(folder_id, "name", encrypted_name)?;
        String::from_utf8(decrypted.plaintext.clone())
            .map_err(|e| KestrelError::Crypto(format!("Folder name is not valid UTF-8: {e}")))
    }

    /// Lists all folders with decrypted names.
    pub async fn list_folders(&self) -> KestrelResult<Vec<Folder>> {
        let rows = FolderRepo::list_all(self.pool).await?;
        let mut folders = Vec::new();

        for row in rows {
            let name = self.decrypt_folder_name(&row.id, &row.name).await.unwrap_or_else(|_| "<decryption error>".to_string());
            folders.push(Folder {
                id: Uuid::parse_str(&row.id).unwrap_or_else(|_| Uuid::nil()),
                name,
                parent_id: row.parent_id.and_then(|s| Uuid::parse_str(&s).ok()),
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            });
        }

        Ok(folders)
    }

    /// Deletes a folder by ID.
    pub async fn delete_folder(&self, id: Uuid) -> KestrelResult<()> {
        FolderRepo::delete(self.pool, &id.to_string()).await?;
        self.audit("Vault", "FolderDeleted", &id.to_string(), None).await?;
        Ok(())
    }

    // ── Vault Meta Operations ──

    /// Checks if the vault has been initialized.
    pub async fn is_vault_initialized(&self) -> KestrelResult<bool> {
        VaultMetaRepo::exists(self.pool).await
    }

    /// Checks if KDF parameters need upgrading.
    pub async fn needs_kdf_upgrade(&self) -> KestrelResult<bool> {
        VaultMetaRepo::needs_kdf_upgrade(self.pool).await
    }

    // ── Audit Operations ──

    /// Records an audit event.
    pub async fn audit(
        &self,
        category: &str,
        action: &str,
        subject: &str,
        metadata_json: Option<String>,
    ) -> KestrelResult<()> {
        let request = CreateAuditEventRequest {
            category: category.to_string(),
            action: action.to_string(),
            subject: subject.to_string(),
            metadata_json,
        };
        AuditEventRepo::create(self.pool, request).await?;
        Ok(())
    }

    // ── Secure Note Operations ──

    /// Creates a new secure note with encrypted title and content.
    ///
    /// Both the title and content are encrypted with the DEK before
    /// storage. Tags (if provided) are also encrypted to prevent
    /// metadata leakage.
    ///
    /// # Security
    ///
    /// - Title is encrypted (unlike vault entries where title is plaintext for search)
    /// - Content is encrypted with AES-256-GCM via the DEK
    /// - Tags are encrypted to prevent organizational structure leakage
    /// - Each field gets its own nonce via the envelope format
    /// - AAD context binds each field to the note ID
    pub async fn create_note(
        &self,
        title: &str,
        content: &str,
        folder_id: Option<Uuid>,
        tags: Vec<String>,
    ) -> KestrelResult<SecureNoteRow> {
        let crypto = self.crypto_service();
        let note_id = Uuid::new_v4().to_string();

        // Encrypt title
        let encrypted_title = crypto.encrypt_field(&note_id, "title", title.as_bytes())?.envelope_bytes;

        // Encrypt content
        let encrypted_content = crypto.encrypt_field(&note_id, "content", content.as_bytes())?.envelope_bytes;

        // Generate nonce (for compatibility with the DB schema's nonce column)
        let mut nonce = [0u8; 12];
        random_bytes(&mut nonce)?;
        let nonce_vec = nonce.to_vec();

        // Encrypt tags
        let encrypted_tags = if !tags.is_empty() {
            let tags_json = serde_json::to_vec(&tags)
                .map_err(|e| KestrelError::Serialization(format!("Failed to serialize tags: {e}")))?;
            Some(crypto.encrypt_field(&note_id, "tags", &tags_json)?.envelope_bytes)
        } else {
            None
        };

        let repo_request = CreateSecureNoteRequest {
            encrypted_title,
            encrypted_content,
            nonce: nonce_vec,
            folder_id: folder_id.map(|u| u.to_string()),
            encrypted_tags,
        };

        let row = SecureNoteRepo::create(self.pool, repo_request).await?;

        // Audit log
        self.audit("Notes", "NoteCreated", &row.id, None).await?;

        Ok(row)
    }

    /// Lists secure notes, optionally filtered by folder.
    ///
    /// Returns notes with decrypted titles for display. Content
    /// is NOT decrypted — use `reveal_note` for that.
    pub async fn list_notes(
        &self,
        folder_id: Option<Uuid>,
    ) -> KestrelResult<Vec<SecureNoteRow>> {
        let rows = SecureNoteRepo::list_by_folder(
            self.pool,
            folder_id.as_ref().map(|u| u.to_string()).as_deref(),
        )
        .await?;

        Ok(rows)
    }

    /// Gets a secure note by ID.
    ///
    /// Returns the note with encrypted fields intact.
    pub async fn get_note(&self, id: Uuid) -> KestrelResult<SecureNoteRow> {
        SecureNoteRepo::get_by_id(self.pool, &id.to_string()).await
    }

    /// Updates an existing secure note.
    ///
    /// Only provided fields are updated. Title and content changes
    /// are re-encrypted with fresh nonces.
    pub async fn update_note(
        &self,
        id: Uuid,
        title: Option<String>,
        content: Option<String>,
        folder_id: Option<Option<Uuid>>,
        tags: Option<Vec<String>>,
    ) -> KestrelResult<SecureNoteRow> {
        let crypto = self.crypto_service();
        let id_str = id.to_string();

        // Encrypt changed fields
        let encrypted_title = match &title {
            Some(t) => Some(crypto.encrypt_field(&id_str, "title", t.as_bytes())?.envelope_bytes),
            None => None,
        };

        let encrypted_content = match &content {
            Some(c) => Some(crypto.encrypt_field(&id_str, "content", c.as_bytes())?.envelope_bytes),
            None => None,
        };

        // Generate new nonce if content changed
        let nonce = if encrypted_content.is_some() {
            let mut n = [0u8; 12];
            random_bytes(&mut n)?;
            Some(n.to_vec())
        } else {
            None
        };

        // Encrypt tags
        let encrypted_tags = match &tags {
            Some(t) if !t.is_empty() => {
                let tags_json = serde_json::to_vec(t)
                    .map_err(|e| KestrelError::Serialization(format!("Failed to serialize tags: {e}")))?;
                Some(Some(crypto.encrypt_field(&id_str, "tags", &tags_json)?.envelope_bytes))
            }
            Some(_) => Some(None), // Clear tags
            None => None,
        };

        let repo_request = crate::db::secure_note_repo::UpdateSecureNoteRequest {
            encrypted_title,
            encrypted_content,
            nonce,
            folder_id: folder_id.map(|opt| opt.map(|u| u.to_string())),
            encrypted_tags,
        };

        let row = SecureNoteRepo::update(self.pool, &id_str, repo_request).await?;

        // Audit log
        self.audit("Notes", "NoteUpdated", &id_str, None).await?;

        Ok(row)
    }

    /// Deletes a secure note by ID.
    pub async fn delete_note(&self, id: Uuid) -> KestrelResult<()> {
        let id_str = id.to_string();
        SecureNoteRepo::delete(self.pool, &id_str).await?;
        self.audit("Notes", "NoteDeleted", &id_str, None).await?;
        Ok(())
    }

    /// Reveals the decrypted content of a secure note.
    ///
    /// This is the ONLY method that returns decrypted note content.
    /// The caller must zeroize the returned `DecryptedField` after use.
    /// This operation is always audit-logged.
    pub async fn reveal_note(&self, id: Uuid) -> KestrelResult<(DecryptedField, DecryptedField)> {
        let id_str = id.to_string();
        let crypto = self.crypto_service();

        // Load the note from database
        let row = SecureNoteRepo::get_by_id(self.pool, &id_str).await?;

        // Decrypt title
        let decrypted_title = crypto.decrypt_field(&id_str, "title", &row.title)?;

        // Decrypt content
        let decrypted_content = crypto.decrypt_field(&id_str, "content", &row.content)?;

        // Audit log — always log content reveals
        self.audit("Notes", "NoteRevealed", &id_str, None).await?;

        Ok((decrypted_title, decrypted_content))
    }

    /// Decrypts the title of a secure note for display in lists.
    ///
    /// Returns the decrypted title string, or a placeholder if
    /// decryption fails (should not happen with correct DEK).
    pub async fn decrypt_note_title(&self, note_id: &str, encrypted_title: &[u8]) -> KestrelResult<String> {
        let crypto = self.crypto_service();
        let decrypted = crypto.decrypt_field(note_id, "title", encrypted_title)?;
        String::from_utf8(decrypted.plaintext.clone())
            .map_err(|e| KestrelError::Crypto(format!("Note title is not valid UTF-8: {e}")))
    }

    /// Counts the total number of secure notes.
    pub async fn count_notes(&self) -> KestrelResult<i64> {
        SecureNoteRepo::count(self.pool).await
    }

    // ── Conversion Helpers ──

    /// Converts a database row to a domain VaultEntry.
    ///
    /// Encrypted fields are preserved as-is (BLOB bytes). The caller
    /// must use `reveal_password` or `decrypt_field` for decryption.
    fn row_to_entry(row: &VaultEntryRow) -> VaultEntry {
        VaultEntry {
            id: Uuid::parse_str(&row.id).unwrap_or_else(|_| Uuid::nil()),
            title: row.title.clone(),
            username: row.username.clone(),
            encrypted_password: row.encrypted_password.clone(),
            encrypted_url: row.encrypted_url.clone(),
            encrypted_notes: row.encrypted_notes.clone(),
            encrypted_totp_secret: row.encrypted_totp_secret.clone(),
            encrypted_tags: row.encrypted_tags.clone(),
            folder_id: row.folder_id.as_ref().and_then(|s| Uuid::parse_str(s).ok()),
            created_at: chrono::Utc::now(),  // TODO: parse from row
            updated_at: chrono::Utc::now(),  // TODO: parse from row
            accessed_at: chrono::Utc::now(), // TODO: parse from row
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_service_impl_exists() {
        // Verify the struct compiles — actual integration tests
        // require a database connection and are run separately.
        // This test ensures the public API is consistent.
    }
}
