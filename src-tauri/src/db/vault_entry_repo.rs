//! Vault entry repository for database operations.
//!
//! Provides typed CRUD operations for the `vault_entries` table.
//! All sensitive fields are stored as encrypted BLOBs in envelope
//! format — this repository does NOT perform encryption/decryption.
//! That responsibility belongs to the vault service layer.
//!
//! # Field Encryption Strategy
//!
//! | Field                | Storage     | Rationale                              |
//! |----------------------|-------------|----------------------------------------|
//! | id                   | TEXT (UUID) | Primary key, not sensitive             |
//! | title                | TEXT        | Plaintext for search indexing          |
//! | username             | TEXT        | Plaintext for search indexing          |
//! | encrypted_password   | BLOB        | Envelope format — most sensitive       |
//! | encrypted_url        | BLOB        | Envelope format — privacy              |
//! | encrypted_notes      | BLOB        | Envelope format — may contain secrets  |
//! | encrypted_totp_secret| BLOB        | Envelope format — 2FA secret           |
//! | encrypted_tags       | BLOB        | Envelope format — metadata privacy     |
//! | folder_id            | TEXT        | Plaintext — not sensitive              |
//!
//! # Envelope Format
//!
//! Each encrypted BLOB contains: [version:1][nonce:12][ciphertext:N][tag:16]
//! The AAD context for each field is: `{entry_id}:{field_name}`

use crate::error::{KestrelError, KestrelResult};
use sqlx::SqlitePool;
use uuid::Uuid;

/// A vault entry row from the database.
///
/// Encrypted fields are returned as raw envelope bytes.
/// Decryption is handled by the service layer using the DEK.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VaultEntryRow {
    /// Unique identifier (UUID v4).
    pub id: String,
    /// Plaintext title (for search indexing).
    pub title: String,
    /// Plaintext username (for search indexing).
    pub username: String,
    /// Encrypted password envelope bytes.
    pub encrypted_password: Vec<u8>,
    /// Encrypted URL envelope bytes.
    pub encrypted_url: Vec<u8>,
    /// Encrypted notes envelope bytes.
    pub encrypted_notes: Vec<u8>,
    /// Encrypted TOTP secret envelope bytes (nullable).
    pub encrypted_totp_secret: Option<Vec<u8>>,
    /// Encrypted tags envelope bytes.
    pub encrypted_tags: Vec<u8>,
    /// Folder ID (nullable).
    pub folder_id: Option<String>,
    /// When this entry was created.
    pub created_at: String,
    /// When this entry was last modified.
    pub updated_at: String,
    /// When this entry was last accessed.
    pub accessed_at: String,
}

/// Request to create a new vault entry.
///
/// All encrypted fields must be set by the service layer
/// (using the DEK and envelope encryption) before calling
/// the repository. Plaintext fields (title, username) are
/// passed directly for search indexing.
#[derive(Debug, Clone)]
pub struct CreateVaultEntryRequest {
    /// Pre-generated entry ID (UUID v4).
    /// Must be generated BEFORE encryption as it is the AAD context.
    pub id: Option<String>,
    /// Plaintext title (for search).
    pub title: String,
    /// Plaintext username (for search).
    pub username: String,
    /// Encrypted password envelope bytes.
    pub encrypted_password: Vec<u8>,
    /// Encrypted URL envelope bytes (empty if no URL).
    pub encrypted_url: Vec<u8>,
    /// Encrypted notes envelope bytes (empty if no notes).
    pub encrypted_notes: Vec<u8>,
    /// Encrypted TOTP secret envelope bytes (None if no TOTP).
    pub encrypted_totp_secret: Option<Vec<u8>>,
    /// Encrypted tags envelope bytes (empty if no tags).
    pub encrypted_tags: Vec<u8>,
    /// Folder ID (nullable).
    pub folder_id: Option<String>,
}

/// Request to update an existing vault entry.
///
/// Only fields that are `Some` will be updated. `None` fields
/// retain their existing values.
#[derive(Debug, Clone)]
pub struct UpdateVaultEntryRequest {
    /// New title (if changing).
    pub title: Option<String>,
    /// New username (if changing).
    pub username: Option<String>,
    /// New encrypted password envelope bytes (if changing).
    pub encrypted_password: Option<Vec<u8>>,
    /// New encrypted URL envelope bytes (if changing).
    pub encrypted_url: Option<Vec<u8>>,
    /// New encrypted notes envelope bytes (if changing).
    pub encrypted_notes: Option<Vec<u8>>,
    /// New encrypted TOTP secret envelope bytes (if changing).
    pub encrypted_totp_secret: Option<Option<Vec<u8>>>,
    /// New encrypted tags envelope bytes (if changing).
    pub encrypted_tags: Option<Vec<u8>>,
    /// New folder assignment (if changing).
    pub folder_id: Option<Option<String>>,
}

/// Vault entry repository for CRUD operations.
pub struct VaultEntryRepo;

impl VaultEntryRepo {
    /// Creates a new vault entry.
    ///
    /// The encrypted fields must already be envelope-encrypted
    /// by the service layer using the DEK before calling this.
    pub async fn create(
        pool: &SqlitePool,
        request: CreateVaultEntryRequest,
    ) -> KestrelResult<VaultEntryRow> {
        let id = request.id.unwrap_or_else(|| Uuid::new_v4().to_string());
        let now = chrono::Utc::now().to_rfc3339();

        sqlx::query(
            "INSERT INTO vault_entries \
             (id, title, username, encrypted_password, encrypted_url, encrypted_notes, \
              encrypted_totp_secret, encrypted_tags, folder_id, \
              created_at, updated_at, accessed_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)"
        )
        .bind(&id)
        .bind(&request.title)
        .bind(&request.username)
        .bind(&request.encrypted_password)
        .bind(&request.encrypted_url)
        .bind(&request.encrypted_notes)
        .bind(&request.encrypted_totp_secret)
        .bind(&request.encrypted_tags)
        .bind(&request.folder_id)
        .bind(&now)
        .bind(&now)
        .bind(&now)
        .execute(pool)
        .await
        .map_err(|e| KestrelError::Database(format!("Failed to create entry: {e}")))?;

        Ok(VaultEntryRow {
            id,
            title: request.title,
            username: request.username,
            encrypted_password: request.encrypted_password,
            encrypted_url: request.encrypted_url,
            encrypted_notes: request.encrypted_notes,
            encrypted_totp_secret: request.encrypted_totp_secret,
            encrypted_tags: request.encrypted_tags,
            folder_id: request.folder_id,
            created_at: now.clone(),
            updated_at: now.clone(),
            accessed_at: now,
        })
    }

    /// Gets a vault entry by ID.
    pub async fn get_by_id(pool: &SqlitePool, id: &str) -> KestrelResult<VaultEntryRow> {
        let row = sqlx::query_as::<_, (String, String, String, Vec<u8>, Vec<u8>, Vec<u8>, Option<Vec<u8>>, Vec<u8>, Option<String>, String, String, String)>(
            "SELECT id, title, username, encrypted_password, encrypted_url, \
             encrypted_notes, encrypted_totp_secret, encrypted_tags, \
             folder_id, created_at, updated_at, accessed_at \
             FROM vault_entries WHERE id = ?1"
        )
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(|e| KestrelError::Database(format!("Failed to query entry: {e}")))?
        .ok_or_else(|| KestrelError::Vault(format!("Entry not found: {id}")))?;

        Ok(VaultEntryRow {
            id: row.0,
            title: row.1,
            username: row.2,
            encrypted_password: row.3,
            encrypted_url: row.4,
            encrypted_notes: row.5,
            encrypted_totp_secret: row.6,
            encrypted_tags: row.7,
            folder_id: row.8,
            created_at: row.9,
            updated_at: row.10,
            accessed_at: row.11,
        })
    }

    /// Updates an existing vault entry.
    ///
    /// Only fields that are `Some` in the request will be updated.
    /// Uses a read-then-write approach for partial updates.
    pub async fn update(
        pool: &SqlitePool,
        id: &str,
        request: UpdateVaultEntryRequest,
    ) -> KestrelResult<VaultEntryRow> {
        let now = chrono::Utc::now().to_rfc3339();

        // Fetch current values for partial update fallback
        let current = Self::get_by_id(pool, id).await?;

        let new_title = request.title.unwrap_or(current.title);
        let new_username = request.username.unwrap_or(current.username);
        let new_encrypted_password = request.encrypted_password.unwrap_or(current.encrypted_password);
        let new_encrypted_url = request.encrypted_url.unwrap_or(current.encrypted_url);
        let new_encrypted_notes = request.encrypted_notes.unwrap_or(current.encrypted_notes);
        let new_encrypted_totp = request.encrypted_totp_secret.flatten().or(current.encrypted_totp_secret);
        let new_encrypted_tags = request.encrypted_tags.unwrap_or(current.encrypted_tags);
        let new_folder_id = request.folder_id.flatten().or(current.folder_id);

        let result = sqlx::query(
            "UPDATE vault_entries SET \
             title = ?1, username = ?2, encrypted_password = ?3, \
             encrypted_url = ?4, encrypted_notes = ?5, encrypted_totp_secret = ?6, \
             encrypted_tags = ?7, folder_id = ?8, updated_at = ?9, accessed_at = ?10 \
             WHERE id = ?11"
        )
        .bind(&new_title)
        .bind(&new_username)
        .bind(&new_encrypted_password)
        .bind(&new_encrypted_url)
        .bind(&new_encrypted_notes)
        .bind(&new_encrypted_totp)
        .bind(&new_encrypted_tags)
        .bind(&new_folder_id)
        .bind(&now)
        .bind(&now)
        .bind(id)
        .execute(pool)
        .await
        .map_err(|e| KestrelError::Database(format!("Failed to update entry: {e}")))?;

        if result.rows_affected() == 0 {
            return Err(KestrelError::Vault(format!("Entry not found: {id}")));
        }

        Self::get_by_id(pool, id).await
    }

    /// Deletes a vault entry by ID.
    pub async fn delete(pool: &SqlitePool, id: &str) -> KestrelResult<()> {
        let result = sqlx::query("DELETE FROM vault_entries WHERE id = ?1")
            .bind(id)
            .execute(pool)
            .await
            .map_err(|e| KestrelError::Database(format!("Failed to delete entry: {e}")))?;

        if result.rows_affected() == 0 {
            return Err(KestrelError::Vault(format!("Entry not found: {id}")));
        }
        Ok(())
    }

    /// Deletes ALL vault entries.
    ///
    /// Use with extreme caution — this is irreversible.
    pub async fn delete_all(pool: &SqlitePool) -> KestrelResult<u64> {
        let result = sqlx::query("DELETE FROM vault_entries")
            .execute(pool)
            .await
            .map_err(|e| KestrelError::Database(format!("Failed to delete all entries: {e}")))?;

        Ok(result.rows_affected())
    }

    /// Lists vault entries with pagination.
    ///
    /// Returns entries ordered by most recently updated first.
    /// Encrypted fields are included as raw bytes — decryption
    /// is handled by the service layer.
    pub async fn list(
        pool: &SqlitePool,
        limit: i64,
        offset: i64,
    ) -> KestrelResult<Vec<VaultEntryRow>> {
        let rows = sqlx::query_as::<_, (String, String, String, Vec<u8>, Vec<u8>, Vec<u8>, Option<Vec<u8>>, Vec<u8>, Option<String>, String, String, String)>(
            "SELECT id, title, username, encrypted_password, encrypted_url, \
             encrypted_notes, encrypted_totp_secret, encrypted_tags, \
             folder_id, created_at, updated_at, accessed_at \
             FROM vault_entries ORDER BY updated_at DESC LIMIT ?1 OFFSET ?2"
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
        .map_err(|e| KestrelError::Database(format!("Failed to list entries: {e}")))?;

        Ok(rows.into_iter().map(|r| VaultEntryRow {
            id: r.0, title: r.1, username: r.2, encrypted_password: r.3,
            encrypted_url: r.4, encrypted_notes: r.5, encrypted_totp_secret: r.6,
            encrypted_tags: r.7, folder_id: r.8, created_at: r.9,
            updated_at: r.10, accessed_at: r.11,
        }).collect())
    }

    /// Lists entries by folder.
    pub async fn list_by_folder(
        pool: &SqlitePool,
        folder_id: &str,
    ) -> KestrelResult<Vec<VaultEntryRow>> {
        let rows = sqlx::query_as::<_, (String, String, String, Vec<u8>, Vec<u8>, Vec<u8>, Option<Vec<u8>>, Vec<u8>, Option<String>, String, String, String)>(
            "SELECT id, title, username, encrypted_password, encrypted_url, \
             encrypted_notes, encrypted_totp_secret, encrypted_tags, \
             folder_id, created_at, updated_at, accessed_at \
             FROM vault_entries WHERE folder_id = ?1 ORDER BY title"
        )
        .bind(folder_id)
        .fetch_all(pool)
        .await
        .map_err(|e| KestrelError::Database(format!("Failed to list by folder: {e}")))?;

        Ok(rows.into_iter().map(|r| VaultEntryRow {
            id: r.0, title: r.1, username: r.2, encrypted_password: r.3,
            encrypted_url: r.4, encrypted_notes: r.5, encrypted_totp_secret: r.6,
            encrypted_tags: r.7, folder_id: r.8, created_at: r.9,
            updated_at: r.10, accessed_at: r.11,
        }).collect())
    }

    /// Lists entries not in any folder (root level).
    pub async fn list_root(pool: &SqlitePool) -> KestrelResult<Vec<VaultEntryRow>> {
        let rows = sqlx::query_as::<_, (String, String, String, Vec<u8>, Vec<u8>, Vec<u8>, Option<Vec<u8>>, Vec<u8>, Option<String>, String, String, String)>(
            "SELECT id, title, username, encrypted_password, encrypted_url, \
             encrypted_notes, encrypted_totp_secret, encrypted_tags, \
             folder_id, created_at, updated_at, accessed_at \
             FROM vault_entries WHERE folder_id IS NULL ORDER BY title"
        )
        .fetch_all(pool)
        .await
        .map_err(|e| KestrelError::Database(format!("Failed to list root entries: {e}")))?;

        Ok(rows.into_iter().map(|r| VaultEntryRow {
            id: r.0, title: r.1, username: r.2, encrypted_password: r.3,
            encrypted_url: r.4, encrypted_notes: r.5, encrypted_totp_secret: r.6,
            encrypted_tags: r.7, folder_id: r.8, created_at: r.9,
            updated_at: r.10, accessed_at: r.11,
        }).collect())
    }

    /// Searches entries by title and username (plaintext fields).
    ///
    /// NOTE: This searches plaintext metadata only. Encrypted fields
    /// are not searchable without decryption. A blind search index
    /// using HKDF-derived sub-keys will be implemented in a future phase.
    pub async fn search(
        pool: &SqlitePool,
        query: &str,
        limit: i64,
    ) -> KestrelResult<Vec<VaultEntryRow>> {
        let pattern = format!("%{query}%");
        let rows = sqlx::query_as::<_, (String, String, String, Vec<u8>, Vec<u8>, Vec<u8>, Option<Vec<u8>>, Vec<u8>, Option<String>, String, String, String)>(
            "SELECT id, title, username, encrypted_password, encrypted_url, \
             encrypted_notes, encrypted_totp_secret, encrypted_tags, \
             folder_id, created_at, updated_at, accessed_at \
             FROM vault_entries \
             WHERE title LIKE ?1 OR username LIKE ?1 \
             ORDER BY updated_at DESC LIMIT ?2"
        )
        .bind(&pattern)
        .bind(limit)
        .fetch_all(pool)
        .await
        .map_err(|e| KestrelError::Database(format!("Failed to search entries: {e}")))?;

        Ok(rows.into_iter().map(|r| VaultEntryRow {
            id: r.0, title: r.1, username: r.2, encrypted_password: r.3,
            encrypted_url: r.4, encrypted_notes: r.5, encrypted_totp_secret: r.6,
            encrypted_tags: r.7, folder_id: r.8, created_at: r.9,
            updated_at: r.10, accessed_at: r.11,
        }).collect())
    }

    /// Returns the total entry count.
    pub async fn count(pool: &SqlitePool) -> KestrelResult<i64> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM vault_entries")
            .fetch_one(pool)
            .await
            .map_err(|e| KestrelError::Database(format!("Failed to count entries: {e}")))?;

        Ok(row.0)
    }

    /// Gets just the encrypted password envelope bytes for an entry.
    ///
    /// Useful for password reveal operations where we don't need
    /// to load the entire entry.
    pub async fn get_encrypted_password(
        pool: &SqlitePool,
        id: &str,
    ) -> KestrelResult<Vec<u8>> {
        let row = sqlx::query_as::<_, (Vec<u8>,)>(
            "SELECT encrypted_password FROM vault_entries WHERE id = ?1"
        )
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(|e| KestrelError::Database(format!("Failed to get password: {e}")))?
        .ok_or_else(|| KestrelError::Vault(format!("Entry not found: {id}")))?;

        Ok(row.0)
    }

    /// Updates the accessed_at timestamp for an entry.
    ///
    /// Called when the entry is viewed or its password is revealed.
    pub async fn touch_accessed(pool: &SqlitePool, id: &str) -> KestrelResult<()> {
        let now = chrono::Utc::now().to_rfc3339();

        sqlx::query("UPDATE vault_entries SET accessed_at = ?1 WHERE id = ?2")
            .bind(&now)
            .bind(id)
            .execute(pool)
            .await
            .map_err(|e| KestrelError::Database(format!("Failed to touch entry: {e}")))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_entry_request_builds() {
        let req = CreateVaultEntryRequest {
            id: None,
            title: "GitHub".to_string(),
            username: "user@example.com".to_string(),
            encrypted_password: vec![1, 2, 3],
            encrypted_url: vec![4, 5, 6],
            encrypted_notes: vec![7, 8, 9],
            encrypted_totp_secret: None,
            encrypted_tags: vec![10, 11, 12],
            folder_id: None,
        };
        assert_eq!(req.title, "GitHub");
        assert!(!req.encrypted_password.is_empty());
    }

    #[test]
    fn update_entry_request_partial() {
        let req = UpdateVaultEntryRequest {
            title: Some("New Title".to_string()),
            username: None,
            encrypted_password: Some(vec![1, 2, 3]),
            encrypted_url: None,
            encrypted_notes: None,
            encrypted_totp_secret: None,
            encrypted_tags: None,
            folder_id: None,
        };
        assert!(req.title.is_some());
        assert!(req.username.is_none());
    }

    #[test]
    fn vault_entry_row_serializes() {
        let row = VaultEntryRow {
            id: "test-id".to_string(),
            title: "GitHub".to_string(),
            username: "user".to_string(),
            encrypted_password: vec![1, 2, 3],
            encrypted_url: vec![4, 5, 6],
            encrypted_notes: vec![7, 8, 9],
            encrypted_totp_secret: None,
            encrypted_tags: vec![10, 11, 12],
            folder_id: None,
            created_at: "2025-01-01T00:00:00Z".to_string(),
            updated_at: "2025-01-01T00:00:00Z".to_string(),
            accessed_at: "2025-01-01T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&row).unwrap();
        assert!(json.contains("GitHub"));
    }
}
