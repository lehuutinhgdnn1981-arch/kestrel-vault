//! Secure note repository for database operations.
//!
//! Provides typed CRUD operations for the `secure_notes` table.
//! Both title and content are stored as encrypted BLOBs — this
//! repository does NOT perform encryption/decryption.
//!
//! # SQL Schema
//!
//! ```sql
//! secure_notes (
//!   id TEXT PRIMARY KEY,
//!   title BLOB NOT NULL,      -- encrypted
//!   content BLOB NOT NULL,    -- encrypted
//!   folder_id TEXT,            -- nullable FK
//!   tags BLOB,                 -- encrypted, nullable
//!   nonce BLOB NOT NULL,      -- 96-bit AES-GCM nonce
//!   created_at TEXT,
//!   updated_at TEXT
//! )
//! ```
//!
//! # Security
//!
//! - Note titles and content are encrypted with AES-256-GCM
//! - Tags are encrypted to prevent metadata leakage
//! - Content is only decrypted through explicit reveal commands

use crate::error::{KestrelError, KestrelResult};
use sqlx::SqlitePool;
use uuid::Uuid;

/// A secure note row from the database.
///
/// Encrypted fields are returned as raw bytes. Decryption
/// is handled by the service layer.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SecureNoteRow {
    /// Unique identifier (UUID v4).
    pub id: String,
    /// Encrypted note title (AES-256-GCM ciphertext).
    pub title: Vec<u8>,
    /// Encrypted note content (AES-256-GCM ciphertext).
    pub content: Vec<u8>,
    /// Folder ID (nullable).
    pub folder_id: Option<String>,
    /// Encrypted tags (AES-256-GCM ciphertext, nullable).
    pub tags: Option<Vec<u8>>,
    /// Nonce used for encryption.
    pub nonce: Vec<u8>,
    /// When this note was created.
    pub created_at: String,
    /// When this note was last updated.
    pub updated_at: String,
}

/// Request to create a new secure note.
///
/// All encrypted fields must be set by the service layer
/// before calling the repository.
#[derive(Debug, Clone)]
pub struct CreateSecureNoteRequest {
    /// Encrypted title (already encrypted).
    pub encrypted_title: Vec<u8>,
    /// Encrypted content (already encrypted).
    pub encrypted_content: Vec<u8>,
    /// Nonce used for encryption.
    pub nonce: Vec<u8>,
    /// Folder ID (nullable).
    pub folder_id: Option<String>,
    /// Encrypted tags (nullable).
    pub encrypted_tags: Option<Vec<u8>>,
}

/// Request to update a secure note.
#[derive(Debug, Clone)]
pub struct UpdateSecureNoteRequest {
    /// New encrypted title (if changing).
    pub encrypted_title: Option<Vec<u8>>,
    /// New encrypted content (if changing).
    pub encrypted_content: Option<Vec<u8>>,
    /// New nonce (if content changed).
    pub nonce: Option<Vec<u8>>,
    /// New folder assignment (if changing).
    pub folder_id: Option<Option<String>>,
    /// New encrypted tags (if changing).
    pub encrypted_tags: Option<Option<Vec<u8>>>,
}

/// Secure note repository for CRUD operations.
pub struct SecureNoteRepo;

impl SecureNoteRepo {
    /// Creates a new secure note.
    pub async fn create(
        pool: &SqlitePool,
        request: CreateSecureNoteRequest,
    ) -> KestrelResult<SecureNoteRow> {
        let id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();

        sqlx::query(
            "INSERT INTO secure_notes (id, title, content, folder_id, tags, nonce, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"
        )
        .bind(&id)
        .bind(&request.encrypted_title)
        .bind(&request.encrypted_content)
        .bind(&request.folder_id)
        .bind(&request.encrypted_tags)
        .bind(&request.nonce)
        .bind(&now)
        .bind(&now)
        .execute(pool)
        .await
        .map_err(|e| KestrelError::Database(format!("Failed to create secure note: {e}")))?;

        Ok(SecureNoteRow {
            id,
            title: request.encrypted_title,
            content: request.encrypted_content,
            folder_id: request.folder_id,
            tags: request.encrypted_tags,
            nonce: request.nonce,
            created_at: now.clone(),
            updated_at: now,
        })
    }

    /// Gets a secure note by ID.
    pub async fn get_by_id(pool: &SqlitePool, id: &str) -> KestrelResult<SecureNoteRow> {
        let row = sqlx::query_as::<_, (String, Vec<u8>, Vec<u8>, Option<String>, Option<Vec<u8>>, Vec<u8>, String, String)>(
            "SELECT id, title, content, folder_id, tags, nonce, created_at, updated_at \
             FROM secure_notes WHERE id = ?1"
        )
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(|e| KestrelError::Database(format!("Failed to get secure note: {e}")))?
        .ok_or_else(|| KestrelError::Vault(format!("Secure note not found: {id}")))?;

        Ok(SecureNoteRow {
            id: row.0,
            title: row.1,
            content: row.2,
            folder_id: row.3,
            tags: row.4,
            nonce: row.5,
            created_at: row.6,
            updated_at: row.7,
        })
    }

    /// Updates a secure note.
    pub async fn update(
        pool: &SqlitePool,
        id: &str,
        request: UpdateSecureNoteRequest,
    ) -> KestrelResult<SecureNoteRow> {
        let now = chrono::Utc::now().to_rfc3339();

        // Fetch current for fallback values
        let current = Self::get_by_id(pool, id).await?;

        let new_title = request.encrypted_title.unwrap_or(current.title);
        let new_content = request.encrypted_content.unwrap_or(current.content);
        let new_nonce = request.nonce.unwrap_or(current.nonce);
        let new_folder_id = request.folder_id.flatten().or(current.folder_id);
        let new_tags = request.encrypted_tags.flatten().or(current.tags);

        let result = sqlx::query(
            "UPDATE secure_notes SET title = ?1, content = ?2, folder_id = ?3, \
             tags = ?4, nonce = ?5, updated_at = ?6 WHERE id = ?7"
        )
        .bind(&new_title)
        .bind(&new_content)
        .bind(&new_folder_id)
        .bind(&new_tags)
        .bind(&new_nonce)
        .bind(&now)
        .bind(id)
        .execute(pool)
        .await
        .map_err(|e| KestrelError::Database(format!("Failed to update secure note: {e}")))?;

        if result.rows_affected() == 0 {
            return Err(KestrelError::Vault(format!("Secure note not found: {id}")));
        }

        Self::get_by_id(pool, id).await
    }

    /// Deletes a secure note by ID.
    pub async fn delete(pool: &SqlitePool, id: &str) -> KestrelResult<()> {
        let result = sqlx::query("DELETE FROM secure_notes WHERE id = ?1")
            .bind(id)
            .execute(pool)
            .await
            .map_err(|e| KestrelError::Database(format!("Failed to delete secure note: {e}")))?;

        if result.rows_affected() == 0 {
            return Err(KestrelError::Vault(format!("Secure note not found: {id}")));
        }
        Ok(())
    }

    /// Lists secure notes by folder.
    pub async fn list_by_folder(
        pool: &SqlitePool,
        folder_id: Option<&str>,
    ) -> KestrelResult<Vec<SecureNoteRow>> {
        let rows = match folder_id {
            Some(fid) => {
                sqlx::query_as::<_, (String, Vec<u8>, Vec<u8>, Option<String>, Option<Vec<u8>>, Vec<u8>, String, String)>(
                    "SELECT id, title, content, folder_id, tags, nonce, created_at, updated_at \
                     FROM secure_notes WHERE folder_id = ?1 ORDER BY updated_at DESC"
                )
                .bind(fid)
                .fetch_all(pool)
                .await
            }
            None => {
                sqlx::query_as::<_, (String, Vec<u8>, Vec<u8>, Option<String>, Option<Vec<u8>>, Vec<u8>, String, String)>(
                    "SELECT id, title, content, folder_id, tags, nonce, created_at, updated_at \
                     FROM secure_notes ORDER BY updated_at DESC"
                )
                .fetch_all(pool)
                .await
            }
        }
        .map_err(|e| KestrelError::Database(format!("Failed to list secure notes: {e}")))?;

        Ok(rows.into_iter().map(|r| SecureNoteRow {
            id: r.0, title: r.1, content: r.2, folder_id: r.3, tags: r.4, nonce: r.5,
            created_at: r.6, updated_at: r.7,
        }).collect())
    }

    /// Returns the total note count.
    pub async fn count(pool: &SqlitePool) -> KestrelResult<i64> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM secure_notes")
            .fetch_one(pool)
            .await
            .map_err(|e| KestrelError::Database(format!("Failed to count notes: {e}")))?;

        Ok(row.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_note_row_serializes() {
        let row = SecureNoteRow {
            id: "test-id".to_string(),
            title: vec![1, 2, 3],
            content: vec![4, 5, 6],
            folder_id: None,
            tags: None,
            nonce: vec![7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18],
            created_at: "2025-01-01T00:00:00Z".to_string(),
            updated_at: "2025-01-01T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&row).unwrap();
        assert!(json.contains("test-id"));
    }

    #[test]
    fn create_note_request_builds() {
        let req = CreateSecureNoteRequest {
            encrypted_title: vec![1, 2, 3],
            encrypted_content: vec![4, 5, 6],
            nonce: vec![7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18],
            folder_id: None,
            encrypted_tags: None,
        };
        assert!(req.encrypted_title.len() == 3);
    }
}
