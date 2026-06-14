//! File entry repository for database operations.
//!
//! Provides typed CRUD operations for the `file_entries` table.
//! Filenames, paths, and MIME types are stored as encrypted BLOBs.
//! Actual file data is stored on disk, encrypted separately.
//!
//! # SQL Schema
//!
//! ```sql
//! file_entries (
//!   id TEXT PRIMARY KEY,
//!   filename BLOB NOT NULL,         -- encrypted
//!   encrypted_path BLOB NOT NULL,   -- encrypted on-disk path
//!   file_size BLOB NOT NULL,        -- encrypted file size
//!   mime_type BLOB,                 -- encrypted, nullable
//!   folder_id TEXT,                 -- nullable FK
//!   nonce BLOB NOT NULL,            -- 96-bit AES-GCM nonce
//!   created_at TEXT,
//!   updated_at TEXT
//! )
//! ```
//!
//! # Security
//!
//! - Filenames are encrypted to prevent content type inference
//! - File sizes are encrypted to prevent pattern analysis
//! - On-disk paths are encrypted to prevent filesystem enumeration
//! - Actual file content is stored encrypted on disk

use crate::error::{KestrelError, KestrelResult};
use sqlx::SqlitePool;
use uuid::Uuid;

/// A file entry row from the database.
///
/// Encrypted fields are returned as raw bytes. Decryption
/// is handled by the service layer.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileEntryRow {
    /// Unique identifier (UUID v4).
    pub id: String,
    /// Encrypted original filename (AES-256-GCM ciphertext).
    pub filename: Vec<u8>,
    /// Encrypted on-disk path (AES-256-GCM ciphertext).
    pub encrypted_path: Vec<u8>,
    /// Encrypted file size in bytes (AES-256-GCM ciphertext).
    pub file_size: Vec<u8>,
    /// Encrypted MIME type (AES-256-GCM ciphertext, nullable).
    pub mime_type: Option<Vec<u8>>,
    /// Folder ID (nullable).
    pub folder_id: Option<String>,
    /// Nonce used for encryption.
    pub nonce: Vec<u8>,
    /// When this file entry was created.
    pub created_at: String,
    /// When this file entry was last updated.
    pub updated_at: String,
}

/// Request to create a new file entry.
///
/// All encrypted fields must be set by the service layer
/// before calling the repository.
#[derive(Debug, Clone)]
pub struct CreateFileEntryRequest {
    /// Pre-generated file entry ID (UUID v4).
    /// The ID must be generated BEFORE encryption because it is
    /// used as the AAD context for metadata encryption.
    /// If None, the repo will generate one (but this will cause
    /// decryption failures if metadata was encrypted with a different ID).
    pub id: Option<String>,
    /// Encrypted filename (already encrypted).
    pub encrypted_filename: Vec<u8>,
    /// Encrypted on-disk path (already encrypted).
    pub encrypted_path: Vec<u8>,
    /// Encrypted file size (already encrypted).
    pub encrypted_file_size: Vec<u8>,
    /// Encrypted MIME type (nullable).
    pub encrypted_mime_type: Option<Vec<u8>>,
    /// Nonce used for encryption.
    pub nonce: Vec<u8>,
    /// Folder ID (nullable).
    pub folder_id: Option<String>,
}

/// Request to update a file entry.
#[derive(Debug, Clone)]
pub struct UpdateFileEntryRequest {
    /// New encrypted filename (if changing).
    pub encrypted_filename: Option<Vec<u8>>,
    /// New encrypted MIME type (if changing).
    pub encrypted_mime_type: Option<Option<Vec<u8>>>,
    /// New folder assignment (if moving).
    pub folder_id: Option<Option<String>>,
}

/// File entry repository for CRUD operations.
pub struct FileEntryRepo;

impl FileEntryRepo {
    /// Creates a new file entry.
    ///
    /// The file entry ID should be pre-generated and passed in the request
    /// so that it matches the AAD context used during metadata encryption.
    /// If no ID is provided, a new one is generated (but this will cause
    /// decryption failures if metadata was encrypted with a different ID).
    pub async fn create(
        pool: &SqlitePool,
        request: CreateFileEntryRequest,
    ) -> KestrelResult<FileEntryRow> {
        let id = request.id.unwrap_or_else(|| Uuid::new_v4().to_string());
        let now = chrono::Utc::now().to_rfc3339();

        sqlx::query(
            "INSERT INTO file_entries (id, filename, encrypted_path, file_size, \
             mime_type, folder_id, nonce, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"
        )
        .bind(&id)
        .bind(&request.encrypted_filename)
        .bind(&request.encrypted_path)
        .bind(&request.encrypted_file_size)
        .bind(&request.encrypted_mime_type)
        .bind(&request.folder_id)
        .bind(&request.nonce)
        .bind(&now)
        .bind(&now)
        .execute(pool)
        .await
        .map_err(|e| KestrelError::Database(format!("Failed to create file entry: {e}")))?;

        Ok(FileEntryRow {
            id,
            filename: request.encrypted_filename,
            encrypted_path: request.encrypted_path,
            file_size: request.encrypted_file_size,
            mime_type: request.encrypted_mime_type,
            folder_id: request.folder_id,
            nonce: request.nonce,
            created_at: now.clone(),
            updated_at: now,
        })
    }

    /// Gets a file entry by ID.
    pub async fn get_by_id(pool: &SqlitePool, id: &str) -> KestrelResult<FileEntryRow> {
        let row = sqlx::query_as::<_, (String, Vec<u8>, Vec<u8>, Vec<u8>, Option<Vec<u8>>, Option<String>, Vec<u8>, String, String)>(
            "SELECT id, filename, encrypted_path, file_size, mime_type, \
             folder_id, nonce, created_at, updated_at \
             FROM file_entries WHERE id = ?1"
        )
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(|e| KestrelError::Database(format!("Failed to get file entry: {e}")))?
        .ok_or_else(|| KestrelError::Vault(format!("File entry not found: {id}")))?;

        Ok(FileEntryRow {
            id: row.0,
            filename: row.1,
            encrypted_path: row.2,
            file_size: row.3,
            mime_type: row.4,
            folder_id: row.5,
            nonce: row.6,
            created_at: row.7,
            updated_at: row.8,
        })
    }

    /// Updates a file entry.
    pub async fn update(
        pool: &SqlitePool,
        id: &str,
        request: UpdateFileEntryRequest,
    ) -> KestrelResult<FileEntryRow> {
        let now = chrono::Utc::now().to_rfc3339();

        let current = Self::get_by_id(pool, id).await?;

        let new_filename = request.encrypted_filename.unwrap_or(current.filename);
        let new_mime_type = request.encrypted_mime_type.flatten().or(current.mime_type);
        let new_folder_id = request.folder_id.flatten().or(current.folder_id);

        let result = sqlx::query(
            "UPDATE file_entries SET filename = ?1, mime_type = ?2, folder_id = ?3, \
             updated_at = ?4 WHERE id = ?5"
        )
        .bind(&new_filename)
        .bind(&new_mime_type)
        .bind(&new_folder_id)
        .bind(&now)
        .bind(id)
        .execute(pool)
        .await
        .map_err(|e| KestrelError::Database(format!("Failed to update file entry: {e}")))?;

        if result.rows_affected() == 0 {
            return Err(KestrelError::Vault(format!("File entry not found: {id}")));
        }

        Self::get_by_id(pool, id).await
    }

    /// Deletes a file entry by ID.
    ///
    /// Note: The actual encrypted file on disk must be deleted
    /// separately by the service layer.
    pub async fn delete(pool: &SqlitePool, id: &str) -> KestrelResult<()> {
        let result = sqlx::query("DELETE FROM file_entries WHERE id = ?1")
            .bind(id)
            .execute(pool)
            .await
            .map_err(|e| KestrelError::Database(format!("Failed to delete file entry: {e}")))?;

        if result.rows_affected() == 0 {
            return Err(KestrelError::Vault(format!("File entry not found: {id}")));
        }
        Ok(())
    }

    /// Deletes ALL file entries.
    ///
    /// Use with extreme caution — this is irreversible.
    /// Note: The actual encrypted files on disk must be deleted separately.
    pub async fn delete_all(pool: &SqlitePool) -> KestrelResult<u64> {
        let result = sqlx::query("DELETE FROM file_entries")
            .execute(pool)
            .await
            .map_err(|e| KestrelError::Database(format!("Failed to delete all file entries: {e}")))?;

        Ok(result.rows_affected())
    }

    /// Lists file entries by folder.
    pub async fn list_by_folder(
        pool: &SqlitePool,
        folder_id: Option<&str>,
    ) -> KestrelResult<Vec<FileEntryRow>> {
        let rows = match folder_id {
            Some(fid) => {
                sqlx::query_as::<_, (String, Vec<u8>, Vec<u8>, Vec<u8>, Option<Vec<u8>>, Option<String>, Vec<u8>, String, String)>(
                    "SELECT id, filename, encrypted_path, file_size, mime_type, \
                     folder_id, nonce, created_at, updated_at \
                     FROM file_entries WHERE folder_id = ?1 ORDER BY created_at DESC"
                )
                .bind(fid)
                .fetch_all(pool)
                .await
            }
            None => {
                sqlx::query_as::<_, (String, Vec<u8>, Vec<u8>, Vec<u8>, Option<Vec<u8>>, Option<String>, Vec<u8>, String, String)>(
                    "SELECT id, filename, encrypted_path, file_size, mime_type, \
                     folder_id, nonce, created_at, updated_at \
                     FROM file_entries ORDER BY created_at DESC"
                )
                .fetch_all(pool)
                .await
            }
        }
        .map_err(|e| KestrelError::Database(format!("Failed to list file entries: {e}")))?;

        Ok(rows.into_iter().map(|r| FileEntryRow {
            id: r.0, filename: r.1, encrypted_path: r.2, file_size: r.3,
            mime_type: r.4, folder_id: r.5, nonce: r.6, created_at: r.7, updated_at: r.8,
        }).collect())
    }

    /// Returns the total file entry count.
    pub async fn count(pool: &SqlitePool) -> KestrelResult<i64> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM file_entries")
            .fetch_one(pool)
            .await
            .map_err(|e| KestrelError::Database(format!("Failed to count file entries: {e}")))?;

        Ok(row.0)
    }

    /// Returns the total encrypted file size (sum of all files).
    ///
    /// Note: This requires decrypting file_size values, which
    /// should be done at the service layer. This method returns
    /// the count of entries for now.
    pub async fn total_file_count(pool: &SqlitePool) -> KestrelResult<i64> {
        Self::count(pool).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_entry_row_serializes() {
        let row = FileEntryRow {
            id: "test-id".to_string(),
            filename: vec![1, 2, 3],
            encrypted_path: vec![4, 5, 6],
            file_size: vec![7, 8, 9],
            mime_type: Some(vec![10, 11, 12]),
            folder_id: None,
            nonce: vec![13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24],
            created_at: "2025-01-01T00:00:00Z".to_string(),
            updated_at: "2025-01-01T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&row).unwrap();
        assert!(json.contains("test-id"));
    }

    #[test]
    fn create_file_entry_request_builds() {
        let req = CreateFileEntryRequest {
            id: None,
            encrypted_filename: vec![1, 2, 3],
            encrypted_path: vec![4, 5, 6],
            encrypted_file_size: vec![7, 8, 9],
            encrypted_mime_type: Some(vec![10, 11, 12]),
            nonce: vec![13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24],
            folder_id: None,
        };
        assert!(req.encrypted_filename.len() == 3);
    }
}
