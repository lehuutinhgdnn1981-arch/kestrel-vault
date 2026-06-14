//! Folder repository for database operations.
//!
//! Provides typed CRUD operations for the `folders` table.
//! Folder names are stored as encrypted BLOBs — this repository
//! does NOT perform encryption/decryption.
//!
//! # SQL Schema
//!
//! ```sql
//! folders (
//!   id TEXT PRIMARY KEY,
//!   name BLOB NOT NULL,       -- encrypted
//!   parent_id TEXT,            -- nullable, self-referential FK
//!   nonce BLOB NOT NULL,      -- 96-bit AES-GCM nonce
//!   created_at TEXT,
//!   updated_at TEXT
//! )
//! ```
//!
//! # Security
//!
//! - Folder names are encrypted to prevent organizational structure leakage
//! - Parent-child relationships are stored as plaintext IDs (not sensitive)
//! - Circular references must be prevented at the application layer

use crate::error::{KestrelError, KestrelResult};
use sqlx::SqlitePool;
use uuid::Uuid;

/// A folder row from the database.
///
/// Encrypted fields are returned as raw bytes. Decryption
/// is handled by the service layer.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FolderRow {
    /// Unique identifier (UUID v4).
    pub id: String,
    /// Encrypted folder name (AES-256-GCM ciphertext).
    pub name: Vec<u8>,
    /// Parent folder ID (None = root level).
    pub parent_id: Option<String>,
    /// Nonce used for name encryption.
    pub nonce: Vec<u8>,
    /// When this folder was created.
    pub created_at: String,
    /// When this folder was last updated.
    pub updated_at: String,
}

/// Request to create a new folder.
///
/// The name must be encrypted by the service layer before
/// being passed to the repository.
#[derive(Debug, Clone)]
pub struct CreateFolderRequest {
    /// Pre-generated folder ID (UUID v4).
    /// The ID must be generated BEFORE encryption because it is
    /// used as the AAD context. If None, the repo will generate one
    /// (but this will cause decryption failures if the name was
    /// encrypted with a different ID).
    pub id: Option<String>,
    /// Encrypted folder name (already encrypted).
    pub encrypted_name: Vec<u8>,
    /// Nonce used for name encryption.
    pub nonce: Vec<u8>,
    /// Parent folder ID (None = root level).
    pub parent_id: Option<String>,
}

/// Request to update a folder.
#[derive(Debug, Clone)]
pub struct UpdateFolderRequest {
    /// New encrypted folder name (if changing).
    pub encrypted_name: Option<Vec<u8>>,
    /// New nonce (if name changed).
    pub nonce: Option<Vec<u8>>,
    /// New parent folder ID (if moving).
    pub parent_id: Option<Option<String>>,
}

/// Folder repository for CRUD operations.
pub struct FolderRepo;

impl FolderRepo {
    /// Creates a new folder.
    ///
    /// The folder ID should be pre-generated and passed in the request
    /// so that it matches the AAD context used during name encryption.
    /// If no ID is provided, a new one is generated (but this will
    /// cause decryption failures if the name was encrypted with a
    /// different ID as AAD context).
    pub async fn create(
        pool: &SqlitePool,
        request: CreateFolderRequest,
    ) -> KestrelResult<FolderRow> {
        let id = request.id.unwrap_or_else(|| Uuid::new_v4().to_string());
        let now = chrono::Utc::now().to_rfc3339();

        sqlx::query(
            "INSERT INTO folders (id, name, parent_id, nonce, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
        )
        .bind(&id)
        .bind(&request.encrypted_name)
        .bind(&request.parent_id)
        .bind(&request.nonce)
        .bind(&now)
        .bind(&now)
        .execute(pool)
        .await
        .map_err(|e| KestrelError::Database(format!("Failed to create folder: {e}")))?;

        Ok(FolderRow {
            id,
            name: request.encrypted_name,
            parent_id: request.parent_id,
            nonce: request.nonce,
            created_at: now.clone(),
            updated_at: now,
        })
    }

    /// Gets a folder by ID.
    pub async fn get_by_id(pool: &SqlitePool, id: &str) -> KestrelResult<FolderRow> {
        let row = sqlx::query_as::<_, (String, Vec<u8>, Option<String>, Vec<u8>, String, String)>(
            "SELECT id, name, parent_id, nonce, created_at, updated_at \
             FROM folders WHERE id = ?1"
        )
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(|e| KestrelError::Database(format!("Failed to get folder: {e}")))?
        .ok_or_else(|| KestrelError::Vault(format!("Folder not found: {id}")))?;

        Ok(FolderRow {
            id: row.0,
            name: row.1,
            parent_id: row.2,
            nonce: row.3,
            created_at: row.4,
            updated_at: row.5,
        })
    }

    /// Updates a folder.
    pub async fn update(
        pool: &SqlitePool,
        id: &str,
        request: UpdateFolderRequest,
    ) -> KestrelResult<FolderRow> {
        let now = chrono::Utc::now().to_rfc3339();

        // Build dynamic update
        let mut updates = vec!["updated_at = ?".to_string()];
        let _param_idx = 2; // Start after id

        if request.encrypted_name.is_some() {
            updates.push(format!("name = ?"));
        }
        if request.nonce.is_some() {
            updates.push(format!("nonce = ?"));
        }
        if request.parent_id.is_some() {
            updates.push("parent_id = ?".to_string());
        }

        // Simple approach: update all if provided
        if request.encrypted_name.is_some() || request.nonce.is_some() || request.parent_id.is_some() {
            let _sql = format!(
                "UPDATE folders SET {} WHERE id = ?",
                updates.join(", ")
            );

            // For simplicity, use a full update approach
            let result = sqlx::query(
                "UPDATE folders SET name = ?1, nonce = ?2, parent_id = ?3, updated_at = ?4 WHERE id = ?5"
            )
            .bind(request.encrypted_name.unwrap_or_default())
            .bind(request.nonce.unwrap_or_default())
            .bind(request.parent_id.flatten())
            .bind(&now)
            .bind(id)
            .execute(pool)
            .await
            .map_err(|e| KestrelError::Database(format!("Failed to update folder: {e}")))?;

            if result.rows_affected() == 0 {
                return Err(KestrelError::Vault(format!("Folder not found: {id}")));
            }
        }

        Self::get_by_id(pool, id).await
    }

    /// Deletes a folder by ID.
    ///
    /// Note: CASCADE will set folder_id to NULL on orphaned entries.
    pub async fn delete(pool: &SqlitePool, id: &str) -> KestrelResult<()> {
        let result = sqlx::query("DELETE FROM folders WHERE id = ?1")
            .bind(id)
            .execute(pool)
            .await
            .map_err(|e| KestrelError::Database(format!("Failed to delete folder: {e}")))?;

        if result.rows_affected() == 0 {
            return Err(KestrelError::Vault(format!("Folder not found: {id}")));
        }
        Ok(())
    }

    /// Deletes ALL folders.
    ///
    /// Use with extreme caution — this is irreversible.
    /// Note: CASCADE will set folder_id to NULL on orphaned entries.
    pub async fn delete_all(pool: &SqlitePool) -> KestrelResult<u64> {
        let result = sqlx::query("DELETE FROM folders")
            .execute(pool)
            .await
            .map_err(|e| KestrelError::Database(format!("Failed to delete all folders: {e}")))?;

        Ok(result.rows_affected())
    }

    /// Lists all root-level folders (parent_id IS NULL).
    pub async fn list_root(pool: &SqlitePool) -> KestrelResult<Vec<FolderRow>> {
        let rows = sqlx::query_as::<_, (String, Vec<u8>, Option<String>, Vec<u8>, String, String)>(
            "SELECT id, name, parent_id, nonce, created_at, updated_at \
             FROM folders WHERE parent_id IS NULL ORDER BY created_at"
        )
        .fetch_all(pool)
        .await
        .map_err(|e| KestrelError::Database(format!("Failed to list root folders: {e}")))?;

        Ok(rows.into_iter().map(|r| FolderRow {
            id: r.0, name: r.1, parent_id: r.2, nonce: r.3, created_at: r.4, updated_at: r.5,
        }).collect())
    }

    /// Lists child folders of a parent.
    pub async fn list_by_parent(
        pool: &SqlitePool,
        parent_id: &str,
    ) -> KestrelResult<Vec<FolderRow>> {
        let rows = sqlx::query_as::<_, (String, Vec<u8>, Option<String>, Vec<u8>, String, String)>(
            "SELECT id, name, parent_id, nonce, created_at, updated_at \
             FROM folders WHERE parent_id = ?1 ORDER BY created_at"
        )
        .bind(parent_id)
        .fetch_all(pool)
        .await
        .map_err(|e| KestrelError::Database(format!("Failed to list child folders: {e}")))?;

        Ok(rows.into_iter().map(|r| FolderRow {
            id: r.0, name: r.1, parent_id: r.2, nonce: r.3, created_at: r.4, updated_at: r.5,
        }).collect())
    }

    /// Lists all folders.
    pub async fn list_all(pool: &SqlitePool) -> KestrelResult<Vec<FolderRow>> {
        let rows = sqlx::query_as::<_, (String, Vec<u8>, Option<String>, Vec<u8>, String, String)>(
            "SELECT id, name, parent_id, nonce, created_at, updated_at \
             FROM folders ORDER BY created_at"
        )
        .fetch_all(pool)
        .await
        .map_err(|e| KestrelError::Database(format!("Failed to list all folders: {e}")))?;

        Ok(rows.into_iter().map(|r| FolderRow {
            id: r.0, name: r.1, parent_id: r.2, nonce: r.3, created_at: r.4, updated_at: r.5,
        }).collect())
    }

    /// Counts entries in a folder.
    pub async fn count_entries(pool: &SqlitePool, folder_id: &str) -> KestrelResult<i64> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM vault_entries WHERE folder_id = ?1"
        )
        .bind(folder_id)
        .fetch_one(pool)
        .await
        .map_err(|e| KestrelError::Database(format!("Failed to count entries: {e}")))?;

        Ok(row.0)
    }

    /// Checks if a circular reference would be created by moving
    /// a folder under a new parent.
    ///
    /// Returns true if moving `folder_id` under `new_parent_id`
    /// would create a cycle (i.e., `new_parent_id` is a descendant
    /// of `folder_id`).
    pub async fn would_create_cycle(
        pool: &SqlitePool,
        folder_id: &str,
        new_parent_id: &str,
    ) -> KestrelResult<bool> {
        // Walk up from new_parent_id to see if we reach folder_id
        let mut current_id = new_parent_id.to_string();
        let max_depth = 100; // Prevent infinite loops

        for _ in 0..max_depth {
            if current_id == folder_id {
                return Ok(true);
            }
            let row: Option<(Option<String>,)> = sqlx::query_as(
                "SELECT parent_id FROM folders WHERE id = ?1"
            )
            .bind(&current_id)
            .fetch_optional(pool)
            .await
            .map_err(|e| KestrelError::Database(format!("Cycle check query failed: {e}")))?;

            match row {
                Some((Some(parent),)) => current_id = parent,
                _ => break, // Reached root
            }
        }

        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folder_row_serializes() {
        let row = FolderRow {
            id: "test-id".to_string(),
            name: vec![1, 2, 3],
            parent_id: None,
            nonce: vec![4, 5, 6],
            created_at: "2025-01-01T00:00:00Z".to_string(),
            updated_at: "2025-01-01T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&row).unwrap();
        assert!(json.contains("test-id"));
    }

    #[test]
    fn create_folder_request_builds() {
        let req = CreateFolderRequest {
            id: None,
            encrypted_name: vec![1, 2, 3],
            nonce: vec![4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            parent_id: None,
        };
        assert!(req.encrypted_name.len() == 3);
        assert!(req.nonce.len() == 12);
    }
}
