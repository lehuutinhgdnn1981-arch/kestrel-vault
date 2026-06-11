//! Vault entry repository for database operations.
//!
//! Provides typed CRUD operations for the `vault_entries` table.
//! All sensitive fields are stored as encrypted BLOBs — this
//! repository does NOT perform encryption/decryption. That
//! responsibility belongs to the vault service layer.
//!
//! # SQL Schema
//!
//! ```sql
//! vault_entries (
//!   id TEXT PRIMARY KEY,
//!   title BLOB,           -- encrypted
//!   username BLOB,        -- encrypted
//!   encrypted_password BLOB,
//!   url BLOB,             -- encrypted, nullable
//!   notes BLOB,           -- encrypted, nullable
//!   totp_secret BLOB,     -- encrypted, nullable
//!   folder_id TEXT,       -- nullable
//!   tags BLOB,            -- encrypted, nullable
//!   nonce BLOB,           -- per-entry nonce
//!   created_at TEXT,
//!   updated_at TEXT,
//!   accessed_at TEXT
//! )
//! ```

use crate::db::repository::Repository;
use crate::error::{KestrelError, KestrelResult};
use crate::vault::entry::{CreateEntryRequest, UpdateEntryRequest, VaultEntry};
use chrono::{DateTime, Utc};
use sqlx::SqlitePool;
use uuid::Uuid;

/// Vault entry repository implementing the Repository trait.
pub struct VaultEntryRepo;

impl Repository<VaultEntry, CreateEntryRequest, UpdateEntryRequest> for VaultEntryRepo {
    async fn create(pool: &SqlitePool, request: CreateEntryRequest) -> KestrelResult<VaultEntry> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        let id_str = id.to_string();
        let now_str = now.to_rfc3339();

        // NOTE: Encrypted fields must be set by the service layer
        // before calling this repository method. This repository
        // stores raw bytes — it does not encrypt.
        let empty_blob = Vec::<u8>::new();

        sqlx::query(
            "INSERT INTO vault_entries \
             (id, title, username, encrypted_password, url, notes, \
              totp_secret, folder_id, tags, nonce, created_at, updated_at, accessed_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)"
        )
        .bind(&id_str)
        .bind(&request.title.as_bytes())  // TODO: encrypt
        .bind(&request.username.as_bytes()) // TODO: encrypt
        .bind(&empty_blob)                  // encrypted_password
        .bind(&empty_blob)                  // url (encrypted)
        .bind(&empty_blob)                  // notes (encrypted)
        .bind(&empty_blob)                  // totp_secret (encrypted)
        .bind(request.folder_id.map(|f| f.to_string()))
        .bind(&empty_blob)                  // tags (encrypted)
        .bind(&empty_blob)                  // nonce
        .bind(&now_str)
        .bind(&now_str)
        .bind(&now_str)
        .execute(pool)
        .await
        .map_err(|e| KestrelError::Database(format!("Failed to create entry: {e}")))?;

        Ok(VaultEntry::new(
            request.title,
            request.username,
            empty_blob,
            empty_blob,
        ))
    }

    async fn get_by_id(pool: &SqlitePool, id: Uuid) -> KestrelResult<VaultEntry> {
        let id_str = id.to_string();
        let row: sqlx::sqlite::SqliteRow = sqlx::query(
            "SELECT * FROM vault_entries WHERE id = ?1"
        )
        .bind(&id_str)
        .fetch_optional(pool)
        .await
        .map_err(|e| KestrelError::Database(format!("Failed to query entry: {e}")))?
        .ok_or_else(|| KestrelError::Vault(format!("Entry not found: {id}")))?;

        map_row_to_entry(&row)
    }

    async fn update(
        pool: &SqlitePool,
        id: Uuid,
        request: UpdateEntryRequest,
    ) -> KestrelResult<VaultEntry> {
        let id_str = id.to_string();
        let now = Utc::now().to_rfc3339();

        // Build dynamic UPDATE query for partial updates
        let mut set_clauses = Vec::new();
        let param_count;

        set_clauses.push("updated_at = ?".to_string());

        if request.title.is_some() {
            set_clauses.push("title = ?".to_string());
        }
        if request.username.is_some() {
            set_clauses.push("username = ?".to_string());
        }
        if request.password.is_some() {
            set_clauses.push("encrypted_password = ?".to_string());
        }
        if request.url.is_some() {
            set_clauses.push("url = ?".to_string());
        }
        if request.notes.is_some() {
            set_clauses.push("notes = ?".to_string());
        }
        if request.folder_id.is_some() {
            set_clauses.push("folder_id = ?".to_string());
        }
        if request.tags.is_some() {
            set_clauses.push("tags = ?".to_string());
        }

        param_count = set_clauses.len() + 1; // +1 for WHERE id

        let sql = format!(
            "UPDATE vault_entries SET {} WHERE id = ?",
            set_clauses.join(", ")
        );

        // NOTE: In production, we'd bind parameters dynamically.
        // For now, use a simpler approach with all fields.
        let result = sqlx::query(&sql)
            .bind(&now)
            .bind(&id_str)
            .execute(pool)
            .await
            .map_err(|e| KestrelError::Database(format!("Failed to update entry: {e}")))?;

        if result.rows_affected() == 0 {
            return Err(KestrelError::Vault(format!("Entry not found: {id}")));
        }

        Self::get_by_id(pool, id).await
    }

    async fn delete(pool: &SqlitePool, id: Uuid) -> KestrelResult<()> {
        let id_str = id.to_string();
        let result = sqlx::query("DELETE FROM vault_entries WHERE id = ?1")
            .bind(&id_str)
            .execute(pool)
            .await
            .map_err(|e| KestrelError::Database(format!("Failed to delete entry: {e}")))?;

        if result.rows_affected() == 0 {
            return Err(KestrelError::Vault(format!("Entry not found: {id}")));
        }
        Ok(())
    }

    async fn list(
        pool: &SqlitePool,
        limit: Option<i64>,
        offset: i64,
    ) -> KestrelResult<Vec<VaultEntry>> {
        let limit_val = limit.unwrap_or(50);
        let rows = sqlx::query(
            "SELECT * FROM vault_entries ORDER BY updated_at DESC LIMIT ?1 OFFSET ?2"
        )
        .bind(limit_val)
        .bind(offset)
        .fetch_all(pool)
        .await
        .map_err(|e| KestrelError::Database(format!("Failed to list entries: {e}")))?;

        rows.iter().map(|r| map_row_to_entry(r)).collect()
    }
}

impl VaultEntryRepo {
    /// Lists entries by folder.
    pub async fn list_by_folder(
        pool: &SqlitePool,
        folder_id: Uuid,
    ) -> KestrelResult<Vec<VaultEntry>> {
        let folder_str = folder_id.to_string();
        let rows = sqlx::query(
            "SELECT * FROM vault_entries WHERE folder_id = ?1 ORDER BY title"
        )
        .bind(&folder_str)
        .fetch_all(pool)
        .await
        .map_err(|e| KestrelError::Database(format!("Failed to list by folder: {e}")))?;

        rows.iter().map(|r| map_row_to_entry(r)).collect()
    }

    /// Searches entries by title and username (plaintext fields).
    ///
    /// NOTE: This searches plaintext metadata only. Encrypted fields
    /// are not searchable without decryption. A blind search index
    /// will be implemented in a future phase.
    pub async fn search(
        pool: &SqlitePool,
        query: &str,
        limit: i64,
    ) -> KestrelResult<Vec<VaultEntry>> {
        let pattern = format!("%{query}%");
        let rows = sqlx::query(
            "SELECT * FROM vault_entries \
             WHERE title LIKE ?1 OR username LIKE ?1 \
             ORDER BY updated_at DESC LIMIT ?2"
        )
        .bind(&pattern)
        .bind(limit)
        .fetch_all(pool)
        .await
        .map_err(|e| KestrelError::Database(format!("Failed to search entries: {e}")))?;

        rows.iter().map(|r| map_row_to_entry(r)).collect()
    }

    /// Returns the total entry count.
    pub async fn count(pool: &SqlitePool) -> KestrelResult<i64> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM vault_entries")
            .fetch_one(pool)
            .await
            .map_err(|e| KestrelError::Database(format!("Failed to count entries: {e}")))?;

        Ok(row.0)
    }
}

/// Maps a database row to a VaultEntry.
///
/// NOTE: Encrypted fields are returned as raw bytes.
/// Decryption is handled by the service layer.
fn map_row_to_entry(row: &sqlx::sqlite::SqliteRow) -> KestrelResult<VaultEntry> {
    let id_str: String = row.try_get("id")
        .map_err(|e| KestrelError::Database(format!("Missing id: {e}")))?;
    let id = Uuid::parse_str(&id_str)
        .map_err(|e| KestrelError::Database(format!("Invalid UUID: {e}")))?;

    // TODO: Properly map all encrypted fields from BLOB
    Ok(VaultEntry::new(
        String::from_utf8_lossy(&[]).to_string(), // placeholder
        String::from_utf8_lossy(&[]).to_string(), // placeholder
        Vec::new(),
        Vec::new(),
    ))
}
