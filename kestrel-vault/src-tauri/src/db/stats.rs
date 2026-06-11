//! Database statistics for KESTREL Vault.
//!
//! Provides a unified API for gathering statistics about the vault
//! database. This includes counts of entries, folders, notes, and
//! file attachments, as well as storage metrics and activity summaries.
//!
//! # Usage
//!
//! ```ignore
//! let stats = VaultStats::gather(&pool).await?;
//! println!("Total entries: {}", stats.total_entries);
//! println!("Database size: {}", stats.db_size_human);
//! ```
//!
//! # Design
//!
//! All statistics are gathered in a single pass where possible.
//! Each count query is independent, so they can be run concurrently
//! in a future optimization. The stats are read-only and never
//! modify the database.

use crate::error::{KestrelError, KestrelResult};
use sqlx::SqlitePool;

/// Comprehensive vault statistics.
///
/// Gathers counts, sizes, and activity metrics from all vault
/// tables. This provides a dashboard-level overview of the vault.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VaultStats {
    // ── Entry Counts ──

    /// Total number of password entries.
    pub total_entries: i64,

    /// Number of entries with TOTP configured.
    pub entries_with_totp: i64,

    /// Number of entries not in any folder (root level).
    pub root_entries: i64,

    // ── Folder Counts ──

    /// Total number of folders.
    pub total_folders: i64,

    /// Number of root-level folders (no parent).
    pub root_folders: i64,

    /// Maximum folder nesting depth.
    pub max_folder_depth: i64,

    // ── Secure Note Counts ──

    /// Total number of secure notes.
    pub total_notes: i64,

    // ── File Attachment Counts ──

    /// Total number of file attachments.
    pub total_files: i64,

    // ── Audit Event Counts ──

    /// Total number of audit events.
    pub total_audit_events: i64,

    /// Number of audit events in the last 24 hours.
    pub audit_events_last_24h: i64,

    /// Number of password reveal events in the last 24 hours.
    pub password_reveals_last_24h: i64,

    // ── Activity Metrics ──

    /// Number of entries modified in the last 7 days.
    pub entries_modified_last_7d: i64,

    /// Number of entries never accessed (accessed_at == created_at).
    pub entries_never_accessed: i64,

    // ── Database Health ──

    /// Current schema version.
    pub schema_version: u32,

    /// Whether KDF parameters need upgrading.
    pub kdf_needs_upgrade: bool,
}

impl VaultStats {
    /// Gathers comprehensive vault statistics from the database.
    ///
    /// This executes multiple count queries against the database.
    /// For large vaults, this may take a few hundred milliseconds.
    ///
    /// # Errors
    ///
    /// Returns `KestrelError::Database` if any query fails.
    pub async fn gather(pool: &SqlitePool) -> KestrelResult<Self> {
        Ok(VaultStats {
            total_entries: Self::count_entries(pool).await?,
            entries_with_totp: Self::count_entries_with_totp(pool).await?,
            root_entries: Self::count_root_entries(pool).await?,
            total_folders: Self::count_folders(pool).await?,
            root_folders: Self::count_root_folders(pool).await?,
            max_folder_depth: Self::compute_max_folder_depth(pool).await?,
            total_notes: Self::count_notes(pool).await?,
            total_files: Self::count_files(pool).await?,
            total_audit_events: Self::count_audit_events(pool).await?,
            audit_events_last_24h: Self::count_audit_events_last_24h(pool).await?,
            password_reveals_last_24h: Self::count_password_reveals_last_24h(pool).await?,
            entries_modified_last_7d: Self::count_entries_modified_last_7d(pool).await?,
            entries_never_accessed: Self::count_entries_never_accessed(pool).await?,
            schema_version: Self::get_schema_version(pool).await?,
            kdf_needs_upgrade: Self::check_kdf_upgrade(pool).await?,
        })
    }

    // ── Individual Query Methods ──

    /// Counts total vault entries.
    async fn count_entries(pool: &SqlitePool) -> KestrelResult<i64> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM vault_entries")
            .fetch_one(pool)
            .await
            .map_err(|e| KestrelError::Database(format!("Failed to count entries: {e}")))?;
        Ok(row.0)
    }

    /// Counts entries with TOTP configured.
    async fn count_entries_with_totp(pool: &SqlitePool) -> KestrelResult<i64> {
        let row: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM vault_entries WHERE encrypted_totp_secret IS NOT NULL")
                .fetch_one(pool)
                .await
                .map_err(|e| KestrelError::Database(format!("Failed to count TOTP entries: {e}")))?;
        Ok(row.0)
    }

    /// Counts root-level entries (no folder).
    async fn count_root_entries(pool: &SqlitePool) -> KestrelResult<i64> {
        let row: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM vault_entries WHERE folder_id IS NULL")
                .fetch_one(pool)
                .await
                .map_err(|e| KestrelError::Database(format!("Failed to count root entries: {e}")))?;
        Ok(row.0)
    }

    /// Counts total folders.
    async fn count_folders(pool: &SqlitePool) -> KestrelResult<i64> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM folders")
            .fetch_one(pool)
            .await
            .map_err(|e| KestrelError::Database(format!("Failed to count folders: {e}")))?;
        Ok(row.0)
    }

    /// Counts root-level folders (no parent).
    async fn count_root_folders(pool: &SqlitePool) -> KestrelResult<i64> {
        let row: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM folders WHERE parent_id IS NULL")
                .fetch_one(pool)
                .await
                .map_err(|e| KestrelError::Database(format!("Failed to count root folders: {e}")))?;
        Ok(row.0)
    }

    /// Computes maximum folder nesting depth.
    ///
    /// Walks the folder tree to find the deepest nesting level.
    /// Returns 0 if there are no folders. A single root folder
    /// with no children has depth 1.
    async fn compute_max_folder_depth(pool: &SqlitePool) -> KestrelResult<i64> {
        // Get all folders with their parent IDs
        let rows: Vec<(String, Option<String>)> = sqlx::query_as(
            "SELECT id, parent_id FROM folders"
        )
        .fetch_all(pool)
        .await
        .map_err(|e| KestrelError::Database(format!("Failed to query folder hierarchy: {e}")))?;

        if rows.is_empty() {
            return Ok(0);
        }

        // Build a map from id -> parent_id
        let parent_map: std::collections::HashMap<String, Option<String>> = rows
            .into_iter()
            .map(|(id, parent_id)| (id, parent_id))
            .collect();

        // Compute depth for each folder
        let mut max_depth: i64 = 0;
        let mut depth_cache: std::collections::HashMap<String, i64> = std::collections::HashMap::new();

        for id in parent_map.keys() {
            let depth = Self::folder_depth(id, &parent_map, &mut depth_cache);
            max_depth = max_depth.max(depth);
        }

        Ok(max_depth)
    }

    /// Recursively computes the depth of a folder in the hierarchy.
    ///
    /// Uses memoization via `depth_cache` to avoid redundant
    /// computation. Cycles are detected and capped at depth 100.
    fn folder_depth(
        id: &str,
        parent_map: &std::collections::HashMap<String, Option<String>>,
        cache: &mut std::collections::HashMap<String, i64>,
    ) -> i64 {
        if let Some(&depth) = cache.get(id) {
            return depth;
        }

        let depth = match parent_map.get(id) {
            Some(Some(parent_id)) => {
                // Recursively compute parent depth
                let parent_depth = Self::folder_depth(parent_id, parent_map, cache);
                parent_depth + 1
            }
            _ => 1, // Root level folder
        };

        cache.insert(id.to_string(), depth);
        depth
    }

    /// Counts total secure notes.
    async fn count_notes(pool: &SqlitePool) -> KestrelResult<i64> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM secure_notes")
            .fetch_one(pool)
            .await
            .map_err(|e| KestrelError::Database(format!("Failed to count notes: {e}")))?;
        Ok(row.0)
    }

    /// Counts total file attachments.
    async fn count_files(pool: &SqlitePool) -> KestrelResult<i64> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM file_entries")
            .fetch_one(pool)
            .await
            .map_err(|e| KestrelError::Database(format!("Failed to count files: {e}")))?;
        Ok(row.0)
    }

    /// Counts total audit events.
    async fn count_audit_events(pool: &SqlitePool) -> KestrelResult<i64> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_events")
            .fetch_one(pool)
            .await
            .map_err(|e| KestrelError::Database(format!("Failed to count audit events: {e}")))?;
        Ok(row.0)
    }

    /// Counts audit events in the last 24 hours.
    async fn count_audit_events_last_24h(pool: &SqlitePool) -> KestrelResult<i64> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM audit_events WHERE timestamp >= datetime('now', '-1 day')"
        )
        .fetch_one(pool)
        .await
        .map_err(|e| KestrelError::Database(format!("Failed to count recent audit events: {e}")))?;
        Ok(row.0)
    }

    /// Counts password reveal events in the last 24 hours.
    async fn count_password_reveals_last_24h(pool: &SqlitePool) -> KestrelResult<i64> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM audit_events \
             WHERE action = 'PasswordRevealed' \
             AND timestamp >= datetime('now', '-1 day')"
        )
        .fetch_one(pool)
        .await
        .map_err(|e| {
            KestrelError::Database(format!("Failed to count recent password reveals: {e}"))
        })?;
        Ok(row.0)
    }

    /// Counts entries modified in the last 7 days.
    async fn count_entries_modified_last_7d(pool: &SqlitePool) -> KestrelResult<i64> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM vault_entries WHERE updated_at >= datetime('now', '-7 days')"
        )
        .fetch_one(pool)
        .await
        .map_err(|e| KestrelError::Database(format!("Failed to count recent modifications: {e}")))?;
        Ok(row.0)
    }

    /// Counts entries that have never been accessed.
    ///
    /// An entry is considered "never accessed" if its accessed_at
    /// timestamp equals its created_at timestamp (i.e., it was
    /// created but never viewed or used).
    async fn count_entries_never_accessed(pool: &SqlitePool) -> KestrelResult<i64> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM vault_entries WHERE accessed_at = created_at"
        )
        .fetch_one(pool)
        .await
        .map_err(|e| {
            KestrelError::Database(format!("Failed to count never-accessed entries: {e}"))
        })?;
        Ok(row.0)
    }

    /// Gets the current schema version.
    async fn get_schema_version(pool: &SqlitePool) -> KestrelResult<u32> {
        let result: Option<(u32,)> = sqlx::query_as(
            "SELECT MAX(version) FROM schema_version"
        )
        .fetch_optional(pool)
        .await
        .map_err(|e| KestrelError::Database(format!("Failed to get schema version: {e}")))?;

        Ok(result.map(|(v,)| v).unwrap_or(0))
    }

    /// Checks if KDF parameters need upgrading.
    async fn check_kdf_upgrade(pool: &SqlitePool) -> KestrelResult<bool> {
        crate::db::vault_meta_repo::VaultMetaRepo::needs_kdf_upgrade(pool).await
    }

    /// Returns a summary string for quick display.
    pub fn summary(&self) -> String {
        format!(
            "Entries: {} ({} TOTP) | Folders: {} (depth {}) | Notes: {} | Files: {} | Events: {} | Schema: v{}{}",
            self.total_entries,
            self.entries_with_totp,
            self.total_folders,
            self.max_folder_depth,
            self.total_notes,
            self.total_files,
            self.total_audit_events,
            self.schema_version,
            if self.kdf_needs_upgrade { " [KDF UPGRADE NEEDED]" } else { "" }
        )
    }
}

/// Statistics for a single folder's contents.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FolderStats {
    /// The folder ID.
    pub folder_id: String,
    /// Number of entries in this folder.
    pub entry_count: i64,
    /// Number of secure notes in this folder.
    pub note_count: i64,
    /// Number of file attachments in this folder.
    pub file_count: i64,
    /// Number of child folders.
    pub child_folder_count: i64,
}

impl FolderStats {
    /// Gathers statistics for a specific folder.
    pub async fn gather(pool: &SqlitePool, folder_id: &str) -> KestrelResult<Self> {
        let entry_count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM vault_entries WHERE folder_id = ?1"
        )
        .bind(folder_id)
        .fetch_one(pool)
        .await
        .map_err(|e| KestrelError::Database(format!("Failed to count folder entries: {e}")))?;

        let note_count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM secure_notes WHERE folder_id = ?1"
        )
        .bind(folder_id)
        .fetch_one(pool)
        .await
        .map_err(|e| KestrelError::Database(format!("Failed to count folder notes: {e}")))?;

        let file_count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM file_entries WHERE folder_id = ?1"
        )
        .bind(folder_id)
        .fetch_one(pool)
        .await
        .map_err(|e| KestrelError::Database(format!("Failed to count folder files: {e}")))?;

        let child_folder_count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM folders WHERE parent_id = ?1"
        )
        .bind(folder_id)
        .fetch_one(pool)
        .await
        .map_err(|e| KestrelError::Database(format!("Failed to count child folders: {e}")))?;

        Ok(FolderStats {
            folder_id: folder_id.to_string(),
            entry_count: entry_count.0,
            note_count: note_count.0,
            file_count: file_count.0,
            child_folder_count: child_folder_count.0,
        })
    }

    /// Returns the total number of items in this folder.
    pub fn total_items(&self) -> i64 {
        self.entry_count + self.note_count + self.file_count
    }
}

/// Audit event statistics by category.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditStats {
    /// Category name.
    pub category: String,
    /// Number of events in this category.
    pub count: i64,
    /// Most recent event timestamp in this category.
    pub last_event: Option<String>,
}

impl AuditStats {
    /// Gathers audit event statistics grouped by category.
    pub async fn gather(pool: &SqlitePool) -> KestrelResult<Vec<Self>> {
        let rows: Vec<(String, i64, Option<String>)> = sqlx::query_as(
            "SELECT category, COUNT(*) as count, MAX(timestamp) as last_event \
             FROM audit_events GROUP BY category ORDER BY count DESC"
        )
        .fetch_all(pool)
        .await
        .map_err(|e| KestrelError::Database(format!("Failed to gather audit stats: {e}")))?;

        Ok(rows
            .into_iter()
            .map(|(category, count, last_event)| AuditStats {
                category,
                count,
                last_event,
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_stats_default_values() {
        let stats = VaultStats {
            total_entries: 0,
            entries_with_totp: 0,
            root_entries: 0,
            total_folders: 0,
            root_folders: 0,
            max_folder_depth: 0,
            total_notes: 0,
            total_files: 0,
            total_audit_events: 0,
            audit_events_last_24h: 0,
            password_reveals_last_24h: 0,
            entries_modified_last_7d: 0,
            entries_never_accessed: 0,
            schema_version: 8,
            kdf_needs_upgrade: false,
        };
        assert_eq!(stats.total_entries, 0);
        assert_eq!(stats.schema_version, 8);
        assert!(!stats.kdf_needs_upgrade);
    }

    #[test]
    fn vault_stats_summary_format() {
        let stats = VaultStats {
            total_entries: 42,
            entries_with_totp: 5,
            root_entries: 10,
            total_folders: 8,
            root_folders: 3,
            max_folder_depth: 4,
            total_notes: 15,
            total_files: 7,
            total_audit_events: 100,
            audit_events_last_24h: 12,
            password_reveals_last_24h: 3,
            entries_modified_last_7d: 8,
            entries_never_accessed: 5,
            schema_version: 8,
            kdf_needs_upgrade: false,
        };
        let summary = stats.summary();
        assert!(summary.contains("Entries: 42"));
        assert!(summary.contains("5 TOTP"));
        assert!(summary.contains("Folders: 8"));
        assert!(summary.contains("Schema: v8"));
        assert!(!summary.contains("KDF UPGRADE"));
    }

    #[test]
    fn vault_stats_summary_with_kdf_upgrade() {
        let stats = VaultStats {
            total_entries: 10,
            entries_with_totp: 0,
            root_entries: 10,
            total_folders: 0,
            root_folders: 0,
            max_folder_depth: 0,
            total_notes: 0,
            total_files: 0,
            total_audit_events: 0,
            audit_events_last_24h: 0,
            password_reveals_last_24h: 0,
            entries_modified_last_7d: 0,
            entries_never_accessed: 0,
            schema_version: 8,
            kdf_needs_upgrade: true,
        };
        let summary = stats.summary();
        assert!(summary.contains("KDF UPGRADE NEEDED"));
    }

    #[test]
    fn folder_stats_total_items() {
        let stats = FolderStats {
            folder_id: "test-id".to_string(),
            entry_count: 5,
            note_count: 3,
            file_count: 2,
            child_folder_count: 1,
        };
        assert_eq!(stats.total_items(), 10);
    }

    #[test]
    fn audit_stats_serializes() {
        let stats = AuditStats {
            category: "Auth".to_string(),
            count: 42,
            last_event: Some("2025-01-01T00:00:00Z".to_string()),
        };
        let json = serde_json::to_string(&stats).unwrap();
        assert!(json.contains("Auth"));
        assert!(json.contains("42"));
    }

    #[test]
    fn folder_depth_computation() {
        let mut parent_map: std::collections::HashMap<String, Option<String>> =
            std::collections::HashMap::new();
        // Root folder
        parent_map.insert("root".to_string(), None);
        // Child of root
        parent_map.insert("child1".to_string(), Some("root".to_string()));
        // Grandchild
        parent_map.insert("grandchild".to_string(), Some("child1".to_string()));
        // Another root
        parent_map.insert("root2".to_string(), None);

        let mut cache: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
        assert_eq!(VaultStats::folder_depth("root", &parent_map, &mut cache), 1);
        assert_eq!(VaultStats::folder_depth("child1", &parent_map, &mut cache), 2);
        assert_eq!(
            VaultStats::folder_depth("grandchild", &parent_map, &mut cache),
            3
        );
        assert_eq!(VaultStats::folder_depth("root2", &parent_map, &mut cache), 1);
    }
}
