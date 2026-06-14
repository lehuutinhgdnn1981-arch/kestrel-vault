-- ============================================================================
-- KESTREL Vault - Vault Entry Indexes Migration (003)
-- ============================================================================
--
-- This migration creates dedicated indexes for vault data tables.
-- Although the initial schema migration (001) already included these indexes,
-- this migration exists as a standalone file to:
--
--   1. Serve as documentation for the index strategy on vault tables
--   2. Allow independent re-creation if indexes were dropped for maintenance
--   3. Provide a template for adding future vault-specific indexes
--
-- IMPORTANT: If running against a database that already has these indexes
-- from migration 001, the IF NOT EXISTS clauses ensure idempotency.
--
-- QUERY PATTERNS SUPPORTED:
--
--   V1: "List all entries in folder X" → WHERE folder_id = ?
--       → idx_vault_entries_folder
--
--   V2: "Show entries sorted by creation date" → ORDER BY created_at
--       → idx_vault_entries_created
--
--   V3: "Show recently modified entries" → ORDER BY updated_at DESC
--       → idx_vault_entries_updated
--
--   V4: "Build folder tree" → WHERE parent_id = ?
--       → idx_folders_parent
--
--   V5: "List all notes in folder X" → WHERE folder_id = ?
--       → idx_secure_notes_folder
--
--   V6: "List all files in folder X" → WHERE folder_id = ?
--       → idx_file_entries_folder
--
-- INDEX DESIGN NOTES:
--
--   FOLDER-BASED INDEXES:
--   The folder_id indexes on vault_entries, secure_notes, and file_entries
--   support the primary navigation pattern: the user selects a folder in
--   the sidebar, and the UI loads all items in that folder. Without these
--   indexes, each folder view would require a full table scan, which
--   becomes unacceptable as the vault grows (thousands of entries).
--
--   FOLDER PARENT INDEX:
--   The idx_folders_parent index supports the tree-building algorithm
--   (vault/folder.rs build_folder_tree). When constructing the folder
--   hierarchy, we need to find all children of a given folder. Without
--   this index, building the tree is O(n^2) in the number of folders.
--
--   TIMESTAMP INDEXES:
--   The created_at and updated_at indexes on vault_entries support:
--   - Chronological entry listing
--   - "Recently added" and "Recently modified" smart folders
--   - Sorted entry display in the UI
--   These indexes are not needed on secure_notes or file_entries because
--   those tables typically contain far fewer rows and the UI sorts them
--   client-side after decryption.
--
--   NO INDEX ON accessed_at:
--   We deliberately do not index accessed_at because:
--   - It is updated on every read operation, causing index maintenance overhead
--   - It is rarely used as a query filter (not worth the write amplification)
--   - If "most recently accessed" sorting is needed, it can be handled
--     client-side from the decrypted dataset
--
-- FUTURE INDEX CONSIDERATIONS:
--
--   - idx_vault_entries_accessed: If "recently used" becomes a primary
--     navigation pattern, add an index on accessed_at. Consider the write
--     amplification tradeoff carefully.
--   - Encrypted search index: Full-text search on encrypted fields is not
--     possible with standard indexes. A future migration may add a blind
--     index (HMAC-based deterministic hash) for title search, e.g.:
--       CREATE INDEX idx_vault_entries_title_hash
--         ON vault_entries(title_search_hash);
--     where title_search_hash = HMAC-SHA256(key, lowercase(title)).
--   - Composite indexes: If the UI frequently filters by (folder_id, updated_at),
--     a composite index would be more efficient than two separate indexes.
--
-- ============================================================================

-- Index for listing vault entries by folder.
-- Supports V1: "List all entries in folder X"
-- This is the most frequently used index for vault navigation.
-- Foreign key ON DELETE SET NULL means entries are moved to "no folder"
-- when their parent folder is deleted — the index still applies.
CREATE INDEX IF NOT EXISTS idx_vault_entries_folder
    ON vault_entries(folder_id);

-- Index for chronological entry listing and "recently added" sorting.
-- Supports V2: "Show entries sorted by creation date"
CREATE INDEX IF NOT EXISTS idx_vault_entries_created
    ON vault_entries(created_at);

-- Index for "recently modified" smart folder and entry listing.
-- Supports V3: "Show recently modified entries"
-- This index sees heavy use in the UI's default sort order.
CREATE INDEX IF NOT EXISTS idx_vault_entries_updated
    ON vault_entries(updated_at);

-- Index for folder tree traversal (finding children of a folder).
-- Supports V4: "Build folder tree"
-- Essential for the recursive tree-building algorithm in vault/folder.rs.
-- Without this index, each level of the tree requires a full table scan.
CREATE INDEX IF NOT EXISTS idx_folders_parent
    ON folders(parent_id);

-- Index for listing secure notes by folder.
-- Supports V5: "List all notes in folder X"
CREATE INDEX IF NOT EXISTS idx_secure_notes_folder
    ON secure_notes(folder_id);

-- Index for listing file entries by folder.
-- Supports V6: "List all files in folder X"
CREATE INDEX IF NOT EXISTS idx_file_entries_folder
    ON file_entries(folder_id);

-- Record this migration
INSERT INTO migration_history (version) VALUES (3);
