-- ============================================================================
-- KESTREL Vault - Initial Database Schema Migration (001)
-- ============================================================================
--
-- Database: SQLCipher-encrypted SQLite
-- Encryption: AES-256-CBC (page-level) via SQLCipher + AES-256-GCM (field-level)
--
-- DUAL ENCRYPTION MODEL:
--   Layer 1 (at rest): SQLCipher encrypts the entire database file at the page
--     level. This protects against offline database theft. The SQLCipher key
--     is derived from the user's master password via Argon2id.
--   Layer 2 (field-level): Sensitive fields are additionally encrypted with
--     AES-256-GCM before being stored as BLOBs. This provides defense-in-depth:
--     even if the SQLCipher key is compromised, individual fields remain
--     protected. Each field-level encryption uses a unique nonce stored
--     alongside the ciphertext.
--
-- NONCE STRATEGY:
--   Every AES-256-GCM encryption generates a fresh 96-bit random nonce via
--   OsRng. The nonce is stored in a dedicated `nonce` column on each table
--   that contains encrypted fields. A single nonce per row is used because
--   all encrypted fields within a row are encrypted together as a single
--   serialized payload, or alternatively each field has its own nonce — see
--   per-table comments for specifics. Nonce reuse with the same key is
--   catastrophic for GCM; the random 96-bit nonce provides 2^32 birthday
--   bound safety (~4 billion encryptions per key before collision risk).
--
-- KEY DERIVATION PARAMETERS (stored in vault_meta):
--   Algorithm: Argon2id (RFC 9106)
--   Memory: 262144 KiB (256 MB) — OWASP recommendation
--   Iterations: 3 — OWASP recommendation
--   Parallelism: 4 — OWASP recommendation
--   Salt: 128-bit cryptographically random
--   Output: 256-bit key
--
-- FOREIGN KEYS:
--   SQLite foreign keys are enabled via PRAGMA foreign_keys = ON in the
--   connection module (db/connection.rs). All FK constraints are declared
--   here and enforced by SQLite at runtime.
--
-- ============================================================================

-- ============================================================================
-- vault_meta: Stores vault-level metadata and key derivation parameters.
-- ============================================================================
-- There is exactly one row in this table after vault initialization.
-- The salt is stored in hexadecimal encoding for SQLCipher PRAGMA key
-- formatting convenience. The KDF parameters are stored so that future
-- parameter changes can be made while still deriving keys from older
-- parameter sets during migration.
-- ============================================================================
CREATE TABLE IF NOT EXISTS vault_meta (
    id              INTEGER PRIMARY KEY CHECK (id = 1),  -- Singleton row
    salt            TEXT    NOT NULL,                      -- Hex-encoded 128-bit Argon2id salt
    iterations      INTEGER NOT NULL DEFAULT 3,           -- Argon2id time cost (OWASP: 3)
    memory_cost     INTEGER NOT NULL DEFAULT 262144,      -- Argon2id memory in KiB (OWASP: 256 MB)
    parallelism     INTEGER NOT NULL DEFAULT 4,           -- Argon2id parallelism (OWASP: 4)
    test_envelope   BLOB,                                 -- Encrypted test envelope for password verification
    hint            TEXT,                                 -- Optional password hint (NOT secure)
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),  -- ISO8601 UTC
    updated_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))   -- ISO8601 UTC
);

-- ============================================================================
-- vault_entries: Password vault entries (login credentials).
-- ============================================================================
-- ENCRYPTION APPROACH:
--   All user-visible sensitive fields are encrypted with AES-256-GCM at the
--   field level. The `title`, `username`, `url`, `notes`, `totp_secret`, and
--   `tags` columns store AES-256-GCM ciphertext as BLOBs. The
--   `encrypted_password` column stores the AES-256-GCM ciphertext of the
--   password. Each row has a single `nonce` BLOB (12 bytes / 96 bits) that
--   was generated randomly at encryption time.
--
--   DESIGN NOTE: A per-row nonce is used because all encrypted fields within
--   a vault entry are encrypted in a single AES-256-GCM operation. The
--   plaintext is serialized as a structured format (e.g., JSON or bincode)
--   containing all sensitive fields, then encrypted as one ciphertext blob.
--   Alternatively, if per-field encryption is preferred in a future migration,
--   each field would receive its own nonce column (e.g., title_nonce,
--   username_nonce, etc.). The current schema uses the single-nonce approach
--   for simplicity and to reduce nonce management complexity.
--
--   The `id` column is a UUID stored as TEXT (36 chars). UUIDs are generated
--   client-side (v4 random) to avoid sequential ID leakage.
-- ============================================================================
CREATE TABLE IF NOT EXISTS vault_entries (
    id                  TEXT    PRIMARY KEY,              -- UUID v4, generated client-side
    title               BLOB    NOT NULL,                 -- AES-256-GCM ciphertext of entry title
    username            BLOB    NOT NULL,                 -- AES-256-GCM ciphertext of username/email
    encrypted_password  BLOB    NOT NULL,                 -- AES-256-GCM ciphertext of password
    url                 BLOB,                             -- AES-256-GCM ciphertext of URL (nullable)
    notes               BLOB,                             -- AES-256-GCM ciphertext of notes (nullable)
    totp_secret         BLOB,                             -- AES-256-GCM ciphertext of TOTP secret (nullable)
    folder_id           TEXT,                             -- UUID reference to folders.id (nullable)
    tags                BLOB,                             -- AES-256-GCM ciphertext of tag list (nullable)
    nonce               BLOB    NOT NULL,                 -- 96-bit AES-GCM nonce for this entry
    created_at          TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at          TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    accessed_at         TEXT,                             -- Last access timestamp, updated on read
    FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE SET NULL
);

-- ============================================================================
-- folders: Hierarchical folder structure for organizing vault entries.
-- ============================================================================
-- ENCRYPTION APPROACH:
--   Folder names are encrypted with AES-256-GCM. The `name` column stores
--   the ciphertext BLOB and the `nonce` column stores the 96-bit nonce.
--   Folder names are encrypted to prevent an attacker who gains access to
--   the raw database from learning organizational structure (e.g., "Banking",
--   "Work", "Health" could reveal sensitive information about the user).
--
--   The `parent_id` column enables a tree structure. Root-level folders
--   have parent_id = NULL. Circular references must be prevented at the
--   application layer (see vault/folder.rs move_folder).
-- ============================================================================
CREATE TABLE IF NOT EXISTS folders (
    id          TEXT    PRIMARY KEY,                      -- UUID v4
    name        BLOB    NOT NULL,                         -- AES-256-GCM ciphertext of folder name
    parent_id   TEXT,                                    -- UUID reference to folders.id (nullable, root if NULL)
    nonce       BLOB    NOT NULL,                         -- 96-bit AES-GCM nonce for this folder
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    FOREIGN KEY (parent_id) REFERENCES folders(id) ON DELETE CASCADE
);

-- ============================================================================
-- secure_notes: Standalone encrypted notes (not tied to login credentials).
-- ============================================================================
-- ENCRYPTION APPROACH:
--   Both `title` and `content` are encrypted with AES-256-GCM. The `nonce`
--   column stores the 96-bit nonce used for the encryption operation.
--   As with vault_entries, a single nonce per row is used because all
--   encrypted fields are encrypted together in one AES-256-GCM call.
-- ============================================================================
CREATE TABLE IF NOT EXISTS secure_notes (
    id          TEXT    PRIMARY KEY,                      -- UUID v4
    title       BLOB    NOT NULL,                         -- AES-256-GCM ciphertext of note title
    content     BLOB    NOT NULL,                         -- AES-256-GCM ciphertext of note content
    folder_id   TEXT,                                    -- UUID reference to folders.id (nullable)
    tags        BLOB,                                    -- AES-256-GCM ciphertext of tag list (nullable)
    nonce       BLOB    NOT NULL,                         -- 96-bit AES-GCM nonce for this note
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE SET NULL
);

-- ============================================================================
-- file_entries: Encrypted file attachments and secure file storage.
-- ============================================================================
-- ENCRYPTION APPROACH:
--   `filename` and `mime_type` are encrypted with AES-256-GCM (stored as
--   BLOB ciphertext). `encrypted_path` stores the encrypted filesystem path
--   to the actual file data (which is stored encrypted on disk). `file_size`
--   is encrypted as an integer — the BLOB contains the AES-256-GCM
--   ciphertext of the serialized integer value. This prevents an attacker
--   from inferring file types or contents based on size patterns.
--   The actual file content is stored separately on disk, encrypted with
--   AES-256-GCM using the same master key (or a file-specific key derived
--   from the master key via HKDF).
-- ============================================================================
CREATE TABLE IF NOT EXISTS file_entries (
    id              TEXT    PRIMARY KEY,                  -- UUID v4
    filename        BLOB    NOT NULL,                     -- AES-256-GCM ciphertext of original filename
    encrypted_path  BLOB    NOT NULL,                     -- AES-256-GCM ciphertext of on-disk file path
    file_size       BLOB    NOT NULL,                     -- AES-256-GCM ciphertext of file size in bytes
    mime_type       BLOB,                                 -- AES-256-GCM ciphertext of MIME type (nullable)
    folder_id       TEXT,                                 -- UUID reference to folders.id (nullable)
    nonce           BLOB    NOT NULL,                     -- 96-bit AES-GCM nonce for this file entry
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE SET NULL
);

-- ============================================================================
-- audit_events: Immutable audit trail for security-relevant operations.
-- ============================================================================
-- ENCRYPTION APPROACH:
--   Audit events are NOT encrypted at the field level. They are protected
--   only by SQLCipher (whole-database encryption). This is intentional:
--   audit events must be queryable by category, action, and timestamp for
--   the security center UI, and encrypting these fields would require
--   decrypting the entire audit log to perform any query. The audit log
--   NEVER contains passwords, keys, or decrypted vault data (enforced at
--   the application layer in audit/event.rs).
--
--   `metadata_json` is a free-form JSON text field for event-specific data.
--   It must not contain secrets. Category and action are stored as TEXT
--   for queryability (matching the Display impl of EventCategory and
--   ActionType enums).
-- ============================================================================
CREATE TABLE IF NOT EXISTS audit_events (
    id              TEXT    PRIMARY KEY,                  -- UUID v4
    category        TEXT    NOT NULL,                     -- Event category: auth, vault, file, system, security
    action          TEXT    NOT NULL,                     -- Action type: create, read, update, delete, login, etc.
    subject         TEXT    NOT NULL,                     -- Who/what performed the action (session ID, not password)
    metadata_json   TEXT,                                 -- Optional JSON metadata (NEVER contains secrets)
    timestamp       TEXT    NOT NULL                      -- ISO8601 UTC timestamp with millisecond precision
);

-- ============================================================================
-- security_settings: Key-value store for security configuration.
-- ============================================================================
-- ENCRYPTION APPROACH:
--   `key` is stored as plaintext (it is a configuration key name, not
--   sensitive data). `value` is stored as plaintext because security settings
--   need to be readable before the vault is unlocked (e.g., lockout count,
--   auto-lock timeout). Settings that require encryption should use a
--   separate mechanism. Values that are truly sensitive (e.g., biometric
--   key references) should be stored in platform-specific secure storage
--   (Keychain/Keystore), not in this table.
-- ============================================================================
CREATE TABLE IF NOT EXISTS security_settings (
    key         TEXT    PRIMARY KEY,                      -- Setting key name (e.g., "auto_lock_minutes")
    value       TEXT    NOT NULL,                         -- Setting value as string
    updated_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- ============================================================================
-- breach_hashes: Local breach database for offline password breach checking.
-- ============================================================================
-- ENCRYPTION APPROACH:
--   This table is NOT field-level encrypted. It stores SHA-256 hash prefixes
--   (following the HIBP k-anonymity model) and occurrence counts. These are
--   not user secrets — they are public breach data. SQLCipher whole-database
--   encryption is sufficient.
--
--   The `prefix` column stores the first 5 characters (20 bits) of the
--   SHA-256 hash in uppercase hex, following the HIBP API convention. The
--   `count` column stores how many times that hash suffix appeared in
--   breaches. The actual full hash is never stored — only the prefix for
--   k-anonymity lookup.
-- ============================================================================
CREATE TABLE IF NOT EXISTS breach_hashes (
    prefix      TEXT    NOT NULL,                         -- First 5 chars of SHA-256 hex (20-bit prefix)
    count       INTEGER NOT NULL DEFAULT 0,              -- Number of occurrences in breach datasets
    PRIMARY KEY (prefix)
);

-- ============================================================================
-- migration_history: Tracks applied migrations for schema versioning.
-- ============================================================================
-- This table is separate from the schema_version table used by the Rust
-- migration runner (db/migrations.rs) to allow SQL-file-based migration
-- tracking alongside the programmatic migration system. Each migration
-- file that is applied records its version number and timestamp here.
-- ============================================================================
CREATE TABLE IF NOT EXISTS migration_history (
    version     INTEGER PRIMARY KEY,                      -- Migration version number (e.g., 1, 2, 3)
    applied_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))  -- ISO8601 UTC
);

-- ============================================================================
-- INDEXES: Performance-critical indexes for common query patterns.
-- ============================================================================

-- vault_entries: Primary lookup patterns
--   - By folder (folder view listing)
--   - By creation time (chronological sorting)
--   - By update time (recently modified)
CREATE INDEX IF NOT EXISTS idx_vault_entries_folder  ON vault_entries(folder_id);
CREATE INDEX IF NOT EXISTS idx_vault_entries_created ON vault_entries(created_at);
CREATE INDEX IF NOT EXISTS idx_vault_entries_updated ON vault_entries(updated_at);

-- folders: Parent-child traversal for tree building
CREATE INDEX IF NOT EXISTS idx_folders_parent ON folders(parent_id);

-- secure_notes: Folder-based listing
CREATE INDEX IF NOT EXISTS idx_secure_notes_folder ON secure_notes(folder_id);

-- file_entries: Folder-based listing
CREATE INDEX IF NOT EXISTS idx_file_entries_folder ON file_entries(folder_id);

-- audit_events: Category and time-range queries for security center
--   - Filter by category (auth, vault, security, etc.)
--   - Filter by timestamp (recent events, date ranges)
--   - Composite: category + timestamp (most common query pattern)
--   - Filter by action type (e.g., all login events)
CREATE INDEX IF NOT EXISTS idx_audit_events_category             ON audit_events(category);
CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp            ON audit_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_events_category_timestamp   ON audit_events(category, timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_events_action               ON audit_events(action);

-- Record this migration in the migration history
INSERT INTO migration_history (version) VALUES (1);
