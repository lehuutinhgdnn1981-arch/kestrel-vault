//! Database module for KESTREL Vault.
//!
//! This module manages the encrypted SQLite database using SQLCipher.
//! All data at rest is encrypted with the user's master key.
//!
//! # SQLCipher Requirements
//!
//! The database MUST be encrypted using SQLCipher with:
//! - AES-256-CBC for page encryption (SQLCipher default, not our application-level cipher)
//! - HMAC-SHA512 for integrity verification
//! - PBKDF2-HMAC-SHA512 for key derivation within SQLCipher
//!
//! Note: SQLCipher uses AES-256-CBC internally for database page encryption.
//! This is acceptable because SQLCipher implements proper HMAC authentication
//! on each page. Our application-level encryption uses AES-256-GCM.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                      DatabaseManager                         │
//! │  (create/open/close/validate/rekey/backup)                   │
//! └────────────────────┬─────────────────────────────────────────┘
//!                      │
//!          ┌───────────┴───────────┐
//!          │                       │
//!    ┌─────┴─────┐          ┌─────┴──────┐
//!    │DbConnection│          │ Migrations  │
//!    │ (pool mgmt)│          │ (schema)    │
//!    └─────┬─────┘          └────────────┘
//!          │
//!    ┌─────┴─────────────────────────────────┐
//!    │              Repository Layer          │
//!    │  VaultMetaRepo  │  VaultEntryRepo     │
//!    │  FolderRepo     │  SecureNoteRepo     │
//!    │  FileEntryRepo  │  AuditEventRepo     │
//!    └───────────────────────────────────────┘
//!          │
//!    ┌─────┴─────────────────────────────────┐
//!    │             Service Layer              │
//!    │  Stats  │  Backup  │  Repository trait │
//!    └────────────────────────────────────────┘
//! ```
//!
//! # Submodules
//!
//! - `connection`: Database connection pool management
//! - `manager`: Database lifecycle management (create/open/close)
//! - `repository`: Generic repository pattern for CRUD operations
//! - `migrations`: Database schema migration management
//! - `stats`: Database statistics and metrics
//! - `backup`: Database backup and export operations
//! - `vault_meta_repo`: Vault metadata (KDF params, wrapped DEK)
//! - `vault_entry_repo`: Password entries
//! - `folder_repo`: Folder hierarchy
//! - `secure_note_repo`: Secure notes
//! - `file_entry_repo`: File attachment metadata
//! - `audit_event_repo`: Append-only audit log

pub mod audit_event_repo;
pub mod backup;
pub mod connection;
pub mod file_entry_repo;
pub mod folder_repo;
pub mod manager;
pub mod migrations;
pub mod repository;
pub mod secure_note_repo;
pub mod stats;
pub mod vault_entry_repo;
pub mod vault_meta_repo;

// Re-export key types
pub use connection::DbConnection;
pub use manager::{
    DatabaseConfig, DatabaseManager, DatabaseSizeInfo, SharedDatabaseManager,
    ValidationReport, VaultDbState,
};
pub use repository::{Repository, Pagination};
pub use backup::{DbBackup, BackupInfo, BackupResult, EncryptedExport};
pub use stats::{VaultStats, FolderStats, AuditStats};
pub use audit_event_repo::{AuditEventRepo, AuditEventRow, CreateAuditEventRequest};
pub use file_entry_repo::{FileEntryRepo, FileEntryRow, CreateFileEntryRequest};
pub use folder_repo::{FolderRepo, FolderRow, CreateFolderRequest as CreateFolderRepoRequest};
pub use secure_note_repo::{SecureNoteRepo, SecureNoteRow, CreateSecureNoteRequest};
pub use vault_entry_repo::{VaultEntryRepo, VaultEntryRow, CreateVaultEntryRequest, UpdateVaultEntryRequest};
pub use vault_meta_repo::{VaultMeta, VaultMetaRepo};
