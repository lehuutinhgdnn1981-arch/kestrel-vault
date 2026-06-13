//! Password vault module for KESTREL Vault.
//!
//! This module manages the storage, retrieval, and organization of
//! password vault entries. All sensitive fields (passwords, notes)
//! are stored as encrypted ciphertext — never as plaintext.
//!
//! # Architecture
//!
//! - **entry**: Vault entry types (structs for entries, create/update requests)
//! - **folder**: Folder organization and hierarchical structure
//! - **search**: Secure search that doesn't leak plaintext patterns
//! - **service**: Concrete implementation bridging crypto + database
//!
//! # Security
//!
//! - Passwords are encrypted with AES-256-GCM before storage
//! - Search operates on encrypted indices, never decrypted plaintext
//! - Folder names are encrypted to prevent structure leakage
//! - All vault operations are recorded in the audit log
//! - The DEK is used for field-level encryption (never the KEK)

pub mod entry;
pub mod folder;
pub mod search;
pub mod service;

use crate::error::KestrelError;
use crate::vault::entry::{CreateEntryRequest, UpdateEntryRequest, VaultEntry};

/// Service trait for vault operations.
///
/// This trait defines the interface for all vault operations,
/// allowing different implementations (e.g., SQLite-backed,
/// in-memory for testing).
#[allow(async_fn_in_trait)]
pub trait VaultService {
    /// Creates a new vault entry.
    async fn create_entry(&self, request: CreateEntryRequest) -> Result<VaultEntry, KestrelError>;

    /// Retrieves a vault entry by ID.
    async fn get_entry(&self, id: uuid::Uuid) -> Result<VaultEntry, KestrelError>;

    /// Updates an existing vault entry.
    async fn update_entry(
        &self,
        id: uuid::Uuid,
        request: UpdateEntryRequest,
    ) -> Result<VaultEntry, KestrelError>;

    /// Deletes a vault entry by ID.
    async fn delete_entry(&self, id: uuid::Uuid) -> Result<(), KestrelError>;

    /// Lists all vault entries in a folder.
    async fn list_entries(
        &self,
        folder_id: Option<uuid::Uuid>,
    ) -> Result<Vec<VaultEntry>, KestrelError>;

    /// Searches vault entries by criteria.
    async fn search_entries(&self, query: &str) -> Result<Vec<VaultEntry>, KestrelError>;
}

// Re-export the service implementation
pub use service::VaultServiceImpl;
