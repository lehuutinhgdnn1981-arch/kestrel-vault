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
//! # Submodules
//!
//! - `connection`: Database connection pool management
//! - `repository`: Generic repository pattern for CRUD operations
//! - `migrations`: Database schema migration management

pub mod connection;
pub mod migrations;
pub mod repository;

// Re-export key types
pub use connection::DbConnection;
pub use repository::Repository;
