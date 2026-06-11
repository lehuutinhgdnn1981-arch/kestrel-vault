//! Tauri command module for KESTREL Vault.
//!
//! Defines the IPC boundary between React (frontend) and Rust (backend).
//! All commands are thin wrappers — business logic lives in domain modules.
//!
//! # IPC Security Model
//!
//! - React NEVER calls invoke directly from components
//! - All calls go through `src/lib/tauri.ts` on the frontend
//! - React NEVER owns encryption keys
//! - React NEVER encrypts or decrypts data
//! - Passwords are ONLY returned via `vault_reveal_password`
//!
//! # Command Categories
//!
//! - **auth**: Vault lifecycle (init, unlock, lock, change password)
//! - **vault**: CRUD for password entries
//! - **audit**: Query and export audit events
//! - **scanner**: Password strength, breach check, vulnerability scan
//! - **crypto**: Low-level crypto (RESTRICTED — prefer domain commands)
//! - **settings**: Application configuration

pub mod audit_commands;
pub mod auth_commands;
pub mod crypto_commands;
pub mod scanner_commands;
pub mod settings_commands;
pub mod types;
pub mod vault_commands;

// Re-export command types for convenience
pub use types::{
    AppSettingsResponse, AuditEventResponse, AuditPageResponse, ChangePasswordRequest,
    CommandError, CommandResult, CreateFolderRequest, FileEntryResponse, FolderResponse,
    InitializeVaultRequest, PasswordRevealResponse, PasswordStrengthResponse,
    SecureNoteRevealResponse, SecureNoteResponse, SecurityBreakdown, SecurityScoreResponse,
    UnlockVaultRequest, VaultEntryResponse, VaultInitResponse, VaultLockResponse,
    VaultStatusResponse, VulnerabilityItemResponse,
};
