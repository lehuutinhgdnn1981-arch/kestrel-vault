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
pub mod folder_commands;
pub mod note_commands;
pub mod scanner_commands;
pub mod settings_commands;
pub mod types;
pub mod vault_commands;

/// Provides a simple async runtime for blocking on async operations
/// from synchronous Tauri command handlers.
///
/// Tauri command handlers are synchronous by default, but our service
/// layer (VaultServiceImpl) uses async database operations. This module
/// provides a way to block_on async calls from sync command handlers.
pub mod async_runtime {
    use tokio::runtime::Runtime;

    thread_local! {
        static RUNTIME: Runtime = Runtime::new().expect("Failed to create Tokio runtime");
    }

    /// Blocks on an async future from a synchronous context.
    ///
    /// Uses a thread-local Tokio runtime to avoid the "Cannot start
    /// a runtime from within a runtime" panic that would occur if
    /// we tried to use tokio::runtime::Handle::block_on from within
    /// a Tauri async command.
    pub fn block_on<F: std::future::Future>(future: F) -> F::Output {
        RUNTIME.with(|rt| rt.block_on(future))
    }
}

// Re-export command types for convenience
pub use types::{
    AppSettingsResponse, AuditEventResponse, AuditPageResponse, ChangePasswordRequest,
    CommandError, CommandResult, CreateFolderRequest, FileEntryResponse, FolderResponse,
    InitializeVaultRequest, PasswordRevealResponse, PasswordStrengthResponse,
    SecureNoteRevealResponse, SecureNoteResponse, SecurityBreakdown, SecurityScoreResponse,
    UnlockVaultRequest, VaultEntryResponse, VaultInitResponse, VaultLockResponse,
    VaultStatusResponse, VulnerabilityItemResponse,
};
