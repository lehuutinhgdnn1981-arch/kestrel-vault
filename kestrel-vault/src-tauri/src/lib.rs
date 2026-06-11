//! KESTREL Vault - Core Library
//!
//! KESTREL Vault is a local-first security platform providing password management,
//! threat scanning, and security auditing. Built with Tauri v2 and React, it
//! prioritizes local data storage, end-to-end encryption, and zero-knowledge
//! architecture.
//!
//! # Architecture
//!
//! - **crypto**: Cryptographic operations (AES-256-GCM, Argon2id, key management)
//! - **db**: SQLite database layer with SQLCipher encryption
//! - **vault**: Password vault entry management and organization
//! - **audit**: Security audit logging and event tracking
//! - **scanner**: Threat scanning, password strength analysis, breach detection
//! - **commands**: Tauri IPC command handlers
//! - **config**: Application configuration management
//! - **security**: Session management, rate limiting, and lockout policies

pub mod audit;
pub mod commands;
pub mod config;
pub mod crypto;
pub mod db;
pub mod error;
pub mod scanner;
pub mod security;
pub mod vault;

use commands::auth_commands::AppState;
use tauri::Manager;

/// Initializes and runs the Tauri application.
///
/// This function sets up the Tauri builder with all required plugins,
/// command handlers, and the application setup hook. It is the single
/// entry point called by the binary `main.rs`.
pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(AppState::default())
        .setup(|app| {
            // Initialize tracing subscriber for structured logging
            tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
                )
                .init();

            tracing::info!("KESTREL Vault starting up");

            // TODO: Initialize database connection pool
            // TODO: Load application configuration
            // TODO: Initialize audit logger
            // TODO: Set up auto-lock timer
            // TODO: Initialize VaultStateMachine in AppState

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // Auth commands
            commands::auth_commands::auth_initialize_vault,
            commands::auth_commands::auth_unlock,
            commands::auth_commands::auth_lock,
            commands::auth_commands::auth_get_session,
            commands::auth_commands::auth_is_vault_initialized,
            commands::auth_commands::auth_change_password,
            commands::auth_commands::auth_get_vault_status,
            commands::auth_commands::auth_auto_lock_check,
            // Vault commands
            commands::vault_commands::vault_create_entry,
            commands::vault_commands::vault_get_entry,
            commands::vault_commands::vault_update_entry,
            commands::vault_commands::vault_delete_entry,
            commands::vault_commands::vault_list_entries,
            commands::vault_commands::vault_search_entries,
            commands::vault_commands::vault_reveal_password,
            // Audit commands
            commands::audit_commands::audit_query_events,
            commands::audit_commands::audit_export_events,
            // Scanner commands
            commands::scanner_commands::scanner_password_strength,
            commands::scanner_commands::scanner_check_breach,
            commands::scanner_commands::scanner_run_full_scan,
            // Crypto commands (RESTRICTED)
            commands::crypto_commands::crypto_derive_key,
            commands::crypto_commands::crypto_encrypt_data,
            commands::crypto_commands::crypto_decrypt_data,
            // Settings commands
            commands::settings_commands::settings_get,
            commands::settings_commands::settings_update,
        ])
        .run(tauri::generate_context!())?;

    Ok(())
}
