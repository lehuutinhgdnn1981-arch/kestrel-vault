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

use tauri::Manager;

/// Initializes and runs the Tauri application.
///
/// This function sets up the Tauri builder with all required plugins,
/// command handlers, and the application setup hook. It is the single
/// entry point called by the binary `main.rs`.
pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
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

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::vault_commands::create_entry,
            commands::vault_commands::get_entry,
            commands::vault_commands::update_entry,
            commands::vault_commands::delete_entry,
            commands::vault_commands::list_entries,
            commands::vault_commands::search_entries,
            commands::audit_commands::get_audit_events,
            commands::audit_commands::query_audit_log,
            commands::audit_commands::export_audit_log,
            commands::scanner_commands::scan_password_strength,
            commands::scanner_commands::check_breach_status,
            commands::scanner_commands::run_vulnerability_scan,
            commands::crypto_commands::derive_key,
            commands::crypto_commands::encrypt_data,
            commands::crypto_commands::decrypt_data,
        ])
        .run(tauri::generate_context!())?;

    Ok(())
}
