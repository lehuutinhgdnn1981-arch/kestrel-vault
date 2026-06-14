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
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
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

            // Initialize database manager with default vault path
            {
                let state = app.state::<AppState>();
                let app_data_dir = app.path().app_data_dir()
                    .expect("Failed to resolve app data directory");
                let vault_path = app_data_dir.join("kestrel_vault.db");

                // Ensure app data directory exists
                if !app_data_dir.exists() {
                    std::fs::create_dir_all(&app_data_dir)?;
                }

                state.init_db_manager(&vault_path);
                state.set_app_data_dir(app_data_dir.clone());
                tracing::info!("Database manager initialized at: {}", vault_path.display());

                // Load application configuration from disk (or use defaults)
                {
                    let mut config_guard = state.config.write().unwrap_or_else(|e| {
                        tracing::error!("Config lock poisoned: {}", e);
                        std::process::exit(1);
                    });
                    match crate::config::AppConfig::load(&app_data_dir) {
                        Ok(loaded_config) => {
                            *config_guard = loaded_config;
                            tracing::info!("Application configuration loaded");
                        }
                        Err(e) => {
                            tracing::warn!("Failed to load config, using defaults: {}", e);
                            // config_guard already has defaults from AppState::default()
                        }
                    }
                }

                // Check if the vault database already exists from a previous session.
                // If it does, open it temporarily to load vault_meta, transition
                // the state machine to Locked, then close the DB.
                // The database will be reopened when the user unlocks.
                if vault_path.exists() {
                    tracing::info!("Existing vault database found — loading vault metadata");

                    // Open database temporarily to read vault_meta
                    let open_result = if let Some(manager) = state.get_db_manager() {
                        crate::commands::async_runtime::block_on(async {
                            manager.open_vault_plain().await
                        })
                    } else {
                        Err(crate::error::KestrelError::Database("No database manager".to_string()))
                    };

                    if let Ok(()) = open_result {
                        // Load vault_meta from the database
                        if let Some(pool) = state.get_db_pool() {
                            let meta_result = crate::commands::async_runtime::block_on(async {
                                crate::db::vault_meta_repo::VaultMetaRepo::get(&pool).await
                            });

                            if let Ok(Some(meta)) = meta_result {
                                // Restore vault metadata in memory
                                state.store_vault_meta_in_memory(
                                    meta.salt,
                                    meta.test_envelope,
                                    crate::crypto::keywrap::WrappedDek::from_bytes(meta.wrapped_dek),
                                    crate::crypto::kdf_params::KdfParams {
                                        version: meta.kdf_version,
                                        memory_cost_kib: meta.memory_cost,
                                        iterations: meta.iterations,
                                        parallelism: meta.parallelism,
                                        salt_len: 16,
                                        key_len: 32,
                                    },
                                );
                                tracing::info!("Vault metadata loaded from database");
                            }
                        }

                        // Close the database — it will be reopened on unlock
                        let _ = state.close_database();

                        // Transition state machine from Uninitialized → Locked
                        tracing::info!("Transitioning vault state to Locked");
                        let mut sm = state.vault_state_machine.write().unwrap_or_else(|e| {
                            tracing::error!("Vault state machine lock poisoned: {}", e);
                            std::process::exit(1);
                        });
                        use crate::security::vault_state::{VaultContext, VaultTransition};
                        let context = VaultContext::new();
                        match sm.transition(VaultTransition::Initialize, &context) {
                            Ok(result) => {
                                tracing::info!(
                                    "Vault state restored: {:?} → {:?}",
                                    result.from_state,
                                    result.to_state
                                );
                                for _ in sm.drain_events() {}
                            }
                            Err(e) => {
                                tracing::warn!("Failed to restore vault state: {} — staying Uninitialized", e);
                            }
                        }
                        drop(sm);
                    } else {
                        tracing::warn!("Failed to open existing vault database — staying Uninitialized");
                    }
                }
            }

            // TODO: Initialize audit logger
            // TODO: Set up auto-lock timer
            // TODO: Load vault_meta from database to restore Locked state

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
            commands::scanner_commands::scanner_check_entry_breach,
            commands::scanner_commands::scanner_run_full_scan,
            commands::scanner_commands::scanner_get_security_score,
            // Crypto commands (RESTRICTED)
            commands::crypto_commands::crypto_derive_key,
            commands::crypto_commands::crypto_encrypt_data,
            commands::crypto_commands::crypto_decrypt_data,
            // Note commands
            commands::note_commands::note_create,
            commands::note_commands::note_list,
            commands::note_commands::note_get,
            commands::note_commands::note_update,
            commands::note_commands::note_delete,
            commands::note_commands::note_reveal,
            // Folder commands
            commands::folder_commands::folder_list,
            commands::folder_commands::folder_create,
            commands::folder_commands::folder_delete,
            // Settings commands
            commands::settings_commands::settings_get,
            commands::settings_commands::settings_update,
            commands::settings_commands::settings_reset,
            // File commands
            commands::file_commands::file_upload,
            commands::file_commands::file_list,
            commands::file_commands::file_get,
            commands::file_commands::file_decrypt,
            commands::file_commands::file_delete,
            // Vault data commands
            commands::vault_data_commands::vault_export,
            commands::vault_data_commands::vault_import,
            commands::vault_data_commands::vault_clear,
            commands::vault_data_commands::backup_create,
        ])
        .run(tauri::generate_context!())?;

    Ok(())
}
