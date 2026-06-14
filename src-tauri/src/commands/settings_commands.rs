//! Settings Tauri commands for KESTREL Vault.
//!
//! Provides read/write access to application settings.
//! All settings changes are audit-logged.
//!
//! # IPC Contract
//!
//! | Command          | Required State | Effect            |
//! |------------------|---------------|-------------------|
//! | settings_get     | Any           | Read-only         |
//! | settings_update  | Unlocked      | Persist + audit   |
//! | settings_reset   | Unlocked      | Reset to defaults |

use crate::commands::types::{
    validate_field, AppSettingsResponse, CommandError, CommandResult,
};
use tauri::State;

use super::auth_commands::AppState;

#[cfg(test)]
use crate::config::AppConfig;

/// Builds an AppSettingsResponse from the current config.
fn build_response(config: &crate::config::AppConfig) -> AppSettingsResponse {
    AppSettingsResponse {
        auto_lock_minutes: config.auto_lock_minutes,
        theme: config.theme.clone(),
        language: config.language.clone(),
        clear_clipboard_seconds: config.clear_clipboard_seconds,
        lock_on_sleep: config.lock_on_sleep,
        lock_on_blur: config.lock_on_blur,
        auto_backup: config.auto_backup,
        backup_frequency: config.backup_frequency.clone(),
        backup_location: config.backup_location.clone(),
        debug_mode: config.debug_mode,
        max_login_attempts: config.max_login_attempts,
        lockout_duration_seconds: config.lockout_duration_seconds,
    }
}

/// Returns the current application settings.
///
/// Available in any vault state (locked or unlocked).
/// Settings contain no secrets.
#[tauri::command]
pub fn settings_get(
    state: State<'_, AppState>,
) -> CommandResult<AppSettingsResponse> {
    // Settings are always readable — no state guard needed
    let config = state.config.read().unwrap_or_else(|e| {
        tracing::error!("Config lock poisoned: {}", e);
        std::process::exit(1);
    });

    Ok(build_response(&config))
}

/// Updates application settings.
///
/// Only provided fields are updated (partial update).
/// All changes are validated and audit-logged.
///
/// # IPC Contract
///
/// - **Required state**: Unlocked (settings changes require active session)
#[tauri::command]
pub fn settings_update(
    auto_lock_minutes: Option<u32>,
    theme: Option<String>,
    language: Option<String>,
    clear_clipboard_seconds: Option<u32>,
    lock_on_sleep: Option<bool>,
    lock_on_blur: Option<bool>,
    auto_backup: Option<bool>,
    backup_frequency: Option<String>,
    backup_location: Option<String>,
    debug_mode: Option<bool>,
    state: State<'_, AppState>,
) -> CommandResult<AppSettingsResponse> {
    // Guard: vault must be unlocked for settings changes
    state.require_unlocked()?;

    // Validate theme if provided
    if let Some(ref t) = theme {
        if let Err(e) = validate_field(t, 20, "theme") {
            return Err(e);
        }
        let valid = ["dark", "light", "system"];
        if !valid.contains(&t.as_str()) {
            return Err(CommandError::validation(
                "Theme must be one of: dark, light, system",
            ));
        }
    }

    // Validate language if provided
    if let Some(ref l) = language {
        if let Err(e) = validate_field(l, 10, "language") {
            return Err(e);
        }
    }

    // Validate numeric ranges
    // 0 means "Never" for both auto-lock and clipboard clear
    if let Some(mins) = auto_lock_minutes {
        if mins > 480 {
            return Err(CommandError::validation(
                "Auto-lock must be between 0 (Never) and 480 minutes",
            ));
        }
    }
    if let Some(secs) = clear_clipboard_seconds {
        if secs > 300 {
            return Err(CommandError::validation(
                "Clear clipboard must be between 0 (Never) and 300 seconds",
            ));
        }
    }

    // Validate backup_frequency if provided
    if let Some(ref freq) = backup_frequency {
        let valid = ["daily", "weekly", "monthly"];
        if !valid.contains(&freq.as_str()) {
            return Err(CommandError::validation(
                "Backup frequency must be one of: daily, weekly, monthly",
            ));
        }
    }

    // Validate backup_location if provided
    if let Some(ref loc) = backup_location {
        if let Err(e) = validate_field(loc, 1024, "backup_location") {
            return Err(e);
        }
    }

    // ── Apply partial updates to AppState config ──
    let updated_response = {
        let mut config_guard = state.config.write().unwrap_or_else(|e| {
            tracing::error!("Config lock poisoned: {}", e);
            std::process::exit(1);
        });

        if let Some(mins) = auto_lock_minutes {
            config_guard.auto_lock_minutes = mins;
        }
        if let Some(ref t) = theme {
            config_guard.theme = t.clone();
        }
        if let Some(ref l) = language {
            config_guard.language = l.clone();
        }
        if let Some(secs) = clear_clipboard_seconds {
            config_guard.clear_clipboard_seconds = secs;
        }
        if let Some(val) = lock_on_sleep {
            config_guard.lock_on_sleep = val;
        }
        if let Some(val) = lock_on_blur {
            config_guard.lock_on_blur = val;
        }
        if let Some(val) = auto_backup {
            config_guard.auto_backup = val;
        }
        if let Some(ref freq) = backup_frequency {
            config_guard.backup_frequency = freq.clone();
        }
        if let Some(ref loc) = backup_location {
            config_guard.backup_location = loc.clone();
        }
        if let Some(val) = debug_mode {
            config_guard.debug_mode = val;
        }

        // Validate the updated config (clamps any out-of-range values)
        config_guard.validate();

        build_response(&config_guard)
    };

    // Persist config to disk
    {
        let config = state.config.read().unwrap_or_else(|e| {
            tracing::error!("Config lock poisoned: {}", e);
            std::process::exit(1);
        });
        let app_data_dir = state.get_app_data_dir();
        if let Some(ref dir) = app_data_dir {
            if let Err(e) = config.save(dir) {
                tracing::warn!("Failed to persist settings: {}", e);
            }
        }
    }

    // Audit log settings change
    if let Some(pool) = state.get_db_pool() {
        let _ = crate::commands::async_runtime::block_on(async {
            crate::db::audit_event_repo::AuditEventRepo::create(
                &pool,
                crate::db::audit_event_repo::CreateAuditEventRequest {
                    category: "settings".to_string(),
                    action: "SettingsChanged".to_string(),
                    subject: "user".to_string(),
                    metadata_json: None,
                },
            )
            .await
        });
    }

    tracing::info!("Settings updated");

    Ok(updated_response)
}

/// Resets all settings to their default values.
///
/// The vault data (passwords, notes, files) is NOT affected.
/// Only application configuration is reset.
///
/// # IPC Contract
///
/// - **Required state**: Unlocked
#[tauri::command]
pub fn settings_reset(
    state: State<'_, AppState>,
) -> CommandResult<AppSettingsResponse> {
    // Guard: vault must be unlocked for settings reset
    state.require_unlocked()?;

    // Replace config with defaults
    let reset_response = {
        let mut config_guard = state.config.write().unwrap_or_else(|e| {
            tracing::error!("Config lock poisoned: {}", e);
            std::process::exit(1);
        });

        *config_guard = crate::config::AppConfig::default();
        build_response(&config_guard)
    };

    // Persist the reset config to disk
    {
        let config = state.config.read().unwrap_or_else(|e| {
            tracing::error!("Config lock poisoned: {}", e);
            std::process::exit(1);
        });
        let app_data_dir = state.get_app_data_dir();
        if let Some(ref dir) = app_data_dir {
            if let Err(e) = config.save(dir) {
                tracing::warn!("Failed to persist settings reset: {}", e);
            }
        }
    }

    // Audit log settings reset
    if let Some(pool) = state.get_db_pool() {
        let _ = crate::commands::async_runtime::block_on(async {
            crate::db::audit_event_repo::AuditEventRepo::create(
                &pool,
                crate::db::audit_event_repo::CreateAuditEventRequest {
                    category: "settings".to_string(),
                    action: "SettingsReset".to_string(),
                    subject: "user".to_string(),
                    metadata_json: None,
                },
            )
            .await
        });
    }

    tracing::info!("Settings reset to defaults");

    Ok(reset_response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_response_serializes() {
        let resp = AppSettingsResponse {
            auto_lock_minutes: 15,
            theme: "dark".to_string(),
            language: "en".to_string(),
            clear_clipboard_seconds: 30,
            lock_on_sleep: true,
            lock_on_blur: false,
            auto_backup: true,
            backup_frequency: "weekly".to_string(),
            backup_location: "~/Backups/KESTREL".to_string(),
            debug_mode: false,
            max_login_attempts: 5,
            lockout_duration_seconds: 300,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"auto_lock_minutes\":15"));
        assert!(json.contains("\"lock_on_sleep\":true"));
        assert!(json.contains("\"auto_backup\":true"));
    }

    #[test]
    fn settings_defaults_match_config() {
        let config = AppConfig::default();
        let resp = build_response(&config);
        assert_eq!(resp.auto_lock_minutes, 15);
        assert_eq!(resp.theme, "dark");
        assert_eq!(resp.language, "en");
        assert_eq!(resp.clear_clipboard_seconds, 30);
        assert_eq!(resp.lock_on_sleep, true);
        assert_eq!(resp.lock_on_blur, false);
        assert_eq!(resp.auto_backup, true);
        assert_eq!(resp.backup_frequency, "weekly");
        assert_eq!(resp.backup_location, "~/Backups/KESTREL");
        assert_eq!(resp.debug_mode, false);
        assert_eq!(resp.max_login_attempts, 5);
        assert_eq!(resp.lockout_duration_seconds, 300);
    }
}
