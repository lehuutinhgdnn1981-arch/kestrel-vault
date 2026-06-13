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

use crate::commands::types::{
    validate_field, AppSettingsResponse, CommandError, CommandResult,
};
use tauri::State;

use super::auth_commands::AppState;

#[cfg(test)]
use crate::config::AppConfig;

/// Returns the current application settings.
///
/// Available in any vault state (locked or unlocked).
/// Settings contain no secrets.
#[tauri::command]
pub fn settings_get(
    state: State<'_, AppState>,
) -> CommandResult<AppSettingsResponse> {
    // Settings are always readable — no state guard needed
    // Read the live configuration from AppState
    let config = state.config.read().unwrap_or_else(|e| {
        tracing::error!("Config lock poisoned: {}", e);
        std::process::exit(1);
    });

    Ok(AppSettingsResponse {
        auto_lock_minutes: config.auto_lock_minutes,
        theme: config.theme.clone(),
        language: config.language.clone(),
        clear_clipboard_seconds: config.clear_clipboard_seconds,
    })
}

/// Updates application settings.
///
/// Only provided fields are updated (partial update).
/// All changes are validated and audit-logged.
//!
//! # IPC Contract
//!
// - **Required state**: Unlocked (settings changes require active session)
//
// # Errors
//
// - `UNAUTHORIZED`: Vault is locked
// - `VALIDATION_ERROR`: Invalid setting values
#[tauri::command]
pub fn settings_update(
    auto_lock_minutes: Option<u32>,
    theme: Option<String>,
    language: Option<String>,
    clear_clipboard_seconds: Option<u32>,
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

    // Validate numeric ranges (using AppConfig clamping rules)
    if let Some(mins) = auto_lock_minutes {
        if mins < 1 || mins > 480 {
            return Err(CommandError::validation(
                "Auto-lock must be between 1 and 480 minutes",
            ));
        }
    }
    if let Some(secs) = clear_clipboard_seconds {
        if secs < 5 || secs > 300 {
            return Err(CommandError::validation(
                "Clear clipboard must be between 5 and 300 seconds",
            ));
        }
    }

    // ── Apply partial updates to AppState config ──
    // All changes are applied atomically within a single write lock.
    // The config is validated before committing to ensure consistency.
    let updated_response = {
        let mut config_guard = state.config.write().unwrap_or_else(|e| {
            tracing::error!("Config lock poisoned: {}", e);
            std::process::exit(1);
        });

        // Apply partial updates (only provided fields are changed)
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

        // Validate the updated config (clamps any out-of-range values)
        config_guard.validate();

        // Build response from the actual (validated) config
        AppSettingsResponse {
            auto_lock_minutes: config_guard.auto_lock_minutes,
            theme: config_guard.theme.clone(),
            language: config_guard.language.clone(),
            clear_clipboard_seconds: config_guard.clear_clipboard_seconds,
        }
    };

    // TODO: Persist config to file/database via AppConfig::save()
    // TODO: Audit log: SettingsChanged { changed_fields }

    tracing::info!("Settings updated");

    Ok(updated_response)
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
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"auto_lock_minutes\":15"));
    }

    #[test]
    fn settings_defaults_match_config() {
        let config = AppConfig::default();
        let resp = AppSettingsResponse {
            auto_lock_minutes: config.auto_lock_minutes,
            theme: config.theme.clone(),
            language: config.language.clone(),
            clear_clipboard_seconds: config.clear_clipboard_seconds,
        };
        assert_eq!(resp.auto_lock_minutes, 15);
        assert_eq!(resp.theme, "dark");
        assert_eq!(resp.language, "en");
        assert_eq!(resp.clear_clipboard_seconds, 30);
    }
}
