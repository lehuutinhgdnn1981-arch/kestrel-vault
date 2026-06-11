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
use crate::config::AppConfig;
use std::sync::RwLock;
use tauri::State;

use super::auth_commands::AppState;

/// Returns the current application settings.
///
/// Available in any vault state (locked or unlocked).
/// Settings contain no secrets.
#[tauri::command]
pub fn settings_get(
    state: State<'_, AppState>,
) -> CommandResult<AppSettingsResponse> {
    // Settings are always readable — no state guard needed
    // TODO: Load from AppConfig stored in AppState
    // For now, return defaults from AppConfig
    let config = AppConfig::default();

    CommandResult::ok(AppSettingsResponse {
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
//! - **Required state**: Unlocked (settings changes require active session)
//!
//! # Errors
//!
//! - `UNAUTHORIZED`: Vault is locked
//! - `VALIDATION_ERROR`: Invalid setting values
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
            return CommandResult::Err(e);
        }
        let valid = ["dark", "light", "system"];
        if !valid.contains(&t.as_str()) {
            return CommandResult::Err(CommandError::validation(
                "Theme must be one of: dark, light, system",
            ));
        }
    }

    // Validate language if provided
    if let Some(ref l) = language {
        if let Err(e) = validate_field(l, 10, "language") {
            return CommandResult::Err(e);
        }
    }

    // Validate numeric ranges (using AppConfig clamping rules)
    let config = AppConfig::default();
    if let Some(mins) = auto_lock_minutes {
        if mins < 1 || mins > 480 {
            return CommandResult::Err(CommandError::validation(
                "Auto-lock must be between 1 and 480 minutes",
            ));
        }
    }
    if let Some(secs) = clear_clipboard_seconds {
        if secs < 5 || secs > 300 {
            return CommandResult::Err(CommandError::validation(
                "Clear clipboard must be between 5 and 300 seconds",
            ));
        }
    }

    // TODO: Load current config from AppState
    // TODO: Apply partial updates
    // TODO: Save to config file/database via AppConfig
    // TODO: Audit log: SettingsChanged { changed_fields }

    // Build response with applied changes
    let current_config = AppConfig::default();
    let auto_lock = auto_lock_minutes.unwrap_or(current_config.auto_lock_minutes);
    let theme_val = theme.unwrap_or_else(|| current_config.theme.clone());
    let lang = language.unwrap_or_else(|| current_config.language.clone());
    let clipboard_secs = clear_clipboard_seconds.unwrap_or(current_config.clear_clipboard_seconds);

    CommandResult::ok(AppSettingsResponse {
        auto_lock_minutes: auto_lock,
        theme: theme_val,
        language: lang,
        clear_clipboard_seconds: clipboard_secs,
    })
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
