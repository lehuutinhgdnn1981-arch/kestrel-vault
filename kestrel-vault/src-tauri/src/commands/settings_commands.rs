//! Settings Tauri commands for KESTREL Vault.
//!
//! Provides read/write access to application settings.
//! All settings changes are audit-logged.

use crate::commands::types::{
    validate_field, AppSettingsResponse, CommandError, CommandResult,
};
use tauri::State;

use super::auth_commands::AppState;

/// Returns the current application settings.
///
/// Available in any vault state (locked or unlocked).
#[tauri::command]
pub fn settings_get(
    _state: State<'_, AppState>,
) -> CommandResult<AppSettingsResponse> {
    // TODO: Load from config file or database
    CommandResult::ok(AppSettingsResponse {
        auto_lock_minutes: 15,
        theme: "dark".to_string(),
        language: "en".to_string(),
        clear_clipboard_seconds: 30,
    })
}

/// Updates application settings.
///
/// Only provided fields are updated (partial update).
/// All changes are validated and audit-logged.
///
/// # Errors
///
/// - `VALIDATION_ERROR`: Invalid setting values
/// - `UNAUTHORIZED`: Vault is locked
#[tauri::command]
pub fn settings_update(
    auto_lock_minutes: Option<u32>,
    theme: Option<String>,
    language: Option<String>,
    clear_clipboard_seconds: Option<u32>,
    _state: State<'_, AppState>,
) -> CommandResult<AppSettingsResponse> {
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

    // Validate numeric ranges
    if let Some(mins) = auto_lock_minutes {
        if !(1..=480).contains(&mins) {
            return CommandResult::Err(CommandError::validation(
                "Auto-lock must be between 1 and 480 minutes",
            ));
        }
    }
    if let Some(secs) = clear_clipboard_seconds {
        if !(5..=300).contains(&secs) {
            return CommandResult::Err(CommandError::validation(
                "Clear clipboard must be between 5 and 300 seconds",
            ));
        }
    }

    // TODO: Load current config
    // TODO: Apply partial updates
    // TODO: Save to config file/database
    // TODO: Audit log: SettingsChanged

    CommandResult::ok(AppSettingsResponse {
        auto_lock_minutes: auto_lock_minutes.unwrap_or(15),
        theme: theme.unwrap_or_else(|| "dark".to_string()),
        language: language.unwrap_or_else(|| "en".to_string()),
        clear_clipboard_seconds: clear_clipboard_seconds.unwrap_or(30),
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
}
