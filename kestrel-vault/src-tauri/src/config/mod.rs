//! Application configuration module for KESTREL Vault.
//!
//! This module manages all user-configurable settings with secure
//! defaults and validation. Configuration is loaded from the
//! application data directory and persisted as JSON.
//!
//! # Security Defaults
//!
//! All defaults are chosen to be restrictive — the user may relax
//! them, but the out-of-the-box experience is always the most
//! secure option:
//!
//! - **Auto-lock**: 15 minutes of inactivity
//! - **Clipboard clear**: 30 seconds after copy
//! - **Max login attempts**: 5 before lockout
//! - **Lockout duration**: 300 seconds (5 minutes)
//!
//! # Value Clamping
//!
//! All values are clamped to safe ranges on load. This prevents
//! misconfiguration (accidental or malicious) from weakening
//! security posture:
//!
//! - `auto_lock_minutes`: 1..=480
//! - `clear_clipboard_seconds`: 5..=300
//! - `max_login_attempts`: 1..=20
//! - `lockout_duration_seconds`: 30..=3600

use crate::error::{KestrelError, KestrelResult};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Minimum allowed auto-lock duration in minutes.
const AUTO_LOCK_MIN: u32 = 1;
/// Maximum allowed auto-lock duration in minutes.
const AUTO_LOCK_MAX: u32 = 480;

/// Minimum allowed clipboard clear time in seconds.
const CLIPBOARD_CLEAR_MIN: u32 = 5;
/// Maximum allowed clipboard clear time in seconds.
const CLIPBOARD_CLEAR_MAX: u32 = 300;

/// Minimum allowed login attempts before lockout.
const MAX_LOGIN_ATTEMPTS_MIN: u32 = 1;
/// Maximum allowed login attempts before lockout.
const MAX_LOGIN_ATTEMPTS_MAX: u32 = 20;

/// Minimum allowed lockout duration in seconds.
const LOCKOUT_DURATION_MIN: u32 = 30;
/// Maximum allowed lockout duration in seconds.
const LOCKOUT_DURATION_MAX: u32 = 3600;

/// Application configuration with security-focused defaults.
///
/// This struct is serialized to/deserialized from JSON in the
/// application data directory. All fields are validated on load
/// and clamped to safe ranges.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AppConfig {
    /// Minutes of inactivity before the vault auto-locks.
    ///
    /// Clamped to [1, 480]. Default: 15.
    pub auto_lock_minutes: u32,

    /// Seconds before clipboard contents are cleared after a copy.
    ///
    /// Clamped to [5, 300]. Default: 30.
    pub clear_clipboard_seconds: u32,

    /// UI theme name (e.g., "dark", "light").
    ///
    /// Default: "dark".
    pub theme: String,

    /// Language code for the UI (ISO 639-1).
    ///
    /// Default: "en".
    pub language: String,

    /// Maximum failed login attempts before lockout is triggered.
    ///
    /// Clamped to [1, 20]. Default: 5.
    pub max_login_attempts: u32,

    /// Duration in seconds the vault stays locked after
    /// exceeding `max_login_attempts`.
    ///
    /// Clamped to [30, 3600]. Default: 300.
    pub lockout_duration_seconds: u32,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            auto_lock_minutes: 15,
            clear_clipboard_seconds: 30,
            theme: "dark".to_string(),
            language: "en".to_string(),
            max_login_attempts: 5,
            lockout_duration_seconds: 300,
        }
    }
}

impl AppConfig {
    /// Validates and clamps all configuration values to safe ranges.
    ///
    /// This method is called automatically when loading config.
    /// It ensures no value can be set outside its allowed range,
    /// regardless of what is stored on disk.
    pub fn validate(&mut self) {
        self.auto_lock_minutes = self.auto_lock_minutes.clamp(AUTO_LOCK_MIN, AUTO_LOCK_MAX);
        self.clear_clipboard_seconds = self
            .clear_clipboard_seconds
            .clamp(CLIPBOARD_CLEAR_MIN, CLIPBOARD_CLEAR_MAX);
        self.max_login_attempts = self
            .max_login_attempts
            .clamp(MAX_LOGIN_ATTEMPTS_MIN, MAX_LOGIN_ATTEMPTS_MAX);
        self.lockout_duration_seconds = self
            .lockout_duration_seconds
            .clamp(LOCKOUT_DURATION_MIN, LOCKOUT_DURATION_MAX);

        if self.theme.trim().is_empty() {
            self.theme = "dark".to_string();
        }
        if self.language.trim().is_empty() {
            self.language = "en".to_string();
        }
    }

    /// Returns whether the config values are all within valid ranges.
    ///
    /// Unlike `validate()`, this does **not** mutate — it only checks.
    pub fn is_valid(&self) -> bool {
        let mut clone = self.clone();
        clone.validate();
        clone == *self
    }

    /// Loads configuration from the application data directory.
    ///
    /// If the config file does not exist, returns the default config.
    /// If the file exists but is malformed, returns an error.
    /// All loaded values are validated and clamped before returning.
    ///
    /// # Errors
    ///
    /// Returns `KestrelError::Config` if the file cannot be read
    /// or contains invalid JSON.
    ///
    /// # TODO
    ///
    /// - Integrate with `tauri::api::path::app_data_dir`
    /// - Add config file migration for version upgrades
    /// - Add atomic write (write to temp, then rename)
    pub fn load(_app_data_dir: &PathBuf) -> KestrelResult<Self> {
        // TODO: Implement actual file loading
        // let config_path = app_data_dir.join("config.json");
        // if !config_path.exists() {
        //     return Ok(Self::default());
        // }
        // let contents = std::fs::read_to_string(&config_path)?;
        // let mut config: AppConfig = serde_json::from_str(&contents)?;
        // config.validate();
        // Ok(config)

        let mut config = Self::default();
        config.validate();
        Ok(config)
    }

    /// Saves the current configuration to the application data directory.
    ///
    /// # Errors
    ///
    /// Returns `KestrelError::Config` if serialization or file I/O fails.
    ///
    /// # TODO
    ///
    /// - Integrate with `tauri::api::path::app_data_dir`
    /// - Add atomic write (write to temp, then rename)
    /// - Set file permissions to owner-only (0600 on Unix)
    pub fn save(&self, _app_data_dir: &PathBuf) -> KestrelResult<()> {
        // TODO: Implement actual file saving
        // let config_path = app_data_dir.join("config.json");
        // let json = serde_json::to_string_pretty(self)?;
        // std::fs::write(&config_path, json)?;
        // Ok(())

        if !self.is_valid() {
            return Err(KestrelError::Config(
                "Cannot save invalid configuration".to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        let config = AppConfig::default();
        assert!(config.is_valid());
    }

    #[test]
    fn validate_clamps_out_of_range_values() {
        let mut config = AppConfig {
            auto_lock_minutes: 0,
            clear_clipboard_seconds: 1,
            max_login_attempts: 100,
            lockout_duration_seconds: 5,
            ..Default::default()
        };
        config.validate();
        assert_eq!(config.auto_lock_minutes, AUTO_LOCK_MIN);
        assert_eq!(config.clear_clipboard_seconds, CLIPBOARD_CLEAR_MIN);
        assert_eq!(config.max_login_attempts, MAX_LOGIN_ATTEMPTS_MAX);
        assert_eq!(config.lockout_duration_seconds, LOCKOUT_DURATION_MIN);
    }

    #[test]
    fn validate_clamps_high_values() {
        let mut config = AppConfig {
            auto_lock_minutes: 9999,
            clear_clipboard_seconds: 9999,
            lockout_duration_seconds: 9999,
            ..Default::default()
        };
        config.validate();
        assert_eq!(config.auto_lock_minutes, AUTO_LOCK_MAX);
        assert_eq!(config.clear_clipboard_seconds, CLIPBOARD_CLEAR_MAX);
        assert_eq!(config.lockout_duration_seconds, LOCKOUT_DURATION_MAX);
    }

    #[test]
    fn empty_theme_defaults_to_dark() {
        let mut config = AppConfig {
            theme: "  ".to_string(),
            ..Default::default()
        };
        config.validate();
        assert_eq!(config.theme, "dark");
    }

    #[test]
    fn empty_language_defaults_to_en() {
        let mut config = AppConfig {
            language: "".to_string(),
            ..Default::default()
        };
        config.validate();
        assert_eq!(config.language, "en");
    }

    #[test]
    fn save_rejects_invalid_config() {
        let config = AppConfig {
            auto_lock_minutes: 0,
            ..Default::default()
        };
        let result = config.save(&PathBuf::from("/tmp"));
        assert!(result.is_err());
    }
}
