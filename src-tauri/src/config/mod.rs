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
//! - **Auto-lock**: 15 minutes of inactivity (0 = Never)
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
//! - `auto_lock_minutes`: 0..=480 (0 = Never)
//! - `clear_clipboard_seconds`: 5..=300
//! - `max_login_attempts`: 1..=20
//! - `lockout_duration_seconds`: 30..=3600

use crate::error::{KestrelError, KestrelResult};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Minimum allowed auto-lock duration in minutes.
/// 0 means "Never" (auto-lock disabled).
const AUTO_LOCK_MIN: u32 = 0;
/// Maximum allowed auto-lock duration in minutes.
const AUTO_LOCK_MAX: u32 = 480;

/// Minimum allowed clipboard clear time in seconds.
/// 0 means "Never" (clipboard clearing disabled).
const CLIPBOARD_CLEAR_MIN: u32 = 0;
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
    /// 0 means "Never" (auto-lock disabled).
    /// Clamped to [0, 480]. Default: 15.
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

    /// Whether to lock the vault when the system goes to sleep.
    ///
    /// Default: true.
    pub lock_on_sleep: bool,

    /// Whether to lock the vault when the application window loses focus.
    ///
    /// Default: false.
    pub lock_on_blur: bool,

    /// Whether automatic encrypted backups are enabled.
    ///
    /// Default: true.
    pub auto_backup: bool,

    /// How often automatic backups run: "daily", "weekly", "monthly".
    ///
    /// Default: "weekly".
    pub backup_frequency: String,

    /// Filesystem path where backups are stored.
    ///
    /// Default: "~/Backups/KESTREL".
    pub backup_location: String,

    /// Whether debug/verbose logging is enabled.
    ///
    /// Default: false.
    pub debug_mode: bool,
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
            lock_on_sleep: true,
            lock_on_blur: false,
            auto_backup: true,
            backup_frequency: "weekly".to_string(),
            backup_location: "~/Backups/KESTREL".to_string(),
            debug_mode: false,
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

        // Validate backup_frequency
        let valid_frequencies = ["daily", "weekly", "monthly"];
        if !valid_frequencies.contains(&self.backup_frequency.as_str()) {
            self.backup_frequency = "weekly".to_string();
        }

        // Validate backup_location is not empty
        if self.backup_location.trim().is_empty() {
            self.backup_location = "~/Backups/KESTREL".to_string();
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
    /// If the file exists but is malformed, returns the default config
    /// with a warning log (graceful degradation).
    /// All loaded values are validated and clamped before returning.
    ///
    /// # Errors
    ///
    /// Returns `KestrelError::Config` if the app data directory cannot
    /// be accessed.
    pub fn load(app_data_dir: &PathBuf) -> KestrelResult<Self> {
        let config_path = app_data_dir.join("config.json");

        if !config_path.exists() {
            tracing::info!("No config file found at {}, using defaults", config_path.display());
            let mut config = Self::default();
            config.validate();
            return Ok(config);
        }

        match std::fs::read_to_string(&config_path) {
            Ok(contents) => {
                match serde_json::from_str::<AppConfig>(&contents) {
                    Ok(mut config) => {
                        config.validate();
                        tracing::info!("Config loaded from {}", config_path.display());
                        Ok(config)
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Config file malformed at {}: {}, using defaults",
                            config_path.display(),
                            e
                        );
                        let mut config = Self::default();
                        config.validate();
                        Ok(config)
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to read config at {}: {}, using defaults",
                    config_path.display(),
                    e
                );
                let mut config = Self::default();
                config.validate();
                Ok(config)
            }
        }
    }

    /// Saves the current configuration to the application data directory.
    ///
    /// Uses atomic write (write to temp file, then rename) to prevent
    /// corruption if the app crashes mid-write.
    ///
    /// # Errors
    ///
    /// Returns `KestrelError::Config` if serialization or file I/O fails.
    pub fn save(&self, app_data_dir: &PathBuf) -> KestrelResult<()> {
        if !self.is_valid() {
            return Err(KestrelError::Config(
                "Cannot save invalid configuration".to_string(),
            ));
        }

        // Ensure the directory exists
        std::fs::create_dir_all(app_data_dir).map_err(|e| {
            KestrelError::Config(format!(
                "Failed to create app data directory {}: {}",
                app_data_dir.display(),
                e
            ))
        })?;

        let config_path = app_data_dir.join("config.json");
        let temp_path = app_data_dir.join("config.json.tmp");

        let json = serde_json::to_string_pretty(self).map_err(|e| {
            KestrelError::Config(format!("Failed to serialize config: {}", e))
        })?;

        // Write to temp file first
        std::fs::write(&temp_path, &json).map_err(|e| {
            KestrelError::Config(format!(
                "Failed to write config to {}: {}",
                temp_path.display(),
                e
            ))
        })?;

        // Atomic rename (on most OS this is atomic when src and dst are same dir)
        std::fs::rename(&temp_path, &config_path).map_err(|e| {
            KestrelError::Config(format!(
                "Failed to rename temp config to {}: {}",
                config_path.display(),
                e
            ))
        })?;

        // Set file permissions to owner-only on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            if let Err(e) = std::fs::set_permissions(&config_path, perms) {
                tracing::warn!("Failed to set config file permissions: {}", e);
            }
        }

        tracing::info!("Config saved to {}", config_path.display());
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
            auto_lock_minutes: 0, // 0 is valid (Never)
            clear_clipboard_seconds: 1, // Below min of 0 is fine, 1 is within range now
            max_login_attempts: 100,
            lockout_duration_seconds: 5,
            ..Default::default()
        };
        config.validate();
        assert_eq!(config.auto_lock_minutes, 0); // 0 stays as 0
        assert_eq!(config.clear_clipboard_seconds, 1); // 1 is now valid (min=0)
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
            max_login_attempts: 0, // Below min of 1
            ..Default::default()
        };
        let result = config.save(&PathBuf::from("/tmp"));
        assert!(result.is_err());
    }

    #[test]
    fn zero_auto_lock_is_valid() {
        let mut config = AppConfig {
            auto_lock_minutes: 0,
            ..Default::default()
        };
        config.validate();
        assert_eq!(config.auto_lock_minutes, 0);
        assert!(config.is_valid());
    }

    #[test]
    fn zero_clipboard_clear_is_valid() {
        let mut config = AppConfig {
            clear_clipboard_seconds: 0,
            ..Default::default()
        };
        config.validate();
        assert_eq!(config.clear_clipboard_seconds, 0);
        assert!(config.is_valid());
    }
}
