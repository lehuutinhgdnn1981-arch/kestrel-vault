//! Configurable KDF parameters for KESTREL Vault.
//!
//! This module defines a structured, serializable representation of the
//! Argon2id parameters used for key derivation. Instead of hardcoding
//! constants, the parameters are stored alongside the salt in `vault_meta`
//! and can be upgraded when security recommendations change.
//!
//! # Why Configurable Parameters?
//!
//! OWASP and other security bodies periodically update their recommendations
//! for Argon2id parameters. As hardware improves, the memory and iteration
//! costs that are sufficient today may become inadequate in the future.
//!
//! By storing parameters alongside the salt, we enable:
//!
//! 1. **Forward compatibility**: New vaults can use stronger parameters
//!    without breaking old vaults.
//! 2. **In-place upgrades**: When the user changes their password, we can
//!    upgrade to the latest recommended parameters.
//! 3. **Per-vault tuning**: Parameters can be adjusted based on the
//!    device's capabilities (e.g., mobile vs desktop).
//!
//! # OWASP Recommendations (as of 2024)
//!
//! | Parameter    | Value          |
//! |--------------|----------------|
//! | Memory       | 256 MB (262144 KiB) |
//! | Iterations   | 3              |
//! | Parallelism  | 4              |
//! | Salt length  | 128 bits (16 bytes) |
//! | Key length   | 256 bits (32 bytes) |
//!
//! # Versioning
//!
//! Parameters include a `version` field for future upgrades. When
//! parameters are upgraded, the version is incremented and the
//! key is re-derived with the new parameters during password change.

use crate::crypto::kdf;
use crate::error::{KestrelError, KestrelResult};
use serde::{Deserialize, Serialize};

/// The current recommended KDF parameter version.
/// Increment this when parameters are upgraded.
pub const CURRENT_KDF_VERSION: u32 = 1;

/// KDF parameters that meet the minimum security requirements.
/// These are used for validation — any stored parameters must
/// meet or exceed these minimums.
pub mod minimum {
    /// Minimum memory cost in KiB (64 MB).
    pub const MEMORY_COST_KIB: u32 = 64 * 1024;
    /// Minimum iterations (1).
    pub const ITERATIONS: u32 = 1;
    /// Minimum parallelism (1).
    pub const PARALLELISM: u32 = 1;
}

/// Configurable Argon2id key derivation parameters.
///
/// This struct is stored in the `vault_meta` table alongside the salt.
/// When the vault is unlocked, these parameters are loaded from the
/// database and used to derive the master key.
///
/// # Security
///
/// - Parameters are validated on load to prevent downgrade attacks
/// - The version field enables future parameter upgrades
/// - Default parameters follow current OWASP recommendations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfParams {
    /// The version of the KDF parameters schema.
    /// Version 1 = current OWASP recommendations.
    pub version: u32,

    /// Memory cost in KiB. Higher = more resistant to GPU attacks.
    /// Default: 262144 (256 MB)
    pub memory_cost_kib: u32,

    /// Number of iterations (time cost). Higher = more CPU work.
    /// Default: 3
    pub iterations: u32,

    /// Degree of parallelism (lanes). Higher = uses more threads.
    /// Default: 4
    pub parallelism: u32,

    /// Salt length in bytes. Default: 16 (128 bits)
    pub salt_len: u32,

    /// Output key length in bytes. Default: 32 (256 bits)
    pub key_len: u32,
}

impl KdfParams {
    /// Creates KDF parameters with current OWASP-recommended values.
    ///
    /// These are the default parameters used for new vaults:
    /// - Memory: 256 MB (262144 KiB)
    /// - Iterations: 3
    /// - Parallelism: 4
    /// - Salt: 16 bytes (128 bits)
    /// - Key: 32 bytes (256 bits)
    pub fn current() -> Self {
        KdfParams {
            version: CURRENT_KDF_VERSION,
            memory_cost_kib: kdf::MEMORY_COST,
            iterations: kdf::ITERATIONS,
            parallelism: kdf::PARALLELISM,
            salt_len: kdf::SALT_LEN as u32,
            key_len: kdf::DERIVED_KEY_LEN as u32,
        }
    }

    /// Creates KDF parameters with the default OWASP-recommended values.
    ///
    /// This is the same as `current()` and is used as the `Default` impl.
    pub fn default_owasp() -> Self {
        Self::current()
    }

    /// Creates custom KDF parameters.
    ///
    /// Use this for devices with constrained memory or when
    /// specific parameter tuning is needed.
    ///
    /// # Arguments
    ///
    /// * `memory_cost_kib` - Memory cost in KiB
    /// * `iterations` - Number of iterations
    /// * `parallelism` - Degree of parallelism
    ///
    /// # Errors
    ///
    /// Returns `KestrelError::Validation` if any parameter is below
    /// the minimum security threshold.
    pub fn custom(
        memory_cost_kib: u32,
        iterations: u32,
        parallelism: u32,
    ) -> KestrelResult<Self> {
        let params = KdfParams {
            version: CURRENT_KDF_VERSION,
            memory_cost_kib,
            iterations,
            parallelism,
            salt_len: kdf::SALT_LEN as u32,
            key_len: kdf::DERIVED_KEY_LEN as u32,
        };
        params.validate()?;
        Ok(params)
    }

    /// Validates that the KDF parameters meet minimum security requirements.
    ///
    /// This is called when loading parameters from the database to
    /// prevent downgrade attacks where an attacker modifies the stored
    /// parameters to weaken the key derivation.
    ///
    /// # Errors
    ///
    /// Returns `KestrelError::Validation` if any parameter is below
    /// the minimum threshold.
    pub fn validate(&self) -> KestrelResult<()> {
        if self.memory_cost_kib < minimum::MEMORY_COST_KIB {
            return Err(KestrelError::Validation(format!(
                "Memory cost {} KiB is below minimum {} KiB",
                self.memory_cost_kib,
                minimum::MEMORY_COST_KIB
            )));
        }

        if self.iterations < minimum::ITERATIONS {
            return Err(KestrelError::Validation(format!(
                "Iterations {} is below minimum {}",
                self.iterations,
                minimum::ITERATIONS
            )));
        }

        if self.parallelism < minimum::PARALLELISM {
            return Err(KestrelError::Validation(format!(
                "Parallelism {} is below minimum {}",
                self.parallelism,
                minimum::PARALLELISM
            )));
        }

        if self.salt_len < 16 {
            return Err(KestrelError::Validation(format!(
                "Salt length {} bytes is below minimum 16 bytes",
                self.salt_len
            )));
        }

        if self.key_len != 32 {
            return Err(KestrelError::Validation(format!(
                "Key length must be 32 bytes (256 bits), got {} bytes",
                self.key_len
            )));
        }

        Ok(())
    }

    /// Checks whether these parameters should be upgraded to the
    /// current recommended values.
    ///
    /// Returns `true` if any parameter is below the current
    /// OWASP recommendation. This is used during password change
    /// to prompt the user to upgrade their parameters.
    pub fn needs_upgrade(&self) -> bool {
        self.version < CURRENT_KDF_VERSION
            || self.memory_cost_kib < kdf::MEMORY_COST
            || self.iterations < kdf::ITERATIONS
            || self.parallelism < kdf::PARALLELISM
    }

    /// Returns a human-readable description of the parameters.
    ///
    /// Useful for display in the security settings UI.
    pub fn description(&self) -> String {
        let memory_mb = self.memory_cost_kib / 1024;
        format!(
            "Argon2id v{}: {} MB, {} iterations, parallelism {}",
            self.version, memory_mb, self.iterations, self.parallelism
        )
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::current()
    }
}

impl std::fmt::Display for KdfParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.description())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_params_match_constants() {
        let params = KdfParams::current();
        assert_eq!(params.version, CURRENT_KDF_VERSION);
        assert_eq!(params.memory_cost_kib, kdf::MEMORY_COST);
        assert_eq!(params.iterations, kdf::ITERATIONS);
        assert_eq!(params.parallelism, kdf::PARALLELISM);
        assert_eq!(params.salt_len, kdf::SALT_LEN as u32);
        assert_eq!(params.key_len, kdf::DERIVED_KEY_LEN as u32);
    }

    #[test]
    fn default_is_current() {
        let default = KdfParams::default();
        let current = KdfParams::current();
        assert_eq!(default, current);
    }

    #[test]
    fn current_params_are_valid() {
        let params = KdfParams::current();
        assert!(params.validate().is_ok());
    }

    #[test]
    fn current_params_dont_need_upgrade() {
        let params = KdfParams::current();
        assert!(!params.needs_upgrade());
    }

    #[test]
    fn custom_params_with_valid_values() {
        let params = KdfParams::custom(128 * 1024, 4, 2).unwrap();
        assert_eq!(params.memory_cost_kib, 128 * 1024);
        assert_eq!(params.iterations, 4);
        assert_eq!(params.parallelism, 2);
    }

    #[test]
    fn custom_params_below_minimum_memory_rejected() {
        let result = KdfParams::custom(1024, 3, 4); // 1 MB — too low
        assert!(result.is_err());
    }

    #[test]
    fn custom_params_below_minimum_iterations_rejected() {
        let result = KdfParams::custom(256 * 1024, 0, 4);
        assert!(result.is_err());
    }

    #[test]
    fn custom_params_below_minimum_parallelism_rejected() {
        let result = KdfParams::custom(256 * 1024, 3, 0);
        assert!(result.is_err());
    }

    #[test]
    fn old_version_needs_upgrade() {
        let mut params = KdfParams::current();
        params.version = 0;
        assert!(params.needs_upgrade());
    }

    #[test]
    fn lower_memory_needs_upgrade() {
        let mut params = KdfParams::current();
        params.memory_cost_kib = 64 * 1024; // 64 MB instead of 256 MB
        assert!(params.needs_upgrade());
    }

    #[test]
    fn lower_iterations_needs_upgrade() {
        let mut params = KdfParams::current();
        params.iterations = 1;
        assert!(params.needs_upgrade());
    }

    #[test]
    fn description_contains_key_info() {
        let params = KdfParams::current();
        let desc = params.description();
        assert!(desc.contains("Argon2id"));
        assert!(desc.contains("256 MB"));
        assert!(desc.contains("3 iterations"));
    }

    #[test]
    fn display_matches_description() {
        let params = KdfParams::current();
        assert_eq!(format!("{}", params), params.description());
    }

    #[test]
    fn params_serialize_deserialize() {
        let params = KdfParams::current();
        let json = serde_json::to_string(&params).unwrap();
        let restored: KdfParams = serde_json::from_str(&json).unwrap();
        assert_eq!(params, restored);
    }

    #[test]
    fn short_salt_rejected() {
        let mut params = KdfParams::current();
        params.salt_len = 8;
        assert!(params.validate().is_err());
    }

    #[test]
    fn wrong_key_len_rejected() {
        let mut params = KdfParams::current();
        params.key_len = 16;
        assert!(params.validate().is_err());
    }

    #[test]
    fn minimum_params_are_valid() {
        // Exactly at the minimum boundary
        let params = KdfParams {
            version: CURRENT_KDF_VERSION,
            memory_cost_kib: minimum::MEMORY_COST_KIB,
            iterations: minimum::ITERATIONS,
            parallelism: minimum::PARALLELISM,
            salt_len: 16,
            key_len: 32,
        };
        assert!(params.validate().is_ok());
    }

    #[test]
    fn just_below_minimum_memory_rejected() {
        let params = KdfParams {
            version: CURRENT_KDF_VERSION,
            memory_cost_kib: minimum::MEMORY_COST_KIB - 1,
            iterations: minimum::ITERATIONS,
            parallelism: minimum::PARALLELISM,
            salt_len: 16,
            key_len: 32,
        };
        assert!(params.validate().is_err());
    }
}
