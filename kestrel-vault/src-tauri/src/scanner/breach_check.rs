//! Breach check module for KESTREL Vault.
//!
//! Provides local-only breach database checking. Passwords are
//! hashed with SHA-256 before any comparison — plaintext passwords
//! are NEVER transmitted or compared directly.
//!
//! # Offline-Only Design
//!
//! This module is designed to work completely offline:
//! - No network calls are made
//! - No plaintext passwords are transmitted
//! - A local breach database is embedded or downloaded periodically
//!
//! # Hash-Based Lookup
//!
//! To check if a password has been breached:
//! 1. Hash the password with SHA-256
//! 2. Look up the hash in the local breach database
//! 3. Return whether a match was found
//!
//! # Privacy
//!
//! Even the SHA-256 hash of the password is never logged or
//! stored persistently. It exists only in memory during the
//! check and is zeroized afterward.
//!
//! # TODO (Phase 2)
//!
//! - Implement local breach database (HIBP-style k-anonymity)
//! - Add periodic database update mechanism
//! - Add database integrity verification

use crate::error::KestrelError;
use crate::scanner::ThreatLevel;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// Result of a breach check.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BreachCheckResult {
    /// Whether the password was found in the breach database.
    pub is_breached: bool,
    /// The threat level based on breach status.
    pub threat_level: ThreatLevel,
    /// Number of times this password appeared in breaches (0 if not found).
    pub occurrence_count: u64,
    /// Human-readable message about the result.
    pub message: String,
}

impl BreachCheckResult {
    /// Creates a result indicating the password was found in breaches.
    pub fn breached(count: u64) -> Self {
        BreachCheckResult {
            is_breached: true,
            threat_level: ThreatLevel::Critical,
            occurrence_count: count,
            message: format!(
                "This password has appeared in {count} known data breaches"
            ),
        }
    }

    /// Creates a result indicating the password was not found.
    pub fn not_breached() -> Self {
        BreachCheckResult {
            is_breached: false,
            threat_level: ThreatLevel::None,
            occurrence_count: 0,
            message: "This password was not found in known data breaches".to_string(),
        }
    }
}

/// Hashes a password with SHA-256 for breach database lookup.
///
/// # Security
///
/// - SHA-256 is used for lookup, NOT for password storage
/// - The hash is never logged or stored persistently
/// - The hash bytes are zeroized after the lookup
///
/// # Note
///
/// SHA-256 is appropriate here because:
/// - This is NOT a password hashing use case (we use Argon2id for that)
/// - This IS a content-addressable lookup (hash → breach count)
/// - Speed is actually desired for quick lookups
pub fn hash_password_for_lookup(password: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    let hash: [u8; 32] = result.into();

    // Zeroize the hasher's internal state
    // Note: Sha256 hasher doesn't implement Zeroize, but the output
    // is what we care about protecting
    hash
}

/// Checks if a password has appeared in known data breaches.
///
/// This function hashes the password with SHA-256 and checks
/// the local breach database. No plaintext password is ever
/// transmitted or compared directly.
///
/// # Arguments
///
/// * `password` - The password to check (not stored or transmitted)
///
/// # Returns
///
/// A `BreachCheckResult` indicating whether the password was
/// found and how many times it appeared in breaches.
///
/// # Errors
///
/// Returns `KestrelError::Scanner` if the breach database
/// cannot be accessed.
///
/// # Security
///
/// - The password is hashed before lookup
/// - No network calls are made
/// - The hash is zeroized after the lookup
///
/// # TODO (Phase 2)
///
/// - Implement actual breach database lookup
/// - Add k-anonymity support for API-based checks
/// - Add local database caching
pub fn check_breach_status(password: &str) -> Result<BreachCheckResult, KestrelError> {
    let mut hash = hash_password_for_lookup(password);

    // TODO: Replace with actual breach database lookup in Phase 2
    // 1. Query local breach database with the SHA-256 hash
    // 2. Return occurrence count if found
    // 3. Zeroize the hash after lookup

    // Placeholder: always return not breached
    hash.zeroize();

    Ok(BreachCheckResult::not_breached())
}

/// Converts a SHA-256 hash to a hexadecimal string for database lookup.
///
/// # Security
///
/// The returned string should be zeroized after use.
pub fn hash_to_hex(hash: &[u8; 32]) -> String {
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_password_deterministic() {
        let h1 = hash_password_for_lookup("test-password");
        let h2 = hash_password_for_lookup("test-password");
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_password_different() {
        let h1 = hash_password_for_lookup("password-a");
        let h2 = hash_password_for_lookup("password-b");
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_to_hex_format() {
        let hash = hash_password_for_lookup("test");
        let hex = hash_to_hex(&hash);
        assert_eq!(hex.len(), 64); // 32 bytes * 2 hex chars
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn breach_check_returns_result() {
        let result = check_breach_status("test-password").unwrap();
        assert!(!result.is_breached);
    }

    #[test]
    fn breached_result() {
        let result = BreachCheckResult::breached(1000);
        assert!(result.is_breached);
        assert_eq!(result.occurrence_count, 1000);
        assert_eq!(result.threat_level, ThreatLevel::Critical);
    }

    #[test]
    fn not_breached_result() {
        let result = BreachCheckResult::not_breached();
        assert!(!result.is_breached);
        assert_eq!(result.threat_level, ThreatLevel::None);
    }
}
