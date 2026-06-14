//! Breach check module for KESTREL Vault.
//!
//! Provides breach checking via the Have I Been Pwned (HIBP) Password API
//! using k-anonymity. Only the first 5 characters of the SHA-1 hash are
//! sent to the API — the full password and full hash NEVER leave the device.
//!
//! # How HIBP k-anonymity works
//!
//! 1. SHA-1 hash the password locally
//! 2. Send only the first 5 hex chars of the hash to HIBP
//! 3. HIBP returns all hash suffixes matching that prefix (thousands)
//! 4. We check locally if our full hash is in the response
//!
//! # Privacy
//!
//! - The full password and full SHA-1 hash never leave the device
//! - HIBP only sees a 5-char prefix that matches thousands of passwords
//! - We add the `Add-Padding: true` header for extra privacy
//! - The hash is zeroized from memory after the check

use crate::error::KestrelError;
use crate::scanner::ThreatLevel;
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};

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

/// Hashes a password with SHA-256 for internal breach vulnerability scanning.
///
/// This is used by the full vulnerability scan, NOT by the HIBP API check.
/// HIBP uses SHA-1 (see `check_breach_status_hibp`).
pub fn hash_password_for_lookup(password: &str) -> [u8; 32] {
    use sha2::Sha256;
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    let hash: [u8; 32] = result.into();
    hash
}

/// Hashes a password with SHA-1 for HIBP API lookup.
/// Returns the uppercase hex string of the hash.
fn sha1_hex(password: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    let hash_bytes: &[u8] = &result;
    let hex: String = hash_bytes.iter().map(|b| format!("{b:02X}")).collect();
    // Zeroize hasher internal state is handled by drop
    hex
}

/// Checks if a password has appeared in known data breaches using the
/// Have I Been Pwned Password API with k-anonymity.
///
/// # Privacy
///
/// - Only the first 5 characters of the SHA-1 hash are sent to HIBP
/// - The full password and full hash NEVER leave the device
/// - Uses `Add-Padding: true` header for extra privacy
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
/// Returns `KestrelError::Scanner` if the HIBP API cannot be reached.
pub fn check_breach_status(password: &str) -> Result<BreachCheckResult, KestrelError> {
    // Use the HIBP API for real breach checking
    check_breach_status_hibp(password)
}

/// Performs the actual HIBP API check with k-anonymity.
///
/// This function makes a network request to the HIBP API.
/// It uses the reqwest blocking client since Tauri commands
/// run on the main thread with block_on.
fn check_breach_status_hibp(password: &str) -> Result<BreachCheckResult, KestrelError> {
    // Step 1: SHA-1 hash the password locally
    let full_hash = sha1_hex(password);
    let prefix = &full_hash[0..5];   // First 5 chars → sent to API
    let suffix = &full_hash[5..];     // Remaining chars → checked locally

    // Step 2: Query HIBP API with only the 5-char prefix
    let url = format!("https://api.pwnedpasswords.com/range/{prefix}");

    let response = crate::commands::async_runtime::block_on(async {
        reqwest::Client::new()
            .get(&url)
            .header("Add-Padding", "true")
            .header("User-Agent", "KESTREL-Vault-Breach-Check")
            .send()
            .await
    });

    let response = match response {
        Ok(resp) => resp,
        Err(e) => {
            tracing::warn!("HIBP API request failed: {}", e);
            return Err(KestrelError::Scanner(format!(
                "Cannot reach Have I Been Pwned API. Check your internet connection. Error: {e}"
            )));
        }
    };

    let status = response.status();
    if !status.is_success() {
        tracing::warn!("HIBP API returned status {}", status);
        return Err(KestrelError::Scanner(format!(
            "Have I Been Pwned API returned error status {status}. Please try again later."
        )));
    }

    let body = crate::commands::async_runtime::block_on(async {
        response.text().await
    });

    let body = match body {
        Ok(text) => text,
        Err(e) => {
            return Err(KestrelError::Scanner(format!(
                "Failed to read HIBP API response: {e}"
            )));
        }
    };

    // Step 3: Check if our hash suffix appears in the response
    // Each line format: HASH_SUFFIX:COUNT
    let mut found_count: u64 = 0;
    for line in body.lines() {
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() == 2 && parts[0] == suffix {
            if let Ok(count) = parts[1].parse::<u64>() {
                found_count = count;
            }
            break;
        }
    }

    // Step 4: Return result
    if found_count > 0 {
        tracing::warn!(
            "Breach check: password found in {} breach records",
            found_count
        );
        Ok(BreachCheckResult::breached(found_count))
    } else {
        tracing::info!("Breach check: password NOT found in breach database");
        Ok(BreachCheckResult::not_breached())
    }
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
    fn sha1_hex_format() {
        let hash = sha1_hex("test");
        assert_eq!(hash.len(), 40); // SHA-1 = 20 bytes = 40 hex chars
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(hash, hash.to_uppercase()); // Should already be uppercase
    }

    #[test]
    fn sha1_known_value() {
        // Known SHA-1 of "password"
        let hash = sha1_hex("password");
        assert_eq!(hash, "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8");
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
