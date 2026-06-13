//! Secure random number generation module.
//!
//! Provides cryptographically secure random generation using
//! the operating system's CSPRNG (`rand::rngs::OsRng`).
//!
//! # Security
//!
//! - All randomness comes from `OsRng` — the OS-provided CSPRNG
//! - No user-space PRNGs or deterministic generation
//! - Thread-safe access to the random provider
//! - All generated values are suitable for cryptographic use

use crate::error::KestrelError;
use crate::crypto::kdf::Salt;
use crate::crypto::cipher::Nonce;
use rand::RngCore;
use uuid::Uuid;

/// Fills a byte buffer with cryptographically secure random bytes.
///
/// Uses the operating system's CSPRNG to generate random data.
/// Suitable for generating salts, nonces, keys, and any other
/// cryptographic material.
///
/// # Errors
///
/// Returns `KestrelError::Crypto` if the system random number
/// generator fails, which indicates a serious system-level problem.
pub fn random_bytes(buf: &mut [u8]) -> Result<(), KestrelError> {
    OsRng.try_fill_bytes(buf)
        .map_err(|e| KestrelError::Crypto(format!("RNG failure: {e}")))?;
    Ok(())
}

/// Generates a cryptographically random salt for key derivation.
///
/// # Errors
///
/// Returns an error if the system RNG fails.
pub fn random_salt() -> Result<Salt, KestrelError> {
    Salt::generate()
}

/// Generates a cryptographically random nonce for AES-256-GCM.
///
/// Each encryption operation MUST use a unique nonce.
/// The probability of nonce collision is negligible with 96-bit nonces.
///
/// # Errors
///
/// Returns an error if the system RNG fails.
pub fn random_nonce() -> Result<Nonce, KestrelError> {
    let mut bytes = [0u8; 12];
    random_bytes(&mut bytes)?;
    Ok(Nonce(bytes))
}

/// Generates a random UUID (version 4) using the operating system's CSPRNG.
///
/// Suitable for generating unique identifiers for vault entries,
/// audit events, and other entities.
///
/// # Errors
///
/// Returns an error if the system RNG fails.
pub fn random_uuid() -> Result<Uuid, KestrelError> {
    let mut bytes = [0u8; 16];
    random_bytes(&mut bytes)?;
    // Set version 4 and variant bits per RFC 4122
    bytes[6] = (bytes[6] & 0x0F) | 0x40; // Version 4
    bytes[8] = (bytes[8] & 0x3F) | 0x80; // Variant 1
    Ok(Uuid::from_bytes(bytes))
}

/// Generates a vector of cryptographically random bytes.
///
/// Convenience function for when you need a specific number
/// of random bytes as a `Vec<u8>`.
///
/// # Errors
///
/// Returns an error if the system RNG fails.
pub fn random_vec(len: usize) -> Result<Vec<u8>, KestrelError> {
    let mut buf = vec![0u8; len];
    random_bytes(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_bytes_differ() -> Result<(), KestrelError> {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        random_bytes(&mut a)?;
        random_bytes(&mut b)?;
        assert_ne!(a, b);
        Ok(())
    }

    #[test]
    fn random_salt_differ() -> Result<(), KestrelError> {
        let s1 = random_salt()?;
        let s2 = random_salt()?;
        assert_ne!(s1.0, s2.0);
        Ok(())
    }

    #[test]
    fn random_nonce_differ() -> Result<(), KestrelError> {
        let n1 = random_nonce()?;
        let n2 = random_nonce()?;
        assert_ne!(n1.0, n2.0);
        Ok(())
    }

    #[test]
    fn random_uuid_valid() -> Result<(), KestrelError> {
        let uuid = random_uuid()?;
        assert_eq!(uuid.get_version(), Some(uuid::Version::Random));
        Ok(())
    }

    #[test]
    fn random_vec_length() -> Result<(), KestrelError> {
        let v = random_vec(64)?;
        assert_eq!(v.len(), 64);
        Ok(())
    }
}
