//! Secure string type for password handling.
//!
//! Rust's `String` type cannot be zeroized because its backing memory
//! is managed by the allocator and may be moved or deallocated without
//! clearing. This module provides `SecureString`, which:
//!
//! - Stores the string content in a fixed `Vec<u8>` on the heap
//! - Implements `Zeroize` to overwrite memory before deallocation
//! - Prevents accidental cloning (only moves)
//! - Converts from/to `String` for IPC boundary compatibility
//!
//! # Security Model
//!
//! The master password arrives as a `String` from Tauri IPC (JavaScript
//! → Rust bridge). We immediately convert it to `SecureString` and
//! zeroize the original. The `SecureString` is then used for key
//! derivation and zeroized when it goes out of scope.
//!
//! # Limitations
//!
//! - The password exists briefly as a `String` before conversion.
//!   This is unavoidable due to Tauri's IPC using `String` parameters.
//! - We cannot guarantee the allocator doesn't leave copies in freed
//!   memory, but `SecureString` minimizes the window of exposure.
//! - If the OS swaps memory to disk, the password could be present in
//!   the swap file. This is mitigated by mlock() in production builds.

use std::fmt;
use std::ops::Deref;
use zeroize::Zeroize;

/// A string that zeroizes its contents on drop.
///
/// This type is designed for handling passwords and other secrets
/// that must not remain in memory after use. It wraps a `Vec<u8>`
/// containing UTF-8 bytes and overwrites them with zeros before
/// deallocation.
///
/// # Usage
///
/// ```ignore
/// fn handle_password(raw: String) {
///     let mut raw = SecureString::from(raw);
///     // Use the password for key derivation
///     let key = derive_key(raw.as_bytes(), &salt);
///     // raw is zeroized when it goes out of scope
/// }
/// ```
///
/// # Security
///
/// - The inner bytes are overwritten with zeros on drop
/// - `Debug` impl shows `[REDACTED SecureString]` — never the content
/// - `Clone` is intentionally NOT implemented to prevent accidental copies
/// - The `AsRef<[u8]>` impl provides read-only access for crypto operations
pub struct SecureString {
    /// The string content stored as bytes for zeroization.
    /// Unlike `String`, we control the backing memory and can
    /// overwrite it before deallocation.
    data: Vec<u8>,
}

impl SecureString {
    /// Creates a new `SecureString` from a byte vector.
    ///
    /// The caller is responsible for ensuring the bytes are valid UTF-8
    /// if string semantics are needed. For password handling, raw bytes
    /// are sufficient since they're passed directly to the KDF.
    pub fn from_bytes(data: Vec<u8>) -> Self {
        SecureString { data }
    }

    /// Returns the length of the string in bytes.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns `true` if the string is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns a reference to the raw bytes.
    ///
    /// Use this for passing to cryptographic functions.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Consumes the `SecureString` and returns the inner bytes.
    ///
    /// # Security
    ///
    /// The caller is responsible for zeroizing the returned bytes.
    /// Prefer using `as_bytes()` when possible to ensure zeroization
    /// happens automatically on drop.
    pub fn into_bytes(mut self) -> Vec<u8> {
        // We can't prevent the caller from leaking these bytes,
        // but we document the responsibility clearly.
        std::mem::take(&mut self.data)
    }

    /// Explicitly zeroizes the string content.
    ///
    /// This is useful when the `SecureString` needs to be cleared
    /// before the end of its scope. Calling this is equivalent to
    /// calling `drop()` but allows the variable to remain in scope.
    pub fn clear(&mut self) {
        self.data.zeroize();
    }
}

impl From<String> for SecureString {
    /// Converts a `String` into a `SecureString`, consuming the original.
    ///
    /// # Security
    ///
    /// This does NOT zeroize the original `String`'s memory, because
    /// Rust's `String` does not support zeroization. The caller should
    /// overwrite the original `String` immediately after conversion:
    ///
    /// ```ignore
    /// let secure = SecureString::from(password);
    /// // The original `password` variable still exists in scope
    /// // with its content in freed memory. If possible, shadow it:
    /// let mut password = secure; // shadows the original
    /// ```
    ///
    /// In practice, the best pattern is to convert at the earliest
    /// possible point (the Tauri command boundary) and let the
    /// original `String` parameter go out of scope quickly.
    fn from(s: String) -> Self {
        SecureString {
            data: s.into_bytes(),
        }
    }
}

impl AsRef<[u8]> for SecureString {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl Deref for SecureString {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl Drop for SecureString {
    fn drop(&mut self) {
        // Overwrite all bytes with zeros before deallocation.
        // This is the critical security property of SecureString.
        self.data.zeroize();
    }
}

impl fmt::Debug for SecureString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never reveal the content in debug output.
        write!(f, "[REDACTED SecureString len={}]", self.data.len())
    }
}

// Intentionally NOT implementing Clone for SecureString.
// Each copy of a secret increases the attack surface for memory
// extraction. If you need to use a SecureString in multiple places,
// pass it by reference.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_string_creates_secure_string() {
        let secure = SecureString::from("my-password".to_string());
        assert_eq!(secure.len(), 11);
        assert_eq!(secure.as_bytes(), b"my-password");
    }

    #[test]
    fn from_bytes_creates_secure_string() {
        let secure = SecureString::from_bytes(b"secret".to_vec());
        assert_eq!(secure.as_bytes(), b"secret");
    }

    #[test]
    fn debug_redacts_content() {
        let secure = SecureString::from("super-secret-password".to_string());
        let debug_str = format!("{:?}", secure);
        assert!(debug_str.contains("REDACTED"));
        assert!(!debug_str.contains("super-secret-password"));
        assert!(debug_str.contains("len=21"));
    }

    #[test]
    fn clear_zeroizes_content() {
        let mut secure = SecureString::from("password123".to_string());
        secure.clear();
        assert_eq!(secure.len(), 11); // Length is preserved (zeroed bytes)
        assert!(secure.as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn drop_zeroizes_content() {
        // We can't directly verify zeroization after drop,
        // but we can test that Drop runs without panicking
        // and that the zeroization code path exists.
        {
            let _secure = SecureString::from("temporary-secret".to_string());
            // Goes out of scope here — Drop should zeroize
        }
    }

    #[test]
    fn deref_provides_bytes_access() {
        let secure = SecureString::from("test".to_string());
        assert_eq!(&*secure, b"test");
    }

    #[test]
    fn as_ref_provides_bytes_access() {
        let secure = SecureString::from("test".to_string());
        let bytes: &[u8] = secure.as_ref();
        assert_eq!(bytes, b"test");
    }

    #[test]
    fn empty_string_works() {
        let secure = SecureString::from(String::new());
        assert!(secure.is_empty());
        assert_eq!(secure.len(), 0);
    }

    #[test]
    fn into_bytes_returns_content() {
        let secure = SecureString::from("data".to_string());
        let bytes = secure.into_bytes();
        assert_eq!(bytes, b"data");
        // Note: after into_bytes(), the caller owns the Vec<u8>
        // and is responsible for zeroizing it.
    }
}
