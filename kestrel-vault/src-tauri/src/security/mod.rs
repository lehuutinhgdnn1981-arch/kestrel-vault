//! Security module for KESTREL Vault.
//!
//! This module provides session management, rate limiting, and
//! account lockout functionality to protect the vault against
//! brute-force attacks, credential stuffing, and unauthorized access.
//!
//! # Security Model
//!
//! The security layer operates on a defense-in-depth principle:
//!
//! 1. **Session Management** — After successful authentication, a
//!    time-bounded session is created. Sessions track activity for
//!    auto-lock and expire after a configurable timeout. Sessions
//!    never store keys or passwords.
//!
//! 2. **Rate Limiting** — Per-operation rate limits prevent automated
//!    attacks. Login attempts, commands, and file operations each
//!    have independent thresholds and sliding windows.
//!
//! 3. **Account Lockout** — Progressive lockout with exponential
//!    backoff deters brute-force password attacks:
//!    - 1–3 failures: immediate retry allowed
//!    - 4–5 failures: exponential delay before retry
//!    - 6+ failures: full lockout requiring vault reset
//!
//! # Threat Model
//!
//! These protections guard against:
//! - **Online brute-force**: Rate limits and lockout slow attempts
//! - **Credential stuffing**: Lockout after few failures
//! - **Session hijacking**: Sessions expire and auto-lock
//! - **Automated tooling**: Per-operation rate limits
//!
//! They do **not** protect against:
//! - Offline attacks on the encrypted database
//! - Compromised master password
//! - Malware on the host system

pub mod lockout;
pub mod rate_limit;
pub mod session;

// Re-export key types for convenience
pub use lockout::{FailedAttemptTracker, LockoutState};
pub use rate_limit::{Operation, RateLimiter};
pub use session::{Session, SessionId, SessionState};
