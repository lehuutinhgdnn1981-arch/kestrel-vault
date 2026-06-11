//! Rate limiting for KESTREL Vault operations.
//!
//! This module provides per-operation rate limiting to prevent
//! automated attacks and abuse. Each operation type has its own
//! configurable threshold and tracking.
//!
//! # Operation Types
//!
//! - **Login**: Authentication attempts — strictest limits
//! - **Command**: General vault commands — moderate limits
//! - **FileOperation**: Import/export operations — relaxed limits
//!
//! # Sliding Window
//!
//! Rate limiting uses a sliding window algorithm: within the
//! configured time window, only `max_attempts` operations are
//! allowed. The window slides forward as time passes.
//!
//! # TODO
//!
//! - Implement actual sliding window with timestamp tracking
//! - Add configurable window duration per operation
//! - Add persistent rate-limit counters (survive restarts)
//! - Add metrics/telemetry for rate-limit events

use crate::error::{KestrelError, KestrelResult};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

/// The type of operation being rate-limited.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Operation {
    /// Authentication / login attempts.
    Login,
    /// General vault commands (CRUD operations).
    Command,
    /// File import/export operations.
    FileOperation,
}

impl Operation {
    /// Returns the default maximum attempts per window for this operation.
    pub fn default_max_attempts(&self) -> u32 {
        match self {
            Operation::Login => 5,
            Operation::Command => 60,
            Operation::FileOperation => 20,
        }
    }

    /// Returns the default window duration in seconds.
    pub fn default_window_seconds(&self) -> u64 {
        match self {
            Operation::Login => 300,
            Operation::Command => 60,
            Operation::FileOperation => 60,
        }
    }
}

/// Tracks timestamps of recent operations for sliding window rate limiting.
#[derive(Debug, Clone)]
struct OperationTracker {
    /// Timestamps of recent operations within the current window.
    timestamps: Vec<DateTime<Utc>>,
    /// Maximum operations allowed in the window.
    max_attempts: u32,
    /// Window duration in seconds.
    window_seconds: u64,
}

impl OperationTracker {
    /// Creates a new tracker with the given limits.
    fn new(max_attempts: u32, window_seconds: u64) -> Self {
        Self {
            timestamps: Vec::new(),
            max_attempts,
            window_seconds,
        }
    }

    /// Removes timestamps outside the current sliding window.
    fn prune(&mut self) {
        let cutoff = Utc::now() - chrono::Duration::seconds(self.window_seconds as i64);
        self.timestamps.retain(|&ts| ts > cutoff);
    }

    /// Records a new operation attempt.
    fn record(&mut self) {
        self.timestamps.push(Utc::now());
    }

    /// Returns whether the operation is currently rate-limited.
    fn is_limited(&self) -> bool {
        self.timestamps.len() as u32 >= self.max_attempts
    }

    /// Returns the number of attempts remaining in the current window.
    fn remaining(&self) -> u32 {
        self.max_attempts.saturating_sub(self.timestamps.len() as u32)
    }
}

/// Per-operation rate limiter using sliding windows.
///
/// Each `Operation` variant has independent rate tracking with
/// configurable thresholds. The limiter is not thread-safe —
/// callers should wrap in a `Mutex` if needed.
///
/// # Example
///
/// ```ignore
/// let mut limiter = RateLimiter::new();
/// if limiter.is_rate_limited(Operation::Login) {
///     return Err(KestrelError::Unauthorized("Rate limited".into()));
/// }
/// limiter.record_attempt(Operation::Login)?;
/// ```
pub struct RateLimiter {
    /// Per-operation tracking data.
    trackers: HashMap<Operation, OperationTracker>,
}

impl RateLimiter {
    /// Creates a new rate limiter with default thresholds.
    pub fn new() -> Self {
        let mut trackers = HashMap::new();
        trackers.insert(
            Operation::Login,
            OperationTracker::new(
                Operation::Login.default_max_attempts(),
                Operation::Login.default_window_seconds(),
            ),
        );
        trackers.insert(
            Operation::Command,
            OperationTracker::new(
                Operation::Command.default_max_attempts(),
                Operation::Command.default_window_seconds(),
            ),
        );
        trackers.insert(
            Operation::FileOperation,
            OperationTracker::new(
                Operation::FileOperation.default_max_attempts(),
                Operation::FileOperation.default_window_seconds(),
            ),
        );
        Self { trackers }
    }

    /// Creates a rate limiter with custom thresholds for an operation.
    pub fn with_custom_limit(
        operation: Operation,
        max_attempts: u32,
        window_seconds: u64,
    ) -> Self {
        let mut limiter = Self::new();
        if let Some(tracker) = limiter.trackers.get_mut(&operation) {
            tracker.max_attempts = max_attempts;
            tracker.window_seconds = window_seconds;
        }
        limiter
    }

    /// Checks whether the given operation is currently rate-limited.
    ///
    /// Returns `true` if the operation has exceeded its maximum
    /// attempts within the sliding window. Callers should check
    /// this **before** performing the operation.
    pub fn is_rate_limited(&mut self, operation: Operation) -> bool {
        if let Some(tracker) = self.trackers.get_mut(&operation) {
            tracker.prune();
            tracker.is_limited()
        } else {
            false
        }
    }

    /// Records an attempt for the given operation.
    ///
    /// Call this after a successful or failed operation to count
    /// it against the rate limit.
    ///
    /// # Errors
    ///
    /// Returns `KestrelError::Unauthorized` if the operation is
    /// currently rate-limited.
    pub fn record_attempt(&mut self, operation: Operation) -> KestrelResult<()> {
        if self.is_rate_limited(operation) {
            return Err(KestrelError::Unauthorized(format!(
                "Rate limit exceeded for {:?}",
                operation
            )));
        }
        if let Some(tracker) = self.trackers.get_mut(&operation) {
            tracker.record();
        }
        Ok(())
    }

    /// Returns the number of remaining attempts for an operation.
    pub fn remaining_attempts(&mut self, operation: Operation) -> u32 {
        if let Some(tracker) = self.trackers.get_mut(&operation) {
            tracker.prune();
            tracker.remaining()
        } else {
            u32::MAX
        }
    }

    /// Resets all rate limit counters.
    ///
    /// This clears all tracked timestamps, allowing all operations
    /// to proceed immediately. Use after a successful authentication
    /// or administrator action.
    pub fn reset(&mut self) {
        for tracker in self.trackers.values_mut() {
            tracker.timestamps.clear();
        }
    }

    /// Resets the rate limit for a specific operation.
    pub fn reset_operation(&mut self, operation: Operation) {
        if let Some(tracker) = self.trackers.get_mut(&operation) {
            tracker.timestamps.clear();
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_limiter_is_not_limited() {
        let mut limiter = RateLimiter::new();
        assert!(!limiter.is_rate_limited(Operation::Login));
        assert!(!limiter.is_rate_limited(Operation::Command));
        assert!(!limiter.is_rate_limited(Operation::FileOperation));
    }

    #[test]
    fn rate_limit_triggers_after_max_attempts() {
        let mut limiter = RateLimiter::with_custom_limit(Operation::Login, 2, 300);
        assert!(limiter.record_attempt(Operation::Login).is_ok());
        assert!(limiter.record_attempt(Operation::Login).is_ok());
        assert!(limiter.is_rate_limited(Operation::Login));
    }

    #[test]
    fn record_attempt_fails_when_limited() {
        let mut limiter = RateLimiter::with_custom_limit(Operation::Login, 1, 300);
        assert!(limiter.record_attempt(Operation::Login).is_ok());
        let result = limiter.record_attempt(Operation::Login);
        assert!(result.is_err());
    }

    #[test]
    fn reset_clears_all_limits() {
        let mut limiter = RateLimiter::with_custom_limit(Operation::Login, 1, 300);
        limiter.record_attempt(Operation::Login).unwrap();
        assert!(limiter.is_rate_limited(Operation::Login));
        limiter.reset();
        assert!(!limiter.is_rate_limited(Operation::Login));
    }

    #[test]
    fn operations_are_independent() {
        let mut limiter = RateLimiter::with_custom_limit(Operation::Login, 1, 300);
        limiter.record_attempt(Operation::Login).unwrap();
        assert!(limiter.is_rate_limited(Operation::Login));
        assert!(!limiter.is_rate_limited(Operation::Command));
    }

    #[test]
    fn remaining_attempts_decreases() {
        let mut limiter = RateLimiter::with_custom_limit(Operation::Login, 3, 300);
        assert_eq!(limiter.remaining_attempts(Operation::Login), 3);
        limiter.record_attempt(Operation::Login).unwrap();
        assert_eq!(limiter.remaining_attempts(Operation::Login), 2);
    }
}
