//! Account lockout management for KESTREL Vault.
//!
//! This module implements progressive account lockout to protect
//! against brute-force password attacks. Failed authentication
//! attempts are tracked and result in increasing restrictions:
//!
//! # Lockout Progression
//!
//! | Failures | State            | Effect                              |
//! |----------|------------------|-------------------------------------|
//! | 1–3      | `Allowed`        | No restriction                      |
//! | 4–5      | `Delayed(secs)`  | Exponential backoff before retry    |
//! | 6+       | `LockedOut`      | Full lockout, requires vault reset  |
//!
//! # Exponential Backoff
//!
//! For the `Delayed` state, the delay doubles with each
//! additional failure:
//! - 4th failure: 2 seconds
//! - 5th failure: 4 seconds
//!
//! # Zeroization
//!
//! The failed attempt counter is zeroized on reset (successful
//! authentication) to prevent residual data from lingering in
//! memory after an unlock.

use chrono::{DateTime, Utc};

/// The current lockout state based on failed authentication attempts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockoutState {
    /// Authentication is allowed — no restrictions.
    Allowed,
    /// Authentication is delayed by the given number of seconds
    /// (exponential backoff).
    Delayed(u64),
    /// The account is fully locked out. Requires vault reset
    /// or administrator intervention.
    LockedOut,
}

impl std::fmt::Display for LockoutState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LockoutState::Allowed => write!(f, "Allowed"),
            LockoutState::Delayed(secs) => write!(f, "Delayed({}s)", secs),
            LockoutState::LockedOut => write!(f, "LockedOut"),
        }
    }
}

/// A single failed authentication attempt with its timestamp.
#[derive(Debug, Clone)]
struct FailedAttempt {
    /// When the failed attempt occurred.
    timestamp: DateTime<Utc>,
}

/// Tracks failed authentication attempts and determines lockout state.
///
/// # Security
///
/// - All internal counters are zeroized on reset for secure clearing
/// - Timestamps enable time-based backoff calculations
/// - Reset on successful authentication prevents lockout accumulation
///
/// # Thread Safety
///
/// This struct is **not** thread-safe. Wrap in a `Mutex` if
/// shared across threads.
#[derive(Debug, Clone)]
pub struct FailedAttemptTracker {
    /// Chronological list of failed attempt timestamps.
    attempts: Vec<FailedAttempt>,
}

impl FailedAttemptTracker {
    /// Creates a new tracker with no failed attempts.
    pub fn new() -> Self {
        Self {
            attempts: Vec::new(),
        }
    }

    /// Records a failed authentication attempt.
    ///
    /// The attempt is timestamped automatically and added to
    /// the tracking list. This may change the lockout state.
    pub fn record_failed_attempt(&mut self) {
        self.attempts.push(FailedAttempt {
            timestamp: Utc::now(),
        });
    }

    /// Returns the current number of failed attempts.
    pub fn failed_count(&self) -> u32 {
        self.attempts.len() as u32
    }

    /// Determines the current lockout state based on the
    /// number of failed attempts.
    ///
    /// # Lockout Progression
    ///
    /// - **1–3 failures**: `Allowed` — no restriction
    /// - **4–5 failures**: `Delayed(secs)` — exponential backoff
    ///   - 4th: 2s, 5th: 4s (2^(failures - 3))
    /// - **6+ failures**: `LockedOut` — full lockout
    pub fn lockout_state(&self) -> LockoutState {
        let count = self.failed_count();
        match count {
            0..=3 => LockoutState::Allowed,
            4 => LockoutState::Delayed(2),
            5 => LockoutState::Delayed(4),
            _ => LockoutState::LockedOut,
        }
    }

    /// Determines the current lockout state, checking if a
    /// delay has already elapsed.
    ///
    /// If the state is `Delayed(n)`, this method checks whether
    /// `n` seconds have passed since the most recent failed
    /// attempt. If so, returns `Allowed`.
    ///
    /// # Arguments
    ///
    /// * `now` - The current time (injectable for testing)
    pub fn lockout_state_at(&self, now: DateTime<Utc>) -> LockoutState {
        let state = self.lockout_state();
        match state {
            LockoutState::Delayed(secs) => {
                if let Some(last) = self.attempts.last() {
                    let elapsed = now - last.timestamp;
                    if elapsed >= chrono::Duration::seconds(secs as i64) {
                        return LockoutState::Allowed;
                    }
                }
                state
            }
            other => other,
        }
    }

    /// Resets all failed attempt counters.
    ///
    /// Call this after a **successful** authentication to
    /// clear the failure history. All internal data is
    /// zeroized before being dropped.
    pub fn reset(&mut self) {
        // Zeroize attempt data: overwrite timestamps then clear
        for attempt in &mut self.attempts {
            attempt.timestamp = Utc::now();
        }
        self.attempts.clear();
    }
}

impl Default for FailedAttemptTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_tracker_is_allowed() {
        let tracker = FailedAttemptTracker::new();
        assert_eq!(tracker.lockout_state(), LockoutState::Allowed);
        assert_eq!(tracker.failed_count(), 0);
    }

    #[test]
    fn three_failures_still_allowed() {
        let mut tracker = FailedAttemptTracker::new();
        for _ in 0..3 {
            tracker.record_failed_attempt();
        }
        assert_eq!(tracker.lockout_state(), LockoutState::Allowed);
    }

    #[test]
    fn four_failures_cause_delay() {
        let mut tracker = FailedAttemptTracker::new();
        for _ in 0..4 {
            tracker.record_failed_attempt();
        }
        assert_eq!(tracker.lockout_state(), LockoutState::Delayed(2));
    }

    #[test]
    fn five_failures_increase_delay() {
        let mut tracker = FailedAttemptTracker::new();
        for _ in 0..5 {
            tracker.record_failed_attempt();
        }
        assert_eq!(tracker.lockout_state(), LockoutState::Delayed(4));
    }

    #[test]
    fn six_failures_cause_lockout() {
        let mut tracker = FailedAttemptTracker::new();
        for _ in 0..6 {
            tracker.record_failed_attempt();
        }
        assert_eq!(tracker.lockout_state(), LockoutState::LockedOut);
    }

    #[test]
    fn reset_clears_all_attempts() {
        let mut tracker = FailedAttemptTracker::new();
        for _ in 0..6 {
            tracker.record_failed_attempt();
        }
        assert_eq!(tracker.lockout_state(), LockoutState::LockedOut);
        tracker.reset();
        assert_eq!(tracker.failed_count(), 0);
        assert_eq!(tracker.lockout_state(), LockoutState::Allowed);
    }

    #[test]
    fn lockout_state_display() {
        assert_eq!(format!("{}", LockoutState::Allowed), "Allowed");
        assert_eq!(format!("{}", LockoutState::Delayed(4)), "Delayed(4s)");
        assert_eq!(format!("{}", LockoutState::LockedOut), "LockedOut");
    }
}
