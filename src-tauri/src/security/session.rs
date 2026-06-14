//! Session management for KESTREL Vault.
//!
//! This module defines the session lifecycle after a successful
//! vault unlock. Sessions are time-bounded and track user activity
//! for auto-lock enforcement.
//!
//! # Key Design Decisions
//!
//! - **No secrets in sessions**: A session never stores keys,
//!   passwords, or derived key material. It is purely a state
//!   token that the UI layer uses to know the vault is unlocked.
//! - **Auto-lock**: If `last_activity` exceeds the configured
//!   timeout, the session is considered expired and the vault
//!   must be re-unlocked.
//! - **UUID-based IDs**: Session IDs are random UUIDs, not
//!   sequential — preventing session prediction attacks.

use crate::error::{KestrelError, KestrelResult};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique identifier for a vault session.
///
/// Uses the newtype pattern to prevent mixing session IDs with
/// other UUID types. Generated using UUID v4 (random).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub Uuid);

impl SessionId {
    /// Generates a new random session ID.
    ///
    /// Uses `uuid::Uuid::new_v4()` for cryptographically random
    /// session identifiers.
    pub fn generate() -> Self {
        Self(Uuid::new_v4())
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The lock state of a vault session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    /// The vault is locked — no data accessible.
    Locked,
    /// The vault is unlocked — data accessible.
    Unlocked,
}

/// A vault session representing an active unlock period.
///
/// Sessions are created after successful authentication and
/// track activity timestamps for auto-lock enforcement.
///
/// # Security
///
/// The session struct intentionally contains **no key material**
/// or passwords. It is a state-tracking mechanism only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Unique session identifier.
    id: SessionId,
    /// Current lock state.
    state: SessionState,
    /// When this session was created.
    created_at: DateTime<Utc>,
    /// When the user last performed an action.
    last_activity: DateTime<Utc>,
    /// When this session expires (absolute time).
    expires_at: DateTime<Utc>,
}

impl Session {
    /// Creates a new unlocked session with the given timeout.
    ///
    /// The session starts in `SessionState::Unlocked` with
    /// `last_activity` set to now. The `timeout_minutes` parameter
    /// controls how long the session remains active without
    /// user interaction.
    ///
    /// # Arguments
    ///
    /// * `timeout_minutes` - Minutes of inactivity before auto-lock
    ///
    /// # Errors
    ///
    /// Returns an error if `timeout_minutes` is 0.
    pub fn new(timeout_minutes: u32) -> KestrelResult<Self> {
        if timeout_minutes == 0 {
            return Err(KestrelError::Validation(
                "Session timeout must be at least 1 minute".to_string(),
            ));
        }
        let now = Utc::now();
        Ok(Self {
            id: SessionId::generate(),
            state: SessionState::Unlocked,
            created_at: now,
            last_activity: now,
            expires_at: now + chrono::Duration::minutes(timeout_minutes as i64),
        })
    }

    /// Returns the session's unique identifier.
    pub fn id(&self) -> &SessionId {
        &self.id
    }

    /// Returns the current lock state.
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Returns when this session was created.
    pub fn created_at(&self) -> &DateTime<Utc> {
        &self.created_at
    }

    /// Returns when the user last performed an action.
    pub fn last_activity(&self) -> &DateTime<Utc> {
        &self.last_activity
    }

    /// Returns when this session expires.
    pub fn expires_at(&self) -> &DateTime<Utc> {
        &self.expires_at
    }

    /// Validates whether the session is still active.
    ///
    /// A session is valid if it is `Unlocked` and the current
    /// time is before `expires_at`. If the session has expired,
    /// its state is set to `Locked`.
    pub fn validate(&mut self) -> bool {
        if self.state == SessionState::Locked {
            return false;
        }
        if Utc::now() > self.expires_at {
            self.state = SessionState::Locked;
            return false;
        }
        true
    }

    /// Records user activity, extending the session expiry.
    ///
    /// This is the "touch" operation — it updates `last_activity`
    /// to now and recalculates `expires_at` based on the
    /// configured timeout.
    ///
    /// # Arguments
    ///
    /// * `timeout_minutes` - The auto-lock timeout in minutes
    ///
    /// # Errors
    ///
    /// Returns an error if the session is already locked.
    pub fn touch(&mut self, timeout_minutes: u32) -> KestrelResult<()> {
        if self.state == SessionState::Locked {
            return Err(KestrelError::Unauthorized(
                "Cannot update a locked session".to_string(),
            ));
        }
        let now = Utc::now();
        self.last_activity = now;
        self.expires_at = now + chrono::Duration::minutes(timeout_minutes as i64);
        Ok(())
    }

    /// Locks the session immediately.
    ///
    /// After calling this, `validate()` will return `false`
    /// and `touch()` will return an error.
    pub fn lock(&mut self) {
        self.state = SessionState::Locked;
    }

    /// Checks whether the auto-lock timeout has been exceeded.
    ///
    /// Unlike `validate()`, this does **not** mutate the session.
    /// It returns `true` if the session should be auto-locked
    /// based on the elapsed time since `last_activity`.
    ///
    /// # Arguments
    ///
    /// * `timeout_minutes` - The auto-lock timeout in minutes
    pub fn is_auto_lock_triggered(&self, timeout_minutes: u32) -> bool {
        if self.state == SessionState::Locked {
            return true;
        }
        let elapsed = Utc::now() - self.last_activity;
        elapsed > chrono::Duration::minutes(timeout_minutes as i64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_session_is_unlocked() -> KestrelResult<()> {
        let session = Session::new(15)?;
        assert_eq!(session.state(), SessionState::Unlocked);
        Ok(())
    }

    #[test]
    fn new_session_rejects_zero_timeout() {
        let result = Session::new(0);
        assert!(result.is_err());
    }

    #[test]
    fn touch_updates_activity() -> KestrelResult<()> {
        let mut session = Session::new(15)?;
        let before = *session.last_activity();
        // Small sleep to ensure time difference
        std::thread::sleep(std::time::Duration::from_millis(10));
        session.touch(15)?;
        assert!(*session.last_activity() > before);
        Ok(())
    }

    #[test]
    fn lock_prevents_touch() -> KestrelResult<()> {
        let mut session = Session::new(15)?;
        session.lock();
        assert_eq!(session.state(), SessionState::Locked);
        let result = session.touch(15);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn locked_session_fails_validation() -> KestrelResult<()> {
        let mut session = Session::new(15)?;
        session.lock();
        assert!(!session.validate());
        Ok(())
    }

    #[test]
    fn session_id_is_unique() -> KestrelResult<()> {
        let s1 = Session::new(15)?;
        let s2 = Session::new(15)?;
        assert_ne!(s1.id(), s2.id());
        Ok(())
    }
}
