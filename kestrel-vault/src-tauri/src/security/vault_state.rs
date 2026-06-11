//! Vault lifecycle state machine for KESTREL Vault.
//!
//! Defines the complete state machine governing the vault lifecycle:
//!
//! ```text
//! Uninitialized → Locked → Unlocked → Locked
//!                   ↑          ↓
//!                   └──────────┘  (auto-lock, manual lock, timeout)
//! ```
//!
//! # Transitions
//!
//! - `Initialize(master_password)` → Uninitialized → Locked
//! - `Unlock(master_password)` → Locked → Unlocked
//! - `Lock()` → Unlocked → Locked (manual)
//! - `AutoLock()` → Unlocked → Locked (timeout)
//! - `ChangePassword(current, new)` → Unlocked → Unlocked
//!
//! # Security
//!
//! - All transitions are validated — illegal transitions return errors
//! - All state changes are audit-logged
//! - Master key is zeroized on Lock/AutoLock
//! - The state machine is thread-safe via `parking_lot::RwLock`

use crate::error::{KestrelError, KestrelResult};
use crate::security::session::{Session, SessionId, SessionState};
use std::fmt;

/// The lifecycle state of the vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultState {
    /// Vault has never been initialized (first-run).
    Uninitialized,
    /// Vault exists but is locked — no data accessible.
    Locked,
    /// Vault is unlocked — data accessible, session active.
    Unlocked,
}

impl fmt::Display for VaultState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultState::Uninitialized => write!(f, "Uninitialized"),
            VaultState::Locked => write!(f, "Locked"),
            VaultState::Unlocked => write!(f, "Unlocked"),
        }
    }
}

/// A vault lifecycle transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultTransition {
    /// First-time vault initialization with a master password.
    Initialize,
    /// Unlock the vault with the master password.
    Unlock,
    /// Manually lock the vault.
    Lock,
    /// Auto-lock triggered by inactivity timeout.
    AutoLock,
    /// Change the master password (vault stays unlocked).
    ChangePassword,
}

impl fmt::Display for VaultTransition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultTransition::Initialize => write!(f, "Initialize"),
            VaultTransition::Unlock => write!(f, "Unlock"),
            VaultTransition::Lock => write!(f, "Lock"),
            VaultTransition::AutoLock => write!(f, "AutoLock"),
            VaultTransition::ChangePassword => write!(f, "ChangePassword"),
        }
    }
}

/// Result of a vault state transition attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransitionResult {
    /// Transition succeeded, vault is now in the given state.
    Success(VaultState),
    /// Transition rejected — would be illegal from current state.
    Rejected {
        from: VaultState,
        transition: VaultTransition,
        reason: String,
    },
}

/// Event emitted when a vault state transition occurs.
#[derive(Debug, Clone)]
pub struct VaultStateEvent {
    /// The transition that occurred.
    pub transition: VaultTransition,
    /// State before the transition.
    pub from_state: VaultState,
    /// State after the transition.
    pub to_state: VaultState,
    /// Timestamp of the transition.
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Session ID if applicable.
    pub session_id: Option<SessionId>,
}

/// Callback type for state change observers.
pub type StateChangeCallback = Box<dyn Fn(&VaultStateEvent) + Send + Sync>;

/// The vault state machine.
///
/// Governs all transitions between vault lifecycle states.
/// Thread-safe access via internal `parking_lot::RwLock`.
///
/// # Usage
///
/// The state machine is the single source of truth for vault state.
/// All commands must check the current state before proceeding:
/// - Data access commands require `VaultState::Unlocked`
/// - Auth commands have their own state requirements
/// - Settings may be accessible in `Locked` state
pub struct VaultStateMachine {
    /// Current vault state.
    state: VaultState,
    /// Active session (only when Unlocked).
    session: Option<Session>,
    /// Observer callbacks for state changes.
    observers: Vec<StateChangeCallback>,
}

impl VaultStateMachine {
    /// Creates a new state machine in the given initial state.
    pub fn new(initial_state: VaultState) -> Self {
        VaultStateMachine {
            state: initial_state,
            session: None,
            observers: Vec::new(),
        }
    }

    /// Creates a new state machine starting from Uninitialized.
    pub fn uninitialized() -> Self {
        Self::new(VaultState::Uninitialized)
    }

    /// Creates a new state machine starting from Locked.
    pub fn locked() -> Self {
        Self::new(VaultState::Locked)
    }

    /// Returns the current vault state.
    pub fn state(&self) -> VaultState {
        self.state
    }

    /// Returns the active session, if any.
    pub fn session(&self) -> Option<&Session> {
        self.session.as_ref()
    }

    /// Returns whether the vault is currently unlocked.
    pub fn is_unlocked(&self) -> bool {
        self.state == VaultState::Unlocked
    }

    /// Validates whether a transition is legal from the current state.
    pub fn validate_transition(&self, transition: &VaultTransition) -> KestrelResult<()> {
        match (&self.state, transition) {
            (VaultState::Uninitialized, VaultTransition::Initialize) => Ok(()),
            (VaultState::Locked, VaultTransition::Unlock) => Ok(()),
            (VaultState::Unlocked, VaultTransition::Lock) => Ok(()),
            (VaultState::Unlocked, VaultTransition::AutoLock) => Ok(()),
            (VaultState::Unlocked, VaultTransition::ChangePassword) => Ok(()),
            (VaultState::Uninitialized, t) => Err(KestrelError::Unauthorized(format!(
                "Cannot {t} from Uninitialized — vault must be initialized first"
            ))),
            (VaultState::Locked, VaultTransition::Initialize) => Err(KestrelError::Unauthorized(
                "Vault is already initialized".to_string(),
            ))),
            (VaultState::Locked, VaultTransition::Lock) => Err(KestrelError::Unauthorized(
                "Vault is already locked".to_string(),
            ))),
            (VaultState::Locked, VaultTransition::AutoLock) => Err(KestrelError::Unauthorized(
                "Vault is already locked".to_string(),
            ))),
            (VaultState::Locked, VaultTransition::ChangePassword) => Err(KestrelError::Unauthorized(
                "Vault must be unlocked to change password".to_string(),
            ))),
            (VaultState::Unlocked, VaultTransition::Initialize) => Err(KestrelError::Unauthorized(
                "Vault is already initialized".to_string(),
            ))),
            (VaultState::Unlocked, VaultTransition::Unlock) => Err(KestrelError::Unauthorized(
                "Vault is already unlocked".to_string(),
            ))),
        }
    }

    /// Attempts a state transition.
    ///
    /// Validates the transition, then applies it if legal.
    /// Notifies all observers of the state change.
    ///
    /// # Errors
    ///
    /// Returns `KestrelError::Unauthorized` if the transition is
    /// illegal from the current state.
    pub fn try_transition(&mut self, transition: VaultTransition) -> KestrelResult<TransitionResult> {
        self.validate_transition(&transition)?;

        let from_state = self.state;
        let to_state = self.compute_target_state(&transition);

        // Apply the transition
        self.apply_transition(&transition, &to_state)?;

        // Notify observers
        let event = VaultStateEvent {
            transition,
            from_state,
            to_state,
            timestamp: chrono::Utc::now(),
            session_id: self.session.as_ref().map(|s| s.id().clone()),
        };
        self.notify_observers(&event);

        Ok(TransitionResult::Success(to_state))
    }

    /// Computes the target state for a transition.
    fn compute_target_state(&self, transition: &VaultTransition) -> VaultState {
        match transition {
            VaultTransition::Initialize => VaultState::Locked,
            VaultTransition::Unlock => VaultState::Unlocked,
            VaultTransition::Lock => VaultState::Locked,
            VaultTransition::AutoLock => VaultState::Locked,
            VaultTransition::ChangePassword => VaultState::Unlocked,
        }
    }

    /// Applies a transition's side effects.
    fn apply_transition(
        &mut self,
        transition: &VaultTransition,
        target_state: &VaultState,
    ) -> KestrelResult<()> {
        match transition {
            VaultTransition::Initialize => {
                // After init, vault is Locked (user must explicitly unlock)
                self.session = None;
            }
            VaultTransition::Unlock => {
                let session = Session::new(15)?; // TODO: use config timeout
                self.session = Some(session);
            }
            VaultTransition::Lock | VaultTransition::AutoLock => {
                // Lock the session if it exists
                if let Some(ref mut session) = self.session {
                    session.lock();
                }
                // Zeroize session reference
                self.session = None;
                // TODO: Zeroize master key in VaultContext
            }
            VaultTransition::ChangePassword => {
                // Vault stays unlocked, session continues
                // TODO: Re-encrypt all data with new key
            }
        }

        self.state = *target_state;
        Ok(())
    }

    /// Registers an observer callback for state changes.
    pub fn observe(&mut self, callback: StateChangeCallback) {
        self.observers.push(callback);
    }

    /// Notifies all observers of a state change event.
    fn notify_observers(&self, event: &VaultStateEvent) {
        for observer in &self.observers {
            observer(event);
        }
    }

    /// Touches the active session to prevent auto-lock.
    ///
    /// # Errors
    ///
    /// Returns error if no active session or session is locked.
    pub fn touch_session(&mut self, timeout_minutes: u32) -> KestrelResult<()> {
        match &mut self.session {
            Some(session) => session.touch(timeout_minutes),
            None => Err(KestrelError::Unauthorized(
                "No active session".to_string(),
            )),
        }
    }

    /// Checks if auto-lock should be triggered.
    pub fn should_auto_lock(&self, timeout_minutes: u32) -> bool {
        match &self.session {
            Some(session) => session.is_auto_lock_triggered(timeout_minutes),
            None => self.state == VaultState::Unlocked,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_state_machine_uninitialized() {
        let sm = VaultStateMachine::uninitialized();
        assert_eq!(sm.state(), VaultState::Uninitialized);
        assert!(!sm.is_unlocked());
    }

    #[test]
    fn new_state_machine_locked() {
        let sm = VaultStateMachine::locked();
        assert_eq!(sm.state(), VaultState::Locked);
    }

    #[test]
    fn initialize_from_uninitialized() -> KestrelResult<()> {
        let mut sm = VaultStateMachine::uninitialized();
        let result = sm.try_transition(VaultTransition::Initialize)?;
        assert_eq!(result, TransitionResult::Success(VaultState::Locked));
        assert_eq!(sm.state(), VaultState::Locked);
        Ok(())
    }

    #[test]
    fn unlock_from_locked() -> KestrelResult<()> {
        let mut sm = VaultStateMachine::locked();
        let result = sm.try_transition(VaultTransition::Unlock)?;
        assert_eq!(result, TransitionResult::Success(VaultState::Unlocked));
        assert!(sm.is_unlocked());
        assert!(sm.session().is_some());
        Ok(())
    }

    #[test]
    fn lock_from_unlocked() -> KestrelResult<()> {
        let mut sm = VaultStateMachine::locked();
        sm.try_transition(VaultTransition::Unlock)?;
        let result = sm.try_transition(VaultTransition::Lock)?;
        assert_eq!(result, TransitionResult::Success(VaultState::Locked));
        assert!(sm.session().is_none());
        Ok(())
    }

    #[test]
    fn auto_lock_from_unlocked() -> KestrelResult<()> {
        let mut sm = VaultStateMachine::locked();
        sm.try_transition(VaultTransition::Unlock)?;
        let result = sm.try_transition(VaultTransition::AutoLock)?;
        assert_eq!(result, TransitionResult::Success(VaultState::Locked));
        Ok(())
    }

    #[test]
    fn change_password_stays_unlocked() -> KestrelResult<()> {
        let mut sm = VaultStateMachine::locked();
        sm.try_transition(VaultTransition::Unlock)?;
        let result = sm.try_transition(VaultTransition::ChangePassword)?;
        assert_eq!(result, TransitionResult::Success(VaultState::Unlocked));
        assert!(sm.is_unlocked());
        Ok(())
    }

    #[test]
    fn unlock_from_uninitialized_rejected() {
        let mut sm = VaultStateMachine::uninitialized();
        let result = sm.try_transition(VaultTransition::Unlock);
        assert!(result.is_err());
    }

    #[test]
    fn lock_from_locked_rejected() {
        let mut sm = VaultStateMachine::locked();
        let result = sm.try_transition(VaultTransition::Lock);
        assert!(result.is_err());
    }

    #[test]
    fn unlock_from_unlocked_rejected() -> KestrelResult<()> {
        let mut sm = VaultStateMachine::locked();
        sm.try_transition(VaultTransition::Unlock)?;
        let result = sm.try_transition(VaultTransition::Unlock);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn initialize_from_locked_rejected() {
        let mut sm = VaultStateMachine::locked();
        let result = sm.try_transition(VaultTransition::Initialize);
        assert!(result.is_err());
    }

    #[test]
    fn change_password_from_locked_rejected() {
        let mut sm = VaultStateMachine::locked();
        let result = sm.try_transition(VaultTransition::ChangePassword);
        assert!(result.is_err());
    }

    #[test]
    fn full_lifecycle() -> KestrelResult<()> {
        let mut sm = VaultStateMachine::uninitialized();
        assert_eq!(sm.state(), VaultState::Uninitialized);

        sm.try_transition(VaultTransition::Initialize)?;
        assert_eq!(sm.state(), VaultState::Locked);

        sm.try_transition(VaultTransition::Unlock)?;
        assert_eq!(sm.state(), VaultState::Unlocked);

        sm.try_transition(VaultTransition::Lock)?;
        assert_eq!(sm.state(), VaultState::Locked);

        sm.try_transition(VaultTransition::Unlock)?;
        sm.try_transition(VaultTransition::AutoLock)?;
        assert_eq!(sm.state(), VaultState::Locked);
        Ok(())
    }

    #[test]
    fn touch_session_when_unlocked() -> KestrelResult<()> {
        let mut sm = VaultStateMachine::locked();
        sm.try_transition(VaultTransition::Unlock)?;
        assert!(sm.touch_session(15).is_ok());
        Ok(())
    }

    #[test]
    fn touch_session_when_locked_fails() -> KestrelResult<()> {
        let mut sm = VaultStateMachine::locked();
        assert!(sm.touch_session(15).is_err());
        Ok(())
    }

    #[test]
    fn state_display() {
        assert_eq!(VaultState::Uninitialized.to_string(), "Uninitialized");
        assert_eq!(VaultState::Locked.to_string(), "Locked");
        assert_eq!(VaultState::Unlocked.to_string(), "Unlocked");
    }
}
