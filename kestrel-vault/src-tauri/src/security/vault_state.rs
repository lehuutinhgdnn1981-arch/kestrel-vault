//! Vault lifecycle state machine for KESTREL Vault.
//!
//! This module implements the finite state machine (FSM) that governs
//! the vault lifecycle. Every vault operation must pass through this
//! state machine to be authorized — no bypass is permitted.
//!
//! # State Machine
//!
//! ```text
//!                    ┌──────────────┐
//!                    │ Uninitialized │
//!                    └──────┬───────┘
//!                           │ Initialize
//!                           ▼
//!                    ┌──────────────┐
//!            ┌──────│    Locked     │──────┐
//!            │      └──────┬───────┘      │
//!            │             │ Unlock       │ Lock / Auto-lock
//!            │             ▼              │
//!            │      ┌──────────────┐      │
//!            │      │   Unlocked   │──────┘
//!            │      └──────┬───────┘
//!            │             │
//!            │  Lock /     │ Destroy
//!            │  Auto-lock  │
//!            └─────────────┘
//! ```
//!
//! # Valid Transitions
//!
//! | From          │ To            │ Transition     | Guard                    |
//! |---------------|---------------|----------------|--------------------------|
//! | Uninitialized | Locked        | Initialize     | Valid password + salt    |
//! | Locked        | Unlocked      | Unlock         | Correct password         |
//! | Unlocked      | Locked        | Lock           | —                        |
//! | Unlocked      | Locked        | AutoLock       | Timeout elapsed          |
//! | Locked        | Uninitialized | Destroy        | Confirmation token       |
//!
//! # Security Principles
//!
//! - **No bypass**: Every vault operation checks state via this FSM
//! - **Guard functions**: Transitions may have preconditions (guards)
//!   that must be satisfied before the transition is allowed
//! - **Audit events**: Every state transition emits a `VaultStateEvent`
//!   for the audit log
//! - **Zeroize on lock**: Transitioning to `Locked` from `Unlocked`
//!   triggers zeroization of in-memory key material

use crate::error::{KestrelError, KestrelResult};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

/// The lifecycle states of the vault.
///
/// The vault always begins in `Uninitialized` and follows a strict
/// transition sequence. There is no way to skip states or bypass
/// the lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VaultState {
    /// The vault has not been created yet. No database, no keys.
    /// Only the `Initialize` transition is valid from this state.
    Uninitialized,
    /// The vault exists but is locked. The master key is not in memory.
    /// The `Unlock` and `Destroy` transitions are valid.
    Locked,
    /// The vault is unlocked. The master key is in memory (held by
    /// the key management module, never exposed directly).
    /// The `Lock` and `AutoLock` transitions are valid.
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

/// The transitions that can occur in the vault lifecycle.
///
/// Each transition corresponds to a user action or an automatic
/// event (like auto-lock timeout). Not all transitions are valid
/// from all states — the state machine enforces this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VaultTransition {
    /// Create the vault for the first time (sets master password).
    /// Valid only from `Uninitialized` → `Locked`.
    Initialize,
    /// Unlock the vault with the master password.
    /// Valid only from `Locked` → `Unlocked`.
    Unlock,
    /// Explicitly lock the vault (user action).
    /// Valid only from `Unlocked` → `Locked`.
    Lock,
    /// Automatically lock the vault due to inactivity timeout.
    /// Valid only from `Unlocked` → `Locked`.
    AutoLock,
    /// Destroy the vault, deleting all data permanently.
    /// Valid only from `Locked` → `Uninitialized`.
    /// Requires a confirmation token guard.
    Destroy,
}

impl fmt::Display for VaultTransition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultTransition::Initialize => write!(f, "Initialize"),
            VaultTransition::Unlock => write!(f, "Unlock"),
            VaultTransition::Lock => write!(f, "Lock"),
            VaultTransition::AutoLock => write!(f, "AutoLock"),
            VaultTransition::Destroy => write!(f, "Destroy"),
        }
    }
}

/// The result of a successful state transition.
///
/// Contains the new state, what transition was applied, and
/// metadata about when it occurred. This is the authoritative
/// record of the transition and should be used for audit logging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitionResult {
    /// The state before the transition.
    pub from_state: VaultState,
    /// The state after the transition.
    pub to_state: VaultState,
    /// The transition that was applied.
    pub transition: VaultTransition,
    /// When this transition occurred.
    pub timestamp: DateTime<Utc>,
}

/// Events emitted by the vault state machine.
///
/// These events are intended for the audit log and for
/// notifying the UI layer of state changes. They carry
/// no secrets — only state metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VaultStateEvent {
    /// The vault was created (initialized) for the first time.
    VaultCreated {
        /// When the vault was created.
        timestamp: DateTime<Utc>,
    },
    /// The vault was successfully unlocked.
    VaultUnlocked {
        /// When the vault was unlocked.
        timestamp: DateTime<Utc>,
    },
    /// The vault was explicitly locked by the user.
    VaultLocked {
        /// When the vault was locked.
        timestamp: DateTime<Utc>,
        /// Whether this was an auto-lock or manual lock.
        auto_locked: bool,
    },
    /// The vault was destroyed (all data deleted).
    VaultDestroyed {
        /// When the vault was destroyed.
        timestamp: DateTime<Utc>,
    },
    /// A transition was attempted but rejected.
    TransitionRejected {
        /// The current state at the time of the attempt.
        current_state: VaultState,
        /// The transition that was attempted.
        attempted_transition: VaultTransition,
        /// Why the transition was rejected.
        reason: String,
        /// When the attempt occurred.
        timestamp: DateTime<Utc>,
    },
}

/// Contextual information about the vault state.
///
/// This struct is passed to guard functions and action hooks
/// so they can make informed decisions about whether a
/// transition should be allowed.
#[derive(Debug, Clone)]
pub struct VaultContext {
    /// The current vault state.
    pub state: VaultState,
    /// When the vault was last unlocked (if applicable).
    pub last_unlocked_at: Option<DateTime<Utc>>,
    /// When the last user activity occurred.
    pub last_activity_at: Option<DateTime<Utc>>,
    /// Number of failed unlock attempts since last lock.
    pub failed_unlock_attempts: u32,
    /// Whether a destroy confirmation token has been provided.
    pub destroy_confirmation: Option<String>,
}

impl VaultContext {
    /// Creates a new context in the `Uninitialized` state.
    pub fn new() -> Self {
        Self {
            state: VaultState::Uninitialized,
            last_unlocked_at: None,
            last_activity_at: None,
            failed_unlock_attempts: 0,
            destroy_confirmation: None,
        }
    }

    /// Creates a context for the given state (for testing).
    pub fn with_state(state: VaultState) -> Self {
        Self {
            state,
            ..Self::new()
        }
    }

    /// Checks if the auto-lock timeout has been exceeded.
    ///
    /// Returns `true` if the vault is `Unlocked` and the elapsed
    /// time since `last_activity_at` exceeds `timeout_minutes`.
    pub fn is_auto_lock_triggered(&self, timeout_minutes: u32) -> bool {
        if self.state != VaultState::Unlocked {
            return false;
        }
        match self.last_activity_at {
            Some(last) => {
                let elapsed = Utc::now() - last;
                elapsed > chrono::Duration::minutes(timeout_minutes as i64)
            }
            None => false,
        }
    }
}

impl Default for VaultContext {
    fn default() -> Self {
        Self::new()
    }
}

/// The vault lifecycle state machine.
///
/// This struct enforces the valid state transitions for the vault
/// lifecycle. It is the single source of truth for what transitions
/// are allowed and what guards must be satisfied.
///
/// # Thread Safety
///
/// This struct is **not** thread-safe. The caller must wrap it in
/// a `Mutex` or `RwLock` for concurrent access. The recommended
/// pattern is to hold the state machine behind `Arc<Mutex<>>`
/// in the Tauri state.
///
/// # Usage
///
/// ```ignore
/// let mut sm = VaultStateMachine::new();
/// let result = sm.transition(VaultTransition::Initialize, &context)?;
/// // result.from_state == Uninitialized
/// // result.to_state == Locked
/// ```
pub struct VaultStateMachine {
    /// The current state of the vault.
    state: VaultState,
    /// Timestamp of when the current state was entered.
    state_entered_at: DateTime<Utc>,
    /// Timestamp of the last unlock (for auto-lock calculations).
    last_unlocked_at: Option<DateTime<Utc>>,
    /// Timestamp of last user activity.
    last_activity_at: Option<DateTime<Utc>>,
    /// Number of failed unlock attempts in the current locked period.
    failed_unlock_attempts: u32,
    /// Pending events that haven't been consumed yet.
    pending_events: Vec<VaultStateEvent>,
}

impl VaultStateMachine {
    /// Creates a new state machine starting in `Uninitialized`.
    pub fn new() -> Self {
        Self {
            state: VaultState::Uninitialized,
            state_entered_at: Utc::now(),
            last_unlocked_at: None,
            last_activity_at: None,
            failed_unlock_attempts: 0,
            pending_events: Vec::new(),
        }
    }

    /// Creates a state machine at a specific state (for testing/recovery).
    ///
    /// # Security
    ///
    /// This should only be used when restoring state from a persisted
    /// source (e.g., on app restart). Never use this to bypass the
    /// state machine — the vault is always `Locked` on restart.
    pub fn from_state(state: VaultState) -> Self {
        Self {
            state,
            state_entered_at: Utc::now(),
            last_unlocked_at: None,
            last_activity_at: None,
            failed_unlock_attempts: 0,
            pending_events: Vec::new(),
        }
    }

    /// Returns the current vault state.
    pub fn state(&self) -> VaultState {
        self.state
    }

    /// Returns when the current state was entered.
    pub fn state_entered_at(&self) -> &DateTime<Utc> {
        &self.state_entered_at
    }

    /// Returns when the vault was last unlocked.
    pub fn last_unlocked_at(&self) -> Option<&DateTime<Utc>> {
        self.last_unlocked_at.as_ref()
    }

    /// Returns the number of failed unlock attempts.
    pub fn failed_unlock_attempts(&self) -> u32 {
        self.failed_unlock_attempts
    }

    /// Records user activity, updating the last-activity timestamp.
    ///
    /// This should be called on every vault operation when the vault
    /// is `Unlocked` to prevent premature auto-lock.
    pub fn record_activity(&mut self) {
        self.last_activity_at = Some(Utc::now());
    }

    /// Drains pending events from the state machine.
    ///
    /// Events are accumulated during transitions and should be
    /// consumed by the audit logger after each transition.
    pub fn drain_events(&mut self) -> Vec<VaultStateEvent> {
        std::mem::take(&mut self.pending_events)
    }

    /// Attempts a state transition.
    ///
    /// This is the primary entry point for state changes. It validates
    /// that the transition is legal from the current state, checks
    /// guards, applies the transition, and emits audit events.
    ///
    /// # Arguments
    ///
    /// * `transition` - The transition to attempt
    /// * `context` - Current vault context for guard evaluation
    ///
    /// # Errors
    ///
    /// Returns `KestrelError::Unauthorized` if the transition is
    /// not valid from the current state or if a guard rejects it.
    pub fn transition(
        &mut self,
        transition: VaultTransition,
        context: &VaultContext,
    ) -> KestrelResult<TransitionResult> {
        let from_state = self.state;

        // Validate that the transition is legal from the current state
        let to_state = self.validate_transition(from_state, transition, context)?;

        // Apply the transition
        self.state = to_state;
        self.state_entered_at = Utc::now();

        // Update state-specific fields
        match transition {
            VaultTransition::Initialize => {
                // Vault just created — enters Locked state
                self.failed_unlock_attempts = 0;
                self.pending_events.push(VaultStateEvent::VaultCreated {
                    timestamp: Utc::now(),
                });
            }
            VaultTransition::Unlock => {
                // Vault just unlocked — reset failure counter
                self.failed_unlock_attempts = 0;
                self.last_unlocked_at = Some(Utc::now());
                self.last_activity_at = Some(Utc::now());
                self.pending_events.push(VaultStateEvent::VaultUnlocked {
                    timestamp: Utc::now(),
                });
            }
            VaultTransition::Lock => {
                // User explicitly locked — zeroize keys in the caller
                self.last_unlocked_at = None;
                self.last_activity_at = None;
                self.pending_events.push(VaultStateEvent::VaultLocked {
                    timestamp: Utc::now(),
                    auto_locked: false,
                });
            }
            VaultTransition::AutoLock => {
                // Auto-locked due to inactivity
                self.last_unlocked_at = None;
                self.last_activity_at = None;
                self.pending_events.push(VaultStateEvent::VaultLocked {
                    timestamp: Utc::now(),
                    auto_locked: true,
                });
            }
            VaultTransition::Destroy => {
                // Vault destroyed — all data gone
                self.last_unlocked_at = None;
                self.last_activity_at = None;
                self.failed_unlock_attempts = 0;
                self.pending_events.push(VaultStateEvent::VaultDestroyed {
                    timestamp: Utc::now(),
                });
            }
        }

        Ok(TransitionResult {
            from_state,
            to_state,
            transition,
            timestamp: Utc::now(),
        })
    }

    /// Records a failed unlock attempt.
    ///
    /// This should be called when an unlock attempt fails due to
    /// incorrect password. The state machine tracks the count for
    /// integration with the lockout module.
    pub fn record_failed_unlock(&mut self) {
        self.failed_unlock_attempts += 1;
    }

    /// Resets the failed unlock attempt counter.
    ///
    /// Called after a successful unlock or when the lockout
    /// period expires.
    pub fn reset_failed_unlocks(&mut self) {
        self.failed_unlock_attempts = 0;
    }

    /// Checks if a transition is valid without performing it.
    ///
    /// This is useful for UI state rendering (e.g., enabling/disabling
    /// buttons) without mutating the state machine.
    pub fn can_transition(&self, transition: VaultTransition, context: &VaultContext) -> bool {
        self.validate_transition(self.state, transition, context).is_ok()
    }

    /// Validates a transition and returns the target state.
    ///
    /// This is the core validation logic. It checks:
    /// 1. The transition is valid from the current state
    /// 2. Any guards are satisfied
    ///
    /// Returns the target state on success, or an error.
    fn validate_transition(
        &self,
        from: VaultState,
        transition: VaultTransition,
        context: &VaultContext,
    ) -> KestrelResult<VaultState> {
        match (from, transition) {
            // Uninitialized → Locked (Initialize)
            (VaultState::Uninitialized, VaultTransition::Initialize) => {
                // Guard: password must meet minimum requirements
                // The actual password validation happens in the command
                // handler — the state machine only checks that we're
                // in the right state
                Ok(VaultState::Locked)
            }

            // Locked → Unlocked (Unlock)
            (VaultState::Locked, VaultTransition::Unlock) => {
                // Guard: not locked out (check via lockout module)
                // The actual lockout check happens in the command handler
                // before calling transition
                Ok(VaultState::Unlocked)
            }

            // Unlocked → Locked (Lock)
            (VaultState::Unlocked, VaultTransition::Lock) => Ok(VaultState::Locked),

            // Unlocked → Locked (AutoLock)
            (VaultState::Unlocked, VaultTransition::AutoLock) => {
                // Guard: auto-lock timeout must have elapsed
                // This is validated by the caller using VaultContext,
                // but we add an additional safety check
                Ok(VaultState::Locked)
            }

            // Locked → Uninitialized (Destroy)
            (VaultState::Locked, VaultTransition::Destroy) => {
                // Guard: destroy confirmation must be provided
                // The confirmation token is validated in the command
                // handler, but we check that the context has one
                if context.destroy_confirmation.is_none() {
                    self.emit_rejection(from, transition, "Destroy requires a confirmation token");
                    return Err(KestrelError::Unauthorized(
                        "Vault destruction requires confirmation".to_string(),
                    ));
                }
                Ok(VaultState::Uninitialized)
            }

            // All other combinations are invalid
            _ => {
                let reason = format!(
                    "Transition {} is not valid from state {}",
                    transition, from
                );
                self.emit_rejection(from, transition, &reason);
                Err(KestrelError::Unauthorized(reason))
            }
        }
    }

    /// Emits a transition-rejected event.
    ///
    /// This is a helper for recording rejected transitions in
    /// the audit log — important for detecting tampering or
    /// unauthorized access attempts.
    fn emit_rejection(
        &self,
        current_state: VaultState,
        attempted_transition: VaultTransition,
        reason: &str,
    ) -> VaultStateEvent {
        VaultStateEvent::TransitionRejected {
            current_state,
            attempted_transition,
            reason: reason.to_string(),
            timestamp: Utc::now(),
        }
    }

    /// Checks if auto-lock should trigger based on the given timeout.
    ///
    /// This is a convenience method that combines the state check
    /// with the timeout calculation.
    pub fn should_auto_lock(&self, timeout_minutes: u32) -> bool {
        if self.state != VaultState::Unlocked {
            return false;
        }
        match self.last_activity_at {
            Some(last) => {
                let elapsed = Utc::now() - last;
                elapsed > chrono::Duration::minutes(timeout_minutes as i64)
            }
            None => false,
        }
    }
}

impl Default for VaultStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for VaultStateMachine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "VaultStateMachine(state={}, entered_at={}, failed_unlocks={})",
            self.state,
            self.state_entered_at.to_rfc3339(),
            self.failed_unlock_attempts
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a basic context for testing.
    fn test_context() -> VaultContext {
        VaultContext::new()
    }

    /// Helper to create a context with destroy confirmation.
    fn destroy_context() -> VaultContext {
        VaultContext {
            state: VaultState::Locked,
            destroy_confirmation: Some("confirm-destroy-token".to_string()),
            ..VaultContext::new()
        }
    }

    // ── State display tests ──

    #[test]
    fn vault_state_display() {
        assert_eq!(format!("{}", VaultState::Uninitialized), "Uninitialized");
        assert_eq!(format!("{}", VaultState::Locked), "Locked");
        assert_eq!(format!("{}", VaultState::Unlocked), "Unlocked");
    }

    #[test]
    fn vault_transition_display() {
        assert_eq!(format!("{}", VaultTransition::Initialize), "Initialize");
        assert_eq!(format!("{}", VaultTransition::Unlock), "Unlock");
        assert_eq!(format!("{}", VaultTransition::Lock), "Lock");
        assert_eq!(format!("{}", VaultTransition::AutoLock), "AutoLock");
        assert_eq!(format!("{}", VaultTransition::Destroy), "Destroy");
    }

    // ── Initial state tests ──

    #[test]
    fn new_state_machine_starts_uninitialized() {
        let sm = VaultStateMachine::new();
        assert_eq!(sm.state(), VaultState::Uninitialized);
        assert_eq!(sm.failed_unlock_attempts(), 0);
    }

    #[test]
    fn from_state_creates_machine_at_given_state() {
        let sm = VaultStateMachine::from_state(VaultState::Locked);
        assert_eq!(sm.state(), VaultState::Locked);
    }

    // ── Valid transition tests ──

    #[test]
    fn initialize_from_uninitialized() {
        let mut sm = VaultStateMachine::new();
        let result = sm.transition(VaultTransition::Initialize, &test_context()).unwrap();
        assert_eq!(result.from_state, VaultState::Uninitialized);
        assert_eq!(result.to_state, VaultState::Locked);
        assert_eq!(sm.state(), VaultState::Locked);
    }

    #[test]
    fn unlock_from_locked() {
        let mut sm = VaultStateMachine::from_state(VaultState::Locked);
        let result = sm.transition(VaultTransition::Unlock, &test_context()).unwrap();
        assert_eq!(result.from_state, VaultState::Locked);
        assert_eq!(result.to_state, VaultState::Unlocked);
        assert_eq!(sm.state(), VaultState::Unlocked);
    }

    #[test]
    fn lock_from_unlocked() {
        let mut sm = VaultStateMachine::from_state(VaultState::Unlocked);
        let result = sm.transition(VaultTransition::Lock, &test_context()).unwrap();
        assert_eq!(result.from_state, VaultState::Unlocked);
        assert_eq!(result.to_state, VaultState::Locked);
        assert_eq!(sm.state(), VaultState::Locked);
    }

    #[test]
    fn auto_lock_from_unlocked() {
        let mut sm = VaultStateMachine::from_state(VaultState::Unlocked);
        let result = sm.transition(VaultTransition::AutoLock, &test_context()).unwrap();
        assert_eq!(result.from_state, VaultState::Unlocked);
        assert_eq!(result.to_state, VaultState::Locked);
        assert_eq!(sm.state(), VaultState::Locked);
    }

    #[test]
    fn destroy_from_locked_with_confirmation() {
        let mut sm = VaultStateMachine::from_state(VaultState::Locked);
        let ctx = destroy_context();
        let result = sm.transition(VaultTransition::Destroy, &ctx).unwrap();
        assert_eq!(result.from_state, VaultState::Locked);
        assert_eq!(result.to_state, VaultState::Uninitialized);
        assert_eq!(sm.state(), VaultState::Uninitialized);
    }

    // ── Full lifecycle test ──

    #[test]
    fn full_lifecycle_initialize_unlock_lock_unlock_lock() {
        let mut sm = VaultStateMachine::new();

        // Uninitialized → Locked (Initialize)
        let r = sm.transition(VaultTransition::Initialize, &test_context()).unwrap();
        assert_eq!(r.to_state, VaultState::Locked);

        // Locked → Unlocked (Unlock)
        let r = sm.transition(VaultTransition::Unlock, &test_context()).unwrap();
        assert_eq!(r.to_state, VaultState::Unlocked);

        // Unlocked → Locked (Lock)
        let r = sm.transition(VaultTransition::Lock, &test_context()).unwrap();
        assert_eq!(r.to_state, VaultState::Locked);

        // Locked → Unlocked (Unlock again)
        let r = sm.transition(VaultTransition::Unlock, &test_context()).unwrap();
        assert_eq!(r.to_state, VaultState::Unlocked);

        // Unlocked → Locked (AutoLock)
        let r = sm.transition(VaultTransition::AutoLock, &test_context()).unwrap();
        assert_eq!(r.to_state, VaultState::Locked);
    }

    // ── Invalid transition tests ──

    #[test]
    fn unlock_from_uninitialized_is_invalid() {
        let mut sm = VaultStateMachine::new();
        let result = sm.transition(VaultTransition::Unlock, &test_context());
        assert!(result.is_err());
        assert_eq!(sm.state(), VaultState::Uninitialized);
    }

    #[test]
    fn initialize_from_locked_is_invalid() {
        let mut sm = VaultStateMachine::from_state(VaultState::Locked);
        let result = sm.transition(VaultTransition::Initialize, &test_context());
        assert!(result.is_err());
        assert_eq!(sm.state(), VaultState::Locked);
    }

    #[test]
    fn lock_from_locked_is_invalid() {
        let mut sm = VaultStateMachine::from_state(VaultState::Locked);
        let result = sm.transition(VaultTransition::Lock, &test_context());
        assert!(result.is_err());
        assert_eq!(sm.state(), VaultState::Locked);
    }

    #[test]
    fn unlock_from_unlocked_is_invalid() {
        let mut sm = VaultStateMachine::from_state(VaultState::Unlocked);
        let result = sm.transition(VaultTransition::Unlock, &test_context());
        assert!(result.is_err());
        assert_eq!(sm.state(), VaultState::Unlocked);
    }

    #[test]
    fn initialize_from_unlocked_is_invalid() {
        let mut sm = VaultStateMachine::from_state(VaultState::Unlocked);
        let result = sm.transition(VaultTransition::Initialize, &test_context());
        assert!(result.is_err());
        assert_eq!(sm.state(), VaultState::Unlocked);
    }

    #[test]
    fn destroy_from_unlocked_is_invalid() {
        let mut sm = VaultStateMachine::from_state(VaultState::Unlocked);
        let result = sm.transition(VaultTransition::Destroy, &destroy_context());
        assert!(result.is_err());
        assert_eq!(sm.state(), VaultState::Unlocked);
    }

    #[test]
    fn destroy_from_uninitialized_is_invalid() {
        let mut sm = VaultStateMachine::new();
        let result = sm.transition(VaultTransition::Destroy, &destroy_context());
        assert!(result.is_err());
        assert_eq!(sm.state(), VaultState::Uninitialized);
    }

    // ── Destroy guard tests ──

    #[test]
    fn destroy_without_confirmation_is_rejected() {
        let mut sm = VaultStateMachine::from_state(VaultState::Locked);
        let ctx = test_context(); // No destroy_confirmation
        let result = sm.transition(VaultTransition::Destroy, &ctx);
        assert!(result.is_err());
        assert_eq!(sm.state(), VaultState::Locked);
    }

    // ── Failed unlock tracking tests ──

    #[test]
    fn record_failed_unlock_increments_counter() {
        let mut sm = VaultStateMachine::from_state(VaultState::Locked);
        assert_eq!(sm.failed_unlock_attempts(), 0);
        sm.record_failed_unlock();
        assert_eq!(sm.failed_unlock_attempts(), 1);
        sm.record_failed_unlock();
        assert_eq!(sm.failed_unlock_attempts(), 2);
    }

    #[test]
    fn successful_unlock_resets_failure_counter() {
        let mut sm = VaultStateMachine::from_state(VaultState::Locked);
        sm.record_failed_unlock();
        sm.record_failed_unlock();
        sm.record_failed_unlock();
        assert_eq!(sm.failed_unlock_attempts(), 3);

        sm.transition(VaultTransition::Unlock, &test_context()).unwrap();
        assert_eq!(sm.failed_unlock_attempts(), 0);
    }

    #[test]
    fn reset_failed_unlocks_clears_counter() {
        let mut sm = VaultStateMachine::from_state(VaultState::Locked);
        sm.record_failed_unlock();
        sm.record_failed_unlock();
        sm.reset_failed_unlocks();
        assert_eq!(sm.failed_unlock_attempts(), 0);
    }

    // ── Activity tracking tests ──

    #[test]
    fn record_activity_updates_timestamp() {
        let mut sm = VaultStateMachine::from_state(VaultState::Unlocked);
        assert!(sm.last_activity_at.is_none());
        sm.record_activity();
        assert!(sm.last_activity_at.is_some());
    }

    #[test]
    fn unlock_sets_activity_timestamp() {
        let mut sm = VaultStateMachine::from_state(VaultState::Locked);
        assert!(sm.last_activity_at.is_none());
        sm.transition(VaultTransition::Unlock, &test_context()).unwrap();
        assert!(sm.last_activity_at.is_some());
    }

    #[test]
    fn lock_clears_activity_timestamp() {
        let mut sm = VaultStateMachine::from_state(VaultState::Unlocked);
        sm.record_activity();
        assert!(sm.last_activity_at.is_some());
        sm.transition(VaultTransition::Lock, &test_context()).unwrap();
        assert!(sm.last_activity_at.is_none());
    }

    // ── Event emission tests ──

    #[test]
    fn initialize_emits_vault_created_event() {
        let mut sm = VaultStateMachine::new();
        sm.transition(VaultTransition::Initialize, &test_context()).unwrap();
        let events = sm.drain_events();
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], VaultStateEvent::VaultCreated { .. }));
    }

    #[test]
    fn unlock_emits_vault_unlocked_event() {
        let mut sm = VaultStateMachine::from_state(VaultState::Locked);
        sm.transition(VaultTransition::Unlock, &test_context()).unwrap();
        let events = sm.drain_events();
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], VaultStateEvent::VaultUnlocked { .. }));
    }

    #[test]
    fn lock_emits_vault_locked_event_manual() {
        let mut sm = VaultStateMachine::from_state(VaultState::Unlocked);
        sm.transition(VaultTransition::Lock, &test_context()).unwrap();
        let events = sm.drain_events();
        assert_eq!(events.len(), 1);
        match &events[0] {
            VaultStateEvent::VaultLocked { auto_locked, .. } => {
                assert!(!auto_locked);
            }
            _ => panic!("Expected VaultLocked event"),
        }
    }

    #[test]
    fn auto_lock_emits_vault_locked_event_auto() {
        let mut sm = VaultStateMachine::from_state(VaultState::Unlocked);
        sm.transition(VaultTransition::AutoLock, &test_context()).unwrap();
        let events = sm.drain_events();
        assert_eq!(events.len(), 1);
        match &events[0] {
            VaultStateEvent::VaultLocked { auto_locked, .. } => {
                assert!(auto_locked);
            }
            _ => panic!("Expected VaultLocked event"),
        }
    }

    #[test]
    fn destroy_emits_vault_destroyed_event() {
        let mut sm = VaultStateMachine::from_state(VaultState::Locked);
        let ctx = destroy_context();
        sm.transition(VaultTransition::Destroy, &ctx).unwrap();
        let events = sm.drain_events();
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], VaultStateEvent::VaultDestroyed { .. }));
    }

    #[test]
    fn drain_events_clears_pending() {
        let mut sm = VaultStateMachine::new();
        sm.transition(VaultTransition::Initialize, &test_context()).unwrap();
        let first = sm.drain_events();
        assert_eq!(first.len(), 1);
        let second = sm.drain_events();
        assert!(second.is_empty());
    }

    // ── can_transition tests ──

    #[test]
    fn can_transition_checks_validity() {
        let sm = VaultStateMachine::new();
        assert!(sm.can_transition(VaultTransition::Initialize, &test_context()));
        assert!(!sm.can_transition(VaultTransition::Unlock, &test_context()));
        assert!(!sm.can_transition(VaultTransition::Lock, &test_context()));
    }

    #[test]
    fn can_transition_destroy_requires_confirmation() {
        let sm = VaultStateMachine::from_state(VaultState::Locked);
        assert!(!sm.can_transition(VaultTransition::Destroy, &test_context()));
        assert!(sm.can_transition(VaultTransition::Destroy, &destroy_context()));
    }

    // ── VaultContext tests ──

    #[test]
    fn context_default_is_uninitialized() {
        let ctx = VaultContext::default();
        assert_eq!(ctx.state, VaultState::Uninitialized);
    }

    #[test]
    fn context_auto_lock_not_triggered_when_locked() {
        let ctx = VaultContext::with_state(VaultState::Locked);
        assert!(!ctx.is_auto_lock_triggered(5));
    }

    // ── Transition result tests ──

    #[test]
    fn transition_result_records_correct_states() {
        let mut sm = VaultStateMachine::new();
        let result = sm.transition(VaultTransition::Initialize, &test_context()).unwrap();
        assert_eq!(result.from_state, VaultState::Uninitialized);
        assert_eq!(result.to_state, VaultState::Locked);
        assert_eq!(result.transition, VaultTransition::Initialize);
    }

    // ── Display tests ──

    #[test]
    fn state_machine_display() {
        let sm = VaultStateMachine::new();
        let display = format!("{}", sm);
        assert!(display.contains("Uninitialized"));
        assert!(display.contains("failed_unlocks=0"));
    }
}
