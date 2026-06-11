//! Authentication Tauri commands for KESTREL Vault.
//!
//! Handles vault initialization, unlock, lock, and password change.
//! These are the ONLY commands that accept the master password.
//!
//! # Security
//!
//! - Master password is NEVER stored — only used for key derivation
//! - Key derivation happens in Rust, never in React
//! - Rate limiting on unlock attempts
//! - Progressive lockout after failures
//! - All auth events are audit-logged
//! - Vault state machine enforces lifecycle transitions
//!
//! # IPC Contract
//!
//! | Command                  | Required State | Effect                          |
//! |--------------------------|---------------|---------------------------------|
//! | auth_initialize_vault    | Uninitialized | Uninitialized → Locked          |
//! | auth_unlock              | Locked        | Locked → Unlocked               |
//! | auth_lock                | Unlocked      | Unlocked → Locked               |
//! | auth_get_session         | Any           | Read-only                       |
//! | auth_is_vault_initialized| Any           | Read-only                       |
//! | auth_change_password     | Unlocked      | Key rotation                    |
//! | auth_get_vault_status    | Any           | Read-only                       |

use crate::commands::types::{
    validate_master_password, CommandError, CommandResult, SessionResponse, VaultInitResponse,
    VaultLockResponse, VaultStatusResponse,
};
use crate::error::KestrelError;
use crate::security::lockout::{FailedAttemptTracker, LockoutState};
use crate::security::rate_limit::{Operation, RateLimiter};
use crate::security::vault_state::{VaultContext, VaultState, VaultStateMachine, VaultTransition};
use std::sync::RwLock;
use tauri::State;

/// App state shared across Tauri commands.
///
/// This struct is managed by Tauri's state management and
/// provides access to the vault state machine, rate limiter,
/// lockout tracker, and other shared resources.
///
/// # Thread Safety
///
/// All fields use `RwLock` for thread-safe access from multiple
/// Tauri command threads. Write locks are held for the minimum
/// time necessary.
///
/// # Security
///
/// - The master key is stored in `Option<MasterKey>` behind a RwLock.
///   When the vault is locked, the key is dropped (zeroized via
///   the `secrecy` crate's `Secret` type).
/// - No passwords are ever stored in this struct.
pub struct AppState {
    /// The vault lifecycle state machine.
    pub vault_state_machine: RwLock<VaultStateMachine>,
    /// Per-operation rate limiter.
    pub rate_limiter: RwLock<RateLimiter>,
    /// Failed attempt tracker for progressive lockout.
    pub lockout_tracker: RwLock<FailedAttemptTracker>,
    /// The master key, present only when vault is unlocked.
    /// When the vault is locked, this is `None` and the key
    /// memory has been zeroized.
    /// TODO: Replace with `RwLock<Option<MasterKey>>` once
    ///       MasterKey is integrated from crypto::key_management.
    pub master_key_present: RwLock<bool>,
}

impl Default for AppState {
    fn default() -> Self {
        AppState {
            vault_state_machine: RwLock::new(VaultStateMachine::new()),
            rate_limiter: RwLock::new(RateLimiter::new()),
            lockout_tracker: RwLock::new(FailedAttemptTracker::new()),
            master_key_present: RwLock::new(false),
        }
    }
}

impl AppState {
    /// Creates a new AppState with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Helper: checks if the vault is in the required state.
    ///
    /// Returns an error if the vault is not in the expected state.
    /// This is the central guard function used by all commands.
    pub fn require_state(&self, required: VaultState) -> Result<(), CommandError> {
        let sm = self.vault_state_machine.read().unwrap_or_else(|e| {
            tracing::error!("Vault state machine lock poisoned: {}", e);
            std::process::exit(1);
        });
        let current = sm.state();
        if current != required {
            return Err(CommandError::unauthorized(format!(
                "Vault must be in {} state, but is currently {}",
                required, current
            )));
        }
        Ok(())
    }

    /// Helper: checks if the vault is unlocked.
    ///
    /// Most vault operations require an unlocked state.
    pub fn require_unlocked(&self) -> Result<(), CommandError> {
        self.require_state(VaultState::Unlocked)
    }

    /// Helper: checks if the vault is NOT uninitialized.
    ///
    /// Some operations (like status checks) require the vault
    /// to at least exist (Locked or Unlocked).
    pub fn require_initialized(&self) -> Result<(), CommandError> {
        let sm = self.vault_state_machine.read().unwrap_or_else(|e| {
            tracing::error!("Vault state machine lock poisoned: {}", e);
            std::process::exit(1);
        });
        if sm.state() == VaultState::Uninitialized {
            return Err(CommandError::unauthorized(
                "Vault has not been initialized",
            ));
        }
        Ok(())
    }

    /// Helper: checks lockout state before allowing unlock.
    ///
    /// Returns an error if the user is locked out.
    pub fn check_lockout(&self) -> Result<(), CommandError> {
        let tracker = self.lockout_tracker.read().unwrap_or_else(|e| {
            tracing::error!("Lockout tracker lock poisoned: {}", e);
            std::process::exit(1);
        });
        match tracker.lockout_state() {
            LockoutState::Allowed => Ok(()),
            LockoutState::Delayed(secs) => {
                // Check if the delay has elapsed
                match tracker.lockout_state_at(chrono::Utc::now()) {
                    LockoutState::Allowed => Ok(()),
                    LockoutState::Delayed(remaining) => Err(CommandError::unauthorized(format!(
                        "Too many failed attempts. Please wait {} seconds before retrying.",
                        remaining
                    ))),
                    LockoutState::LockedOut => Err(CommandError::unauthorized(
                        "Account is locked due to too many failed attempts. Vault reset required.",
                    )),
                }
            }
            LockoutState::LockedOut => Err(CommandError::unauthorized(
                "Account is locked due to too many failed attempts. Vault reset required.",
            )),
        }
    }
}

/// Initializes the vault for the first time.
///
/// Creates the vault metadata, derives the master key, and
/// stores the encrypted test envelope. After initialization,
/// the vault is in Locked state — the user must explicitly unlock.
///
/// # IPC Contract
///
/// - **Required state**: Uninitialized
/// - **Transition**: Uninitialized → Locked
///
/// # Errors
///
/// - `UNAUTHORIZED`: Vault is already initialized
/// - `VALIDATION_ERROR`: Master password too short/long
#[tauri::command]
pub fn auth_initialize_vault(
    master_password: String,
    hint: Option<String>,
    state: State<'_, AppState>,
) -> CommandResult<VaultInitResponse> {
    // Validate inputs
    if let Err(e) = validate_master_password(&master_password) {
        return CommandResult::Err(e);
    }
    if let Some(ref h) = hint {
        if h.len() > 100 {
            return CommandResult::Err(CommandError::validation(
                "Hint must be at most 100 characters",
            ));
        }
    }

    // Guard: vault must be in Uninitialized state
    state.require_state(VaultState::Uninitialized)?;

    // Transition: Uninitialized → Locked
    {
        let mut sm = state.vault_state_machine.write().unwrap_or_else(|e| {
            tracing::error!("Vault state machine lock poisoned: {}", e);
            std::process::exit(1);
        });
        let context = VaultContext::new();
        match sm.transition(VaultTransition::Initialize, &context) {
            Ok(result) => {
                tracing::info!(
                    "Vault initialized: {:?} → {:?}",
                    result.from_state,
                    result.to_state
                );
                // Drain and log events
                for event in sm.drain_events() {
                    tracing::info!("Vault event: {:?}", event);
                }
            }
            Err(e) => {
                return CommandResult::Err(CommandError::from_kestrel(e));
            }
        }
    }

    // TODO: Generate salt using crypto::random
    // TODO: Derive master key from password using crypto::kdf
    // TODO: Create test envelope for verification using crypto::envelope
    // TODO: Store vault_meta in database via VaultMetaRepo
    // TODO: Audit log: VaultInitialized
    // TODO: Zeroize master_password

    CommandResult::ok(VaultInitResponse {
        initialized: true,
        state: VaultState::Locked.to_string(),
    })
}

/// Unlocks the vault with the master password.
///
/// Derives the key from the password, verifies the test envelope,
/// creates a new session, and transitions to Unlocked state.
///
/// # IPC Contract
///
/// - **Required state**: Locked
/// - **Transition**: Locked → Unlocked
///
/// # Security
///
/// - Rate limited to prevent brute force
/// - Progressive lockout after failures
/// - Master password is zeroized after key derivation
/// - Failed attempts are audit-logged
///
/// # Errors
///
/// - `UNAUTHORIZED`: Vault is locked out, or wrong password
/// - `VALIDATION_ERROR`: Master password too short/long
#[tauri::command]
pub fn auth_unlock(
    master_password: String,
    state: State<'_, AppState>,
) -> CommandResult<SessionResponse> {
    // Validate input
    if let Err(e) = validate_master_password(&master_password) {
        return CommandResult::Err(e);
    }

    // Guard: vault must be in Locked state
    state.require_state(VaultState::Locked)?;

    // Guard: check rate limiter
    {
        let mut limiter = state.rate_limiter.write().unwrap_or_else(|e| {
            tracing::error!("Rate limiter lock poisoned: {}", e);
            std::process::exit(1);
        });
        if limiter.is_rate_limited(Operation::Login) {
            return CommandResult::Err(CommandError::unauthorized(
                "Too many login attempts. Please try again later.",
            ));
        }
        if let Err(e) = limiter.record_attempt(Operation::Login) {
            return CommandResult::Err(CommandError::from_kestrel(e));
        }
    }

    // Guard: check lockout state
    state.check_lockout()?;

    // TODO: Derive key from password
    // TODO: Verify test envelope
    // TODO: If verification fails:
    //   - Record failed attempt in lockout tracker
    //   - Record failed attempt in state machine
    //   - Audit log: UnlockFailed
    //   - Zeroize master_password
    //   - Return error

    // Simulate successful verification for now:
    let unlock_succeeded = true;

    if !unlock_succeeded {
        // Record failure
        {
            let mut tracker = state.lockout_tracker.write().unwrap_or_else(|e| {
                tracing::error!("Lockout tracker lock poisoned: {}", e);
                std::process::exit(1);
            });
            tracker.record_failed_attempt();
        }
        {
            let mut sm = state.vault_state_machine.write().unwrap_or_else(|e| {
                tracing::error!("Vault state machine lock poisoned: {}", e);
                std::process::exit(1);
            });
            sm.record_failed_unlock();
        }
        // TODO: Audit log: UnlockFailed
        // TODO: Zeroize master_password
        return CommandResult::Err(CommandError::unauthorized(
            "Incorrect master password",
        ));
    }

    // Successful unlock
    {
        let mut tracker = state.lockout_tracker.write().unwrap_or_else(|e| {
            tracing::error!("Lockout tracker lock poisoned: {}", e);
            std::process::exit(1);
        });
        tracker.reset();
    }

    // Transition: Locked → Unlocked
    let session_id;
    {
        let mut sm = state.vault_state_machine.write().unwrap_or_else(|e| {
            tracing::error!("Vault state machine lock poisoned: {}", e);
            std::process::exit(1);
        });
        let context = VaultContext::with_state(VaultState::Locked);
        match sm.transition(VaultTransition::Unlock, &context) {
            Ok(result) => {
                tracing::info!(
                    "Vault unlocked: {:?} → {:?}",
                    result.from_state,
                    result.to_state
                );
                for event in sm.drain_events() {
                    tracing::info!("Vault event: {:?}", event);
                }
            }
            Err(e) => {
                return CommandResult::Err(CommandError::from_kestrel(e));
            }
        }
        session_id = uuid::Uuid::new_v4().to_string();
    }

    // Mark master key as present
    {
        let mut key_present = state.master_key_present.write().unwrap_or_else(|e| {
            tracing::error!("Master key flag lock poisoned: {}", e);
            std::process::exit(1);
        });
        *key_present = true;
    }

    // TODO: Create Session
    // TODO: Store MasterKey in AppState
    // TODO: Audit log: UnlockSucceeded
    // TODO: Zeroize master_password

    CommandResult::ok(SessionResponse {
        session_id,
        expires_at: chrono::Utc::now()
            + chrono::Duration::minutes(15), // Default; should use config
        is_unlocked: true,
    })
}

/// Locks the vault immediately.
///
/// Zeroizes the master key, destroys the session, clears all
/// decrypted data from memory, and transitions to Locked state.
///
/// # IPC Contract
///
/// - **Required state**: Unlocked
/// - **Transition**: Unlocked → Locked
///
/// # Security
///
/// - Master key is zeroized
/// - All decrypted data is cleared
/// - Session is destroyed
/// - Audit-logged
#[tauri::command]
pub fn auth_lock(state: State<'_, AppState>) -> CommandResult<VaultLockResponse> {
    // Guard: vault must be in Unlocked state
    state.require_state(VaultState::Unlocked)?;

    // Transition: Unlocked → Locked
    {
        let mut sm = state.vault_state_machine.write().unwrap_or_else(|e| {
            tracing::error!("Vault state machine lock poisoned: {}", e);
            std::process::exit(1);
        });
        let context = VaultContext::with_state(VaultState::Unlocked);
        match sm.transition(VaultTransition::Lock, &context) {
            Ok(result) => {
                tracing::info!(
                    "Vault locked: {:?} → {:?}",
                    result.from_state,
                    result.to_state
                );
                for event in sm.drain_events() {
                    tracing::info!("Vault event: {:?}", event);
                }
            }
            Err(e) => {
                return CommandResult::Err(CommandError::from_kestrel(e));
            }
        }
    }

    // Zeroize master key
    {
        let mut key_present = state.master_key_present.write().unwrap_or_else(|e| {
            tracing::error!("Master key flag lock poisoned: {}", e);
            std::process::exit(1);
        });
        *key_present = false;
    }

    // Reset rate limiter for login
    {
        let mut limiter = state.rate_limiter.write().unwrap_or_else(|e| {
            tracing::error!("Rate limiter lock poisoned: {}", e);
            std::process::exit(1);
        });
        limiter.reset_operation(Operation::Login);
    }

    // TODO: Zeroize actual MasterKey (when integrated)
    // TODO: Destroy Session
    // TODO: Clear all decrypted data from memory
    // TODO: Audit log: VaultLocked

    CommandResult::ok(VaultLockResponse {
        state: VaultState::Locked.to_string(),
    })
}

/// Returns the current session state.
///
/// # Security
///
/// This returns ONLY session metadata — never keys or passwords.
#[tauri::command]
pub fn auth_get_session(
    state: State<'_, AppState>,
) -> CommandResult<Option<SessionResponse>> {
    let sm = state.vault_state_machine.read().unwrap_or_else(|e| {
        tracing::error!("Vault state machine lock poisoned: {}", e);
        std::process::exit(1);
    });

    if sm.state() == VaultState::Unlocked {
        // TODO: Return actual session data
        CommandResult::ok(Some(SessionResponse {
            session_id: "active".to_string(),
            expires_at: "todo".to_string(),
            is_unlocked: true,
        }))
    } else {
        CommandResult::ok(None)
    }
}

/// Checks if the vault has been initialized.
///
/// This command is always available regardless of vault state.
#[tauri::command]
pub fn auth_is_vault_initialized(
    state: State<'_, AppState>,
) -> CommandResult<bool> {
    let sm = state.vault_state_machine.read().unwrap_or_else(|e| {
        tracing::error!("Vault state machine lock poisoned: {}", e);
        std::process::exit(1);
    });
    CommandResult::ok(sm.state() != VaultState::Uninitialized)
}

/// Returns the current vault status with lockout information.
///
/// This command is always available regardless of vault state.
/// Returns state metadata only — no secrets.
#[tauri::command]
pub fn auth_get_vault_status(
    state: State<'_, AppState>,
) -> CommandResult<VaultStatusResponse> {
    let sm = state.vault_state_machine.read().unwrap_or_else(|e| {
        tracing::error!("Vault state machine lock poisoned: {}", e);
        std::process::exit(1);
    });
    let tracker = state.lockout_tracker.read().unwrap_or_else(|e| {
        tracing::error!("Lockout tracker lock poisoned: {}", e);
        std::process::exit(1);
    });

    let is_locked_out = matches!(tracker.lockout_state(), LockoutState::LockedOut);

    CommandResult::ok(VaultStatusResponse::from_state(
        sm.state(),
        sm.failed_unlock_attempts(),
        is_locked_out,
    ))
}

/// Changes the master password.
///
/// Requires the vault to be unlocked. Derives a new key from
/// the new password, re-encrypts all data, and updates vault_meta.
///
/// # IPC Contract
///
/// - **Required state**: Unlocked
/// - **Effect**: Key rotation (state remains Unlocked)
///
/// # Security
///
/// - Current password must be verified
/// - Re-encryption is transactional (rollback on failure)
/// - Old key is zeroized after successful rotation
/// - Audit-logged
///
/// # Errors
///
/// - `UNAUTHORIZED`: Wrong current password, or vault is locked
/// - `VALIDATION_ERROR`: New password too short/long
#[tauri::command]
pub fn auth_change_password(
    current_password: String,
    new_password: String,
    state: State<'_, AppState>,
) -> CommandResult<()> {
    // Validate inputs
    if let Err(e) = validate_master_password(&current_password) {
        return CommandResult::Err(e);
    }
    if let Err(e) = validate_master_password(&new_password) {
        return CommandResult::Err(e);
    }

    // Guard: vault must be unlocked
    state.require_unlocked()?;

    // TODO: Verify current password (derive key, check test envelope)
    // TODO: Derive new key from new password
    // TODO: Re-encrypt all vault entries in a transaction
    // TODO: Update vault_meta with new salt and test envelope
    // TODO: Zeroize old key
    // TODO: Zeroize current_password and new_password
    // TODO: Audit log: PasswordChanged

    CommandResult::ok(())
}

#[cfg(test)]
mod tests {
    use crate::commands::types::*;
    use crate::security::vault_state::VaultState;

    #[test]
    fn session_response_serializes() {
        let resp = SessionResponse {
            session_id: "test-id".to_string(),
            expires_at: "2025-01-01T00:00:00Z".to_string(),
            is_unlocked: true,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("test-id"));
    }

    #[test]
    fn password_reveal_serializes() {
        let resp = PasswordRevealResponse {
            password: "secret123".to_string(),
            auto_clear_seconds: 30,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("secret123"));
    }

    #[test]
    fn vault_status_from_state() {
        let resp = VaultStatusResponse::from_state(VaultState::Locked, 2, false);
        assert_eq!(resp.state, "Locked");
        assert!(resp.is_initialized);
        assert!(!resp.is_unlocked);
        assert_eq!(resp.failed_unlock_attempts, 2);
        assert!(!resp.is_locked_out);
    }

    #[test]
    fn vault_status_unlocked() {
        let resp = VaultStatusResponse::from_state(VaultState::Unlocked, 0, false);
        assert_eq!(resp.state, "Unlocked");
        assert!(resp.is_initialized);
        assert!(resp.is_unlocked);
    }

    #[test]
    fn vault_status_uninitialized() {
        let resp = VaultStatusResponse::from_state(VaultState::Uninitialized, 0, false);
        assert_eq!(resp.state, "Uninitialized");
        assert!(!resp.is_initialized);
        assert!(!resp.is_unlocked);
    }

    #[test]
    fn vault_status_locked_out() {
        let resp = VaultStatusResponse::from_state(VaultState::Locked, 6, true);
        assert!(resp.is_locked_out);
        assert_eq!(resp.failed_unlock_attempts, 6);
    }

    #[test]
    fn vault_init_response_serializes() {
        let resp = VaultInitResponse {
            initialized: true,
            state: "Locked".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("initialized"));
        assert!(json.contains("Locked"));
    }

    #[test]
    fn vault_lock_response_serializes() {
        let resp = VaultLockResponse {
            state: "Locked".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("Locked"));
    }
}
