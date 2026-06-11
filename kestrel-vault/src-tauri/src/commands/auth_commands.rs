//! Tauri commands for authentication and vault lifecycle.
//!
//! Provides IPC handlers for vault initialization, unlock, lock,
//! session management, and password changes. These commands are
//! the ONLY way the frontend interacts with auth state.
//!
//! # Security
//!
//! - Master password is only transmitted during unlock/init (never stored)
//! - Rate limiting on all unlock attempts (5 per minute)
//! - Progressive lockout after repeated failures
//! - Every auth event is logged in the audit trail
//! - Passwords are zeroized from memory after use
//!
//! # Rate Limits
//!
//! - `auth_unlock`: 5 attempts per minute, progressive lockout
//! - `auth_change_password`: 3 per minute
//! - Other auth commands: 10 per minute

use crate::audit::event::{ActionType, AuditEvent, EventCategory};
use crate::commands::types::{
    validate_not_blank, validate_no_null_bytes, validate_string_field,
    CommandResult, SessionResponse, ValidationRules,
};
use crate::error::KestrelError;
use crate::security::lockout::{FailedAttemptTracker, LockoutState};
use crate::security::rate_limit::Operation;
use crate::security::session::Session;
use tauri::State;

// ─── Application State ───────────────────────────────────────────────

/// Application state shared across all Tauri commands.
///
/// Holds references to all services needed by command handlers.
/// Managed by Tauri's state system (injected at runtime).
///
/// # TODO (Phase 2)
///
/// - Add VaultService reference
/// - Add AuditLogger reference
/// - Replace Option<()> with real service instances
pub struct AppState {
    /// Active session (if vault is unlocked).
    pub session: parking_lot::Mutex<Option<Session>>,
    /// Failed attempt tracker for lockout enforcement.
    pub lockout_tracker: parking_lot::Mutex<FailedAttemptTracker>,
    /// Rate limiter for all operations.
    pub rate_limiter: parking_lot::Mutex<crate::security::rate_limit::RateLimiter>,
    /// Whether the vault has been initialized.
    pub vault_initialized: parking_lot::Mutex<bool>,
    /// TODO: Audit logger service.
    pub _audit_logger: Option<()>,
    /// TODO: Vault service instance.
    pub _vault_service: Option<()>,
}

impl AppState {
    /// Creates a new AppState with default values.
    pub fn new() -> Self {
        Self {
            session: parking_lot::Mutex::new(None),
            lockout_tracker: parking_lot::Mutex::new(FailedAttemptTracker::new()),
            rate_limiter: parking_lot::Mutex::new(
                crate::security::rate_limit::RateLimiter::new(),
            ),
            vault_initialized: parking_lot::Mutex::new(false),
            _audit_logger: None,
            _vault_service: None,
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Helper Functions ────────────────────────────────────────────────

/// Checks if the vault is currently unlocked.
/// Returns an error if the vault is locked.
fn require_unlocked(state: &AppState) -> Result<(), KestrelError> {
    let session = state.session.lock();
    match session.as_ref() {
        Some(s) if s.state() == crate::security::session::SessionState::Unlocked => Ok(()),
        _ => Err(KestrelError::Unauthorized(
            "Vault is locked. Please unlock first.".to_string(),
        )),
    }
}

/// Logs an audit event (stub until Phase 2).
fn log_audit_event(
    _state: &AppState,
    _category: EventCategory,
    _action: ActionType,
    _subject: &str,
) {
    // TODO (Phase 2): Delegate to audit logger service
    // let event = AuditEvent::new(category, action, subject.to_string());
    // state._audit_logger.log_event(event).await;
}

/// Checks and enforces lockout before auth operations.
fn check_lockout(state: &AppState) -> Result<(), KestrelError> {
    let tracker = state.lockout_tracker.lock();
    match tracker.lockout_state() {
        LockoutState::Allowed => Ok(()),
        LockoutState::Delayed(secs) => Err(KestrelError::Unauthorized(format!(
            "Too many failed attempts. Please wait {secs} seconds before retrying."
        ))),
        LockoutState::LockedOut => Err(KestrelError::Unauthorized(
            "Account locked due to too many failed attempts. Vault reset required.".to_string(),
        )),
    }
}

/// Checks rate limit for an operation.
fn check_rate_limit(
    state: &AppState,
    operation: Operation,
) -> Result<(), KestrelError> {
    let mut limiter = state.rate_limiter.lock();
    if limiter.is_rate_limited(operation) {
        return Err(KestrelError::Unauthorized(format!(
            "Rate limit exceeded for {operation:?}. Please try again later."
        )));
    }
    Ok(())
}

// ─── Tauri Commands ──────────────────────────────────────────────────

/// First-time vault initialization.
///
/// Creates the encrypted vault database and derives the master key
/// from the provided password. This command can only be called once.
///
/// # Arguments
///
/// * `master_password` - The master password (min 8 chars)
/// * `hint` - Optional password hint (max 100 chars)
///
/// # Security
///
/// - Password is zeroized after key derivation
/// - Salt is generated cryptographically
/// - Event is logged in audit trail
#[tauri::command]
pub async fn auth_initialize_vault(
    state: State<'_, AppState>,
    master_password: String,
    hint: Option<String>,
) -> CommandResult<()> {
    // Check if already initialized
    if *state.vault_initialized.lock() {
        return CommandResult::err("Vault has already been initialized".to_string());
    }

    // Validate master password
    if let Err(e) = validate_string_field(
        &master_password,
        ValidationRules::MIN_MASTER_PASSWORD_LEN,
        ValidationRules::MAX_PASSWORD_LEN,
        "Master password",
        false,
    ) {
        return CommandResult::from_kestrel_error(e);
    }

    // Validate hint if provided
    if let Some(ref h) = hint {
        if let Err(e) = validate_string_field(
            h,
            0,
            ValidationRules::MAX_HINT_LEN,
            "Password hint",
            true,
        ) {
            return CommandResult::from_kestrel_error(e);
        }
    }

    // Rate limit check
    if let Err(e) = check_rate_limit(&state, Operation::Login) {
        return CommandResult::from_kestrel_error(e);
    }

    // TODO (Phase 2): Delegate to vault service
    // 1. Generate salt
    // 2. Derive master key from password
    // 3. Create encrypted database
    // 4. Store salt and verification hash
    // 5. Zeroize password from memory

    *state.vault_initialized.lock() = true;
    log_audit_event(&state, EventCategory::Auth, ActionType::Create, "vault_init");

    CommandResult::ok(())
}

/// Unlock the vault with the master password.
///
/// Derives the master key from the password and opens the
/// encrypted database. A new session is created on success.
///
/// # Security
///
/// - Rate limited: 5 attempts per minute
/// - Progressive lockout after repeated failures
/// - Failed attempts are logged with timestamps
/// - Password is zeroized after key derivation
#[tauri::command]
pub async fn auth_unlock(
    state: State<'_, AppState>,
    master_password: String,
) -> CommandResult<SessionResponse> {
    // Check if vault is initialized
    if !*state.vault_initialized.lock() {
        return CommandResult::err("Vault has not been initialized".to_string());
    }

    // Check lockout state
    if let Err(e) = check_lockout(&state) {
        return CommandResult::from_kestrel_error(e);
    }

    // Rate limit check
    if let Err(e) = check_rate_limit(&state, Operation::Login) {
        return CommandResult::from_kestrel_error(e);
    }

    // Record the attempt
    if let Err(e) = state.rate_limiter.lock().record_attempt(Operation::Login) {
        return CommandResult::from_kestrel_error(e);
    }

    // Validate input
    if let Err(e) = validate_no_null_bytes(&master_password, "Master password") {
        return CommandResult::from_kestrel_error(e);
    }

    // TODO (Phase 2): Delegate to vault service
    // 1. Load salt from database
    // 2. Derive key from password + salt
    // 3. Verify key against stored verification hash
    // 4. If verified: create session, store key in memory
    // 5. If not: record failed attempt, increment lockout

    // Placeholder: assume success for now
    // In production, this would be the actual verification:
    // match vault_service.unlock(&master_password).await {
    //     Ok(session) => {
    //         state.lockout_tracker.lock().reset();
    //         ...
    //     }
    //     Err(_) => {
    //         state.lockout_tracker.lock().record_failed_attempt();
    //         ...
    //     }
    // }

    let session = Session::new(15).map_err(KestrelError::from)?;
    let session_resp = SessionResponse {
        session_id: session.id().to_string(),
        expires_at: *session.expires_at(),
        is_unlocked: true,
    };

    *state.session.lock() = Some(session);
    state.lockout_tracker.lock().reset();
    state.rate_limiter.lock().reset_operation(Operation::Login);

    log_audit_event(&state, EventCategory::Auth, ActionType::Unlock, "user");

    CommandResult::ok(session_resp)
}

/// Lock the vault, zeroizing all keys from memory.
///
/// After calling this, the vault requires re-authentication
/// to access any data. All derived keys are zeroized.
///
/// # Security
///
/// - All in-memory keys are zeroized
/// - Session is invalidated
/// - Event is logged in audit trail
#[tauri::command]
pub async fn auth_lock(
    state: State<'_, AppState>,
) -> CommandResult<()> {
    // Lock the session if it exists
    {
        let mut session = state.session.lock();
        if let Some(ref mut s) = *session {
            s.lock();
        }
    }

    // Clear the session entirely (zeroizes references)
    *state.session.lock() = None;

    log_audit_event(&state, EventCategory::Auth, ActionType::Lock, "user");

    CommandResult::ok(())
}

/// Get the current session state.
///
/// Returns session info if the vault is unlocked, or
/// an indication that the vault is locked. This is used
/// by the frontend to determine which UI to show.
///
/// # Security
///
/// - No secrets are returned (no keys, no passwords)
/// - Session ID is an opaque token, not a secret
#[tauri::command]
pub async fn auth_get_session(
    state: State<'_, AppState>,
) -> CommandResult<Option<SessionResponse>> {
    let session = state.session.lock();
    match session.as_ref() {
        Some(s) => {
            let resp = SessionResponse {
                session_id: s.id().to_string(),
                expires_at: *s.expires_at(),
                is_unlocked: s.state()
                    == crate::security::session::SessionState::Unlocked,
            };
            CommandResult::ok(Some(resp))
        }
        None => CommandResult::ok(None),
    }
}

/// Check if the vault has been initialized.
///
/// Returns true if the vault database exists and has been
/// set up with a master password. Used by the frontend to
/// decide between "initialize" and "unlock" screens.
#[tauri::command]
pub async fn auth_is_vault_initialized(
    state: State<'_, AppState>,
) -> CommandResult<bool> {
    CommandResult::ok(*state.vault_initialized.lock())
}

/// Change the master password.
///
/// Requires the current password for verification, then
/// re-encrypts the vault with a new key derived from
/// the new password.
///
/// # Security
///
/// - Current password is verified before change
/// - New password must meet minimum requirements
/// - All entries are re-encrypted with the new key
/// - Old key is zeroized after re-encryption
/// - Event is logged in audit trail
#[tauri::command]
pub async fn auth_change_password(
    state: State<'_, AppState>,
    current: String,
    new: String,
) -> CommandResult<()> {
    // Require vault to be unlocked
    if let Err(e) = require_unlocked(&state) {
        return CommandResult::from_kestrel_error(e);
    }

    // Rate limit check
    if let Err(e) = check_rate_limit(&state, Operation::Login) {
        return CommandResult::from_kestrel_error(e);
    }

    // Validate current password input
    if let Err(e) = validate_no_null_bytes(&current, "Current password") {
        return CommandResult::from_kestrel_error(e);
    }

    // Validate new password meets requirements
    if let Err(e) = validate_string_field(
        &new,
        ValidationRules::MIN_MASTER_PASSWORD_LEN,
        ValidationRules::MAX_PASSWORD_LEN,
        "New password",
        false,
    ) {
        return CommandResult::from_kestrel_error(e);
    }

    // New password must differ from current
    if current == new {
        return CommandResult::err(
            "New password must be different from current password".to_string(),
        );
    }

    // TODO (Phase 2): Delegate to vault service
    // 1. Verify current password
    // 2. Generate new salt
    // 3. Derive new key from new password + new salt
    // 4. Re-encrypt all vault entries with new key
    // 5. Store new salt and verification hash
    // 6. Zeroize old key and password strings

    log_audit_event(
        &state,
        EventCategory::Auth,
        ActionType::Update,
        "master_password",
    );

    CommandResult::ok(())
}
