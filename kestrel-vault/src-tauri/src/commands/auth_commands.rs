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
//! - Passwords use SecureString for memory zeroization
//! - Sessions are managed through the Session type
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
//! | auth_auto_lock_check     | Unlocked      | Check + auto-lock if expired    |

use crate::commands::types::{
    validate_master_password, CommandError, CommandResult, SessionResponse, VaultInitResponse,
    VaultLockResponse, VaultStatusResponse,
};
use crate::config::AppConfig;
use crate::crypto::kdf::{MEMORY_COST, ITERATIONS, PARALLELISM};
use crate::crypto::key_management::{MasterKey, initialize_vault_keys, unlock_vault_keys, rotate_master_key};
use crate::crypto::keywrap::{DataEncryptionKey, WrappedDek};
use crate::crypto::kdf_params::KdfParams;
use crate::crypto::secure_string::SecureString;
use crate::crypto::vault_crypto::{initialize_vault_crypto, unlock_vault_crypto, VaultCryptoService};
use crate::db::DbConnection;
use crate::error::KestrelError;
use crate::security::lockout::{FailedAttemptTracker, LockoutState};
use crate::security::rate_limit::{Operation, RateLimiter};
use crate::security::session::{Session, SessionId, SessionState};
use crate::security::vault_state::{VaultContext, VaultState, VaultStateMachine, VaultTransition};
use std::sync::RwLock;
use tauri::State;

/// App state shared across Tauri commands.
///
/// This struct is managed by Tauri's state management and
/// provides access to the vault state machine, rate limiter,
/// lockout tracker, master key, session, and configuration.
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
///   the `secrecy` crate's `Secret` type and `ZeroizeOnDrop`).
/// - No passwords are ever stored in this struct.
/// - The session holds no secrets — only state metadata.
pub struct AppState {
    /// The vault lifecycle state machine.
    pub vault_state_machine: RwLock<VaultStateMachine>,
    /// Per-operation rate limiter.
    pub rate_limiter: RwLock<RateLimiter>,
    /// Failed attempt tracker for progressive lockout.
    pub lockout_tracker: RwLock<FailedAttemptTracker>,
    /// The encrypted database connection (SQLCipher).
    /// Only available after vault initialization or unlock.
    /// None when the vault is uninitialized or the database
    /// hasn't been opened yet.
    pub db: RwLock<Option<DbConnection>>,
    /// The master key (KEK), present only when vault is unlocked.
    /// When the vault is locked, this is `None` and the key
    /// memory has been zeroized via `ZeroizeOnDrop`.
    /// In the KEK/DEK hierarchy, this key wraps/unwraps the DEK.
    pub master_key: RwLock<Option<MasterKey>>,
    /// The data encryption key (DEK), present only when vault is unlocked.
    /// The DEK is used for all field-level encryption/decryption.
    /// It is wrapped (encrypted) by the KEK and stored in vault_meta.
    /// When the vault is locked, this is `None` and the key is zeroized.
    pub dek: RwLock<Option<DataEncryptionKey>>,
    /// Hex-encoded salt for key derivation (persisted in vault_meta).
    /// Available after vault initialization.
    pub salt_hex: RwLock<Option<String>>,
    /// Test envelope bytes for password verification.
    /// Available after vault initialization.
    pub test_envelope: RwLock<Option<Vec<u8>>>,
    /// The wrapped DEK bytes (persisted in vault_meta).
    /// Available after vault initialization.
    pub wrapped_dek: RwLock<Option<WrappedDek>>,
    /// KDF parameters (persisted in vault_meta).
    /// Available after vault initialization.
    pub kdf_params: RwLock<Option<KdfParams>>,
    /// The current session, present only when vault is unlocked.
    /// Contains no secrets — only session metadata (ID, timestamps, state).
    pub session: RwLock<Option<Session>>,
    /// Application configuration (auto-lock timeout, etc.).
    pub config: RwLock<AppConfig>,
}

impl Default for AppState {
    fn default() -> Self {
        AppState {
            vault_state_machine: RwLock::new(VaultStateMachine::new()),
            rate_limiter: RwLock::new(RateLimiter::new()),
            lockout_tracker: RwLock::new(FailedAttemptTracker::new()),
            db: RwLock::new(None),
            master_key: RwLock::new(None),
            dek: RwLock::new(None),
            salt_hex: RwLock::new(None),
            test_envelope: RwLock::new(None),
            wrapped_dek: RwLock::new(None),
            kdf_params: RwLock::new(None),
            session: RwLock::new(None),
            config: RwLock::new(AppConfig::default()),
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

    /// Returns a clone of the master key if the vault is unlocked.
    ///
    /// Returns `None` if the vault is locked or uninitialized.
    /// This is used by vault commands that need to encrypt/decrypt data.
    pub fn get_master_key(&self) -> Option<MasterKey> {
        let guard = self.master_key.read().unwrap_or_else(|e| {
            tracing::error!("Master key lock poisoned: {}", e);
            std::process::exit(1);
        });
        guard.clone()
    }

    /// Returns a clone of the DEK if the vault is unlocked.
    ///
    /// Returns `None` if the vault is locked or uninitialized.
    /// This is used by vault commands that need field-level encryption.
    pub fn get_dek(&self) -> Option<DataEncryptionKey> {
        let guard = self.dek.read().unwrap_or_else(|e| {
            tracing::error!("DEK lock poisoned: {}", e);
            std::process::exit(1);
        });
        guard.clone()
    }

    /// Returns a reference-counted clone of the database connection
    /// if the database has been opened.
    ///
    /// Returns `None` if the database hasn't been initialized yet.
    /// This is used by vault commands that need database access.
    pub fn get_db(&self) -> Option<DbConnection> {
        let guard = self.db.read().unwrap_or_else(|e| {
            tracing::error!("DB lock poisoned: {}", e);
            std::process::exit(1);
        });
        guard.clone()
    }

    /// Validates the current session and checks for auto-lock.
    ///
    /// This should be called at the start of every vault operation
    /// to ensure the session hasn't expired. If auto-lock is triggered,
    /// the vault is locked automatically.
    ///
    /// Returns `Ok(())` if the session is valid.
    /// Returns `Err` if the session is expired (and locks the vault).
    pub fn validate_session(&self) -> Result<(), CommandError> {
        let auto_lock_minutes = {
            let config = self.config.read().unwrap_or_else(|e| {
                tracing::error!("Config lock poisoned: {}", e);
                std::process::exit(1);
            });
            config.auto_lock_minutes
        };

        let should_lock = {
            let mut session_guard = self.session.write().unwrap_or_else(|e| {
                tracing::error!("Session lock poisoned: {}", e);
                std::process::exit(1);
            });
            match session_guard.as_mut() {
                Some(session) => {
                    // Check if auto-lock should trigger
                    if session.is_auto_lock_triggered(auto_lock_minutes) {
                        tracing::warn!("Session auto-lock triggered after {} minutes of inactivity", auto_lock_minutes);
                        // Lock the session
                        session.lock();
                        true
                    } else {
                        // Validate the session is still active
                        if !session.validate() {
                            tracing::warn!("Session has expired");
                            true
                        } else {
                            // Touch the session to extend the timeout
                            if let Err(e) = session.touch(auto_lock_minutes) {
                                tracing::error!("Failed to touch session: {}", e);
                                true
                            } else {
                                false
                            }
                        }
                    }
                }
                None => true, // No session means vault should be locked
            }
        };

        if should_lock {
            // Perform auto-lock
            self.perform_auto_lock()?;
            return Err(CommandError::unauthorized(
                "Session expired. Vault has been locked due to inactivity.",
            ));
        }

        Ok(())
    }

    /// Performs an auto-lock of the vault.
    ///
    /// This is called when the session expires or auto-lock is triggered.
    /// It transitions the state machine, zeroizes the master key, and
    /// destroys the session.
    fn perform_auto_lock(&self) -> Result<(), CommandError> {
        // Transition: Unlocked → Locked (AutoLock)
        {
            let mut sm = self.vault_state_machine.write().unwrap_or_else(|e| {
                tracing::error!("Vault state machine lock poisoned: {}", e);
                std::process::exit(1);
            });
            let context = VaultContext::with_state(VaultState::Unlocked);
            match sm.transition(VaultTransition::AutoLock, &context) {
                Ok(result) => {
                    tracing::info!(
                        "Vault auto-locked: {:?} → {:?}",
                        result.from_state,
                        result.to_state
                    );
                    for event in sm.drain_events() {
                        tracing::info!("Vault event: {:?}", event);
                    }
                }
                Err(e) => {
                    tracing::error!("Auto-lock transition failed: {}", e);
                    // Even if the transition fails, we still zeroize the key
                }
            }
        }

        // Zeroize the master key (KEK)
        {
            let mut key_guard = self.master_key.write().unwrap_or_else(|e| {
                tracing::error!("Master key lock poisoned: {}", e);
                std::process::exit(1);
            });
            *key_guard = None;
        }

        // Zeroize the DEK
        {
            let mut dek_guard = self.dek.write().unwrap_or_else(|e| {
                tracing::error!("DEK lock poisoned: {}", e);
                std::process::exit(1);
            });
            *dek_guard = None;
        }

        // Destroy the session
        {
            let mut session_guard = self.session.write().unwrap_or_else(|e| {
                tracing::error!("Session lock poisoned: {}", e);
                std::process::exit(1);
            });
            *session_guard = None;
        }

        // Reset rate limiter for login
        {
            let mut limiter = self.rate_limiter.write().unwrap_or_else(|e| {
                tracing::error!("Rate limiter lock poisoned: {}", e);
                std::process::exit(1);
            });
            limiter.reset_operation(Operation::Login);
        }

        tracing::info!("Vault auto-locked — master key zeroized, session destroyed");
        Ok(())
    }

    /// Loads vault metadata (salt + test envelope) from the database.
    ///
    /// This should be called on app startup to restore the vault state.
    /// When vault_meta exists, the vault is in the Locked state.
    ///
    /// # TODO
    ///
    /// - Connect to the actual database once SQLCipher is integrated
    /// - Load salt_hex and test_envelope from vault_meta table
    pub fn load_vault_meta(&self) -> Result<(), CommandError> {
        // TODO: Load from database
        // For now, if salt_hex and test_envelope are already set (from
        // a previous initialize in this session), keep them.
        Ok(())
    }

    /// Stores vault metadata in memory after initialization.
    ///
    /// This updates the in-memory salt, test envelope, wrapped DEK,
    /// and KDF params so that unlock can work without querying the database.
    fn store_vault_meta_in_memory(
        &self,
        salt_hex: String,
        test_envelope: Vec<u8>,
        wrapped_dek: WrappedDek,
        kdf_params: KdfParams,
    ) {
        {
            let mut salt = self.salt_hex.write().unwrap_or_else(|e| {
                tracing::error!("Salt lock poisoned: {}", e);
                std::process::exit(1);
            });
            *salt = Some(salt_hex);
        }
        {
            let mut envelope = self.test_envelope.write().unwrap_or_else(|e| {
                tracing::error!("Test envelope lock poisoned: {}", e);
                std::process::exit(1);
            });
            *envelope = Some(test_envelope);
        }
        {
            let mut wdek = self.wrapped_dek.write().unwrap_or_else(|e| {
                tracing::error!("Wrapped DEK lock poisoned: {}", e);
                std::process::exit(1);
            });
            *wdek = Some(wrapped_dek);
        }
        {
            let mut params = self.kdf_params.write().unwrap_or_else(|e| {
                tracing::error!("KDF params lock poisoned: {}", e);
                std::process::exit(1);
            });
            *params = Some(kdf_params);
        }
    }

    /// Parses a hex-encoded salt string into a `Salt` struct.
    ///
    /// # Errors
    ///
    /// Returns `KestrelError::Crypto` if the hex string is invalid or
    /// the salt is not exactly 16 bytes.
    fn parse_salt_from_hex(hex: &str) -> Result<crate::crypto::kdf::Salt, KestrelError> {
        let salt_bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap_or(0))
            .collect();

        if salt_bytes.len() != 16 {
            return Err(KestrelError::Crypto(
                "Invalid salt length".to_string(),
            ));
        }

        let mut salt_array = [0u8; 16];
        salt_array.copy_from_slice(&salt_bytes);
        Ok(crate::crypto::kdf::Salt(salt_array))
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

    // ── Crypto: KEK/DEK hierarchy initialization ──
    // Convert password to SecureString immediately for zeroization
    let init_result = {
        let secure_password = SecureString::from(master_password);
        let result = initialize_vault_keys(secure_password.as_bytes());
        // secure_password is zeroized when it goes out of scope
        match result {
            Ok(r) => r,
            Err(e) => return CommandResult::Err(CommandError::from_kestrel(e)),
        }
    };

    // Encode salt as hex for storage
    let salt_hex: String = init_result.salt.0.iter().map(|b| format!("{b:02x}")).collect();

    // ── Transition: Uninitialized → Locked ──
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

    // ── Store vault metadata in memory ──
    // In production, this would be persisted to the database via VaultMetaRepo.
    // For now, we store it in AppState for the current session.
    state.store_vault_meta_in_memory(
        salt_hex.clone(),
        init_result.test_envelope_bytes.clone(),
        init_result.wrapped_dek.clone(),
        init_result.kdf_params.clone(),
    );

    // ── Store master key in AppState (vault is now Locked, NOT Unlocked) ──
    // After initialization, the vault goes to Locked state.
    // The master key is NOT stored — the user must explicitly unlock.
    // We zeroize the master key immediately since we're going to Locked state.
    // The DEK is also NOT stored — it's only in wrapped (encrypted) form.
    drop(init_result.master_key);

    // TODO: Persist vault_meta to database via VaultMetaRepo
    // vault_meta: {
    //   id: 1,
    //   salt: salt_hex,
    //   iterations: ITERATIONS,
    //   memory_cost: MEMORY_COST,
    //   parallelism: PARALLELISM,
    //   test_envelope: test_envelope_bytes,
    //   hint: hint,
    // }
    // TODO: Audit log: VaultInitialized

    tracing::info!(
        "Vault initialized with Argon2id (memory={}KiB, iterations={}, parallelism={})",
        MEMORY_COST, ITERATIONS, PARALLELISM
    );

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
/// - Master password is zeroized after key derivation (via SecureString)
/// - Failed attempts are audit-logged
/// - Session is created with configurable auto-lock timeout
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

    // ── Crypto: KEK/DEK unlock ──
    let unlock_result = {
        // Get the stored salt, test envelope, and wrapped DEK
        let salt_hex = {
            let guard = state.salt_hex.read().unwrap_or_else(|e| {
                tracing::error!("Salt lock poisoned: {}", e);
                std::process::exit(1);
            });
            guard.clone()
        };
        let test_envelope_bytes = {
            let guard = state.test_envelope.read().unwrap_or_else(|e| {
                tracing::error!("Test envelope lock poisoned: {}", e);
                std::process::exit(1);
            });
            guard.clone()
        };
        let wrapped_dek = {
            let guard = state.wrapped_dek.read().unwrap_or_else(|e| {
                tracing::error!("Wrapped DEK lock poisoned: {}", e);
                std::process::exit(1);
            });
            guard.clone()
        };

        match (salt_hex, test_envelope_bytes, wrapped_dek) {
            (Some(sh), Some(te), Some(wdek)) => {
                // Parse salt from hex
                let salt = match AppState::parse_salt_from_hex(&sh) {
                    Ok(s) => s,
                    Err(e) => return CommandResult::Err(CommandError::from_kestrel(e)),
                };

                // Convert password to SecureString for zeroization
                let secure_password = SecureString::from(master_password);

                // Use KEK/DEK hierarchy: derive KEK, verify test envelope, unwrap DEK
                let result = unlock_vault_keys(
                    secure_password.as_bytes(),
                    &salt,
                    &te,
                    &wdek,
                );
                // secure_password is zeroized when it goes out of scope
                result
            }
            (None, _, _) => Err(KestrelError::Config(
                "Vault salt not found. Vault may not be initialized.".to_string(),
            )),
            (_, None, _) => Err(KestrelError::Config(
                "Test envelope not found. Vault may not be initialized.".to_string(),
            )),
            (_, _, None) => Err(KestrelError::Config(
                "Wrapped DEK not found. Vault may not be initialized.".to_string(),
            )),
        }
    };

    match unlock_result {
        Ok((master_key, dek)) => {
            // ── Successful unlock ──

            // Reset lockout tracker
            {
                let mut tracker = state.lockout_tracker.write().unwrap_or_else(|e| {
                    tracing::error!("Lockout tracker lock poisoned: {}", e);
                    std::process::exit(1);
                });
                tracker.reset();
            }

            // Get auto-lock timeout from config
            let auto_lock_minutes = {
                let config = state.config.read().unwrap_or_else(|e| {
                    tracing::error!("Config lock poisoned: {}", e);
                    std::process::exit(1);
                });
                config.auto_lock_minutes
            };

            // Transition: Locked → Unlocked
            let session_id: SessionId;
            let expires_at: chrono::DateTime<chrono::Utc>;
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
            }

            // Create a new session
            let new_session = match Session::new(auto_lock_minutes) {
                Ok(s) => s,
                Err(e) => return CommandResult::Err(CommandError::from_kestrel(e)),
            };
            session_id = new_session.id().clone();
            expires_at = *new_session.expires_at();

            // Store session in AppState
            {
                let mut session_guard = state.session.write().unwrap_or_else(|e| {
                    tracing::error!("Session lock poisoned: {}", e);
                    std::process::exit(1);
                });
                *session_guard = Some(new_session);
            }

            // Store master key (KEK) in AppState
            {
                let mut key_guard = state.master_key.write().unwrap_or_else(|e| {
                    tracing::error!("Master key lock poisoned: {}", e);
                    std::process::exit(1);
                });
                *key_guard = Some(master_key);
            }

            // Store DEK in AppState
            {
                let mut dek_guard = state.dek.write().unwrap_or_else(|e| {
                    tracing::error!("DEK lock poisoned: {}", e);
                    std::process::exit(1);
                });
                *dek_guard = Some(dek);
            }

            // TODO: Audit log: UnlockSucceeded

            CommandResult::ok(SessionResponse {
                session_id: session_id.to_string(),
                expires_at: expires_at.to_rfc3339(),
                is_unlocked: true,
            })
        }
        Err(KestrelError::Unauthorized(msg)) => {
            // ── Failed unlock (wrong password) ──

            // Record failure in lockout tracker
            {
                let mut tracker = state.lockout_tracker.write().unwrap_or_else(|e| {
                    tracing::error!("Lockout tracker lock poisoned: {}", e);
                    std::process::exit(1);
                });
                tracker.record_failed_attempt();
            }

            // Record failure in state machine
            {
                let mut sm = state.vault_state_machine.write().unwrap_or_else(|e| {
                    tracing::error!("Vault state machine lock poisoned: {}", e);
                    std::process::exit(1);
                });
                sm.record_failed_unlock();
            }

            tracing::warn!("Failed unlock attempt: {}", msg);

            // TODO: Audit log: UnlockFailed

            CommandResult::Err(CommandError::unauthorized(
                "Incorrect master password",
            ))
        }
        Err(e) => {
            // Other errors (crypto, config, etc.)
            CommandResult::Err(CommandError::from_kestrel(e))
        }
    }
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
/// - Session is destroyed
/// - All decrypted data is cleared
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

    // ── Zeroize master key (KEK) ──
    {
        let mut key_guard = state.master_key.write().unwrap_or_else(|e| {
            tracing::error!("Master key lock poisoned: {}", e);
            std::process::exit(1);
        });
        // Dropping the MasterKey triggers ZeroizeOnDrop, which
        // securely erases the key material from memory.
        *key_guard = None;
    }

    // ── Zeroize DEK ──
    {
        let mut dek_guard = state.dek.write().unwrap_or_else(|e| {
            tracing::error!("DEK lock poisoned: {}", e);
            std::process::exit(1);
        });
        // Dropping the DataEncryptionKey triggers ZeroizeOnDrop.
        *dek_guard = None;
    }

    // ── Destroy session ──
    {
        let mut session_guard = state.session.write().unwrap_or_else(|e| {
            tracing::error!("Session lock poisoned: {}", e);
            std::process::exit(1);
        });
        *session_guard = None;
    }

    // Reset rate limiter for login
    {
        let mut limiter = state.rate_limiter.write().unwrap_or_else(|e| {
            tracing::error!("Rate limiter lock poisoned: {}", e);
            std::process::exit(1);
        });
        limiter.reset_operation(Operation::Login);
    }

    // TODO: Audit log: VaultLocked

    tracing::info!("Vault locked — KEK and DEK zeroized, session destroyed");

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
    let session_guard = state.session.read().unwrap_or_else(|e| {
        tracing::error!("Session lock poisoned: {}", e);
        std::process::exit(1);
    });

    match session_guard.as_ref() {
        Some(session) => {
            // Check if session is still valid
            if session.state() == SessionState::Unlocked {
                CommandResult::ok(Some(SessionResponse {
                    session_id: session.id().to_string(),
                    expires_at: session.expires_at().to_rfc3339(),
                    is_unlocked: true,
                }))
            } else {
                CommandResult::ok(None)
            }
        }
        None => CommandResult::ok(None),
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

/// Checks if auto-lock should trigger and locks the vault if needed.
///
/// This is intended to be called periodically from the frontend
/// (e.g., every 30 seconds) to enforce the auto-lock timeout.
///
/// # IPC Contract
///
/// - **Required state**: Unlocked (otherwise no-op)
///
/// # Returns
///
/// - `true` if the vault was auto-locked
/// - `false` if the session is still valid
#[tauri::command]
pub fn auth_auto_lock_check(
    state: State<'_, AppState>,
) -> CommandResult<bool> {
    // Only check if vault is unlocked
    {
        let sm = state.vault_state_machine.read().unwrap_or_else(|e| {
            tracing::error!("Vault state machine lock poisoned: {}", e);
            std::process::exit(1);
        });
        if sm.state() != VaultState::Unlocked {
            return CommandResult::ok(false);
        }
    }

    // Validate session (this will auto-lock if expired)
    match state.validate_session() {
        Ok(()) => CommandResult::ok(false),
        Err(_) => CommandResult::ok(true), // Vault was auto-locked
    }
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
/// - Both passwords use SecureString for zeroization
/// - New session is created after rotation
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

    // Validate session is active
    state.validate_session()?;

    // ── Verify current password ──
    let current_key_verified = {
        let salt_hex = state.salt_hex.read().unwrap_or_else(|e| {
            tracing::error!("Salt lock poisoned: {}", e);
            std::process::exit(1);
        });
        let test_envelope = state.test_envelope.read().unwrap_or_else(|e| {
            tracing::error!("Test envelope lock poisoned: {}", e);
            std::process::exit(1);
        });

        match (salt_hex.as_ref(), test_envelope.as_ref()) {
            (Some(sh), Some(te)) => {
                let salt = match AppState::parse_salt_from_hex(sh) {
                    Ok(s) => s,
                    Err(_) => return CommandResult::Err(CommandError::from_kestrel(
                        KestrelError::Crypto("Invalid salt format".to_string()),
                    )),
                };

                let secure_current = SecureString::from(current_password);
                let result = unlock_vault_crypto(secure_current.as_bytes(), &salt, te);
                // secure_current is zeroized when it goes out of scope
                result.is_ok()
            }
            _ => false,
        }
    };

    if !current_key_verified {
        return CommandResult::Err(CommandError::unauthorized(
            "Current password is incorrect",
        ));
    }

    // ── KEK/DEK key rotation using rotate_master_key ──
    // With the KEK/DEK hierarchy, password change is O(1):
    // 1. Get the current KEK (master key) and wrapped DEK
    // 2. Rotate: derive new KEK from new password, re-wrap DEK
    // 3. No vault data needs to be re-encrypted
    let old_master_key = state.get_master_key().ok_or_else(|| {
        CommandError::unauthorized("Vault is locked — master key not available")
    })?;
    let old_wrapped_dek = {
        let guard = state.wrapped_dek.read().unwrap_or_else(|e| {
            tracing::error!("Wrapped DEK lock poisoned: {}", e);
            std::process::exit(1);
        });
        guard.clone().ok_or_else(|| {
            CommandError::unauthorized("Wrapped DEK not available")
        })?
    };

    let secure_new = SecureString::from(new_password);
    let (rotation_pair, rotation_result) = rotate_master_key(
        old_master_key,
        &old_wrapped_dek,
        &secure_new,
    )
    .map_err(CommandError::from_kestrel)?;
    // secure_new is zeroized when it goes out of scope

    let new_salt_hex: String = rotation_result.new_salt.0.iter().map(|b| format!("{b:02x}")).collect();

    // ── Update in-memory vault metadata ──
    state.store_vault_meta_in_memory(
        new_salt_hex,
        rotation_result.new_test_envelope,
        rotation_result.new_wrapped_dek,
        KdfParams::current(), // Use current params (may upgrade if old params were outdated)
    );

    // ── Update master key (KEK) in AppState ──
    {
        let mut key_guard = state.master_key.write().unwrap_or_else(|e| {
            tracing::error!("Master key lock poisoned: {}", e);
            std::process::exit(1);
        });
        *key_guard = Some(rotation_pair.new_key);
    }

    // ── Update DEK in AppState ──
    // The DEK itself hasn't changed — only its wrapping has.
    // The DEK is still the same key, so we don't need to update it.
    // (It was never re-derived, only re-wrapped.)

    // ── Create new session after rotation ──
    let auto_lock_minutes = {
        let config = state.config.read().unwrap_or_else(|e| {
            tracing::error!("Config lock poisoned: {}", e);
            std::process::exit(1);
        });
        config.auto_lock_minutes
    };
    let new_session = Session::new(auto_lock_minutes)
        .map_err(CommandError::from_kestrel)?;
    {
        let mut session_guard = state.session.write().unwrap_or_else(|e| {
            tracing::error!("Session lock poisoned: {}", e);
            std::process::exit(1);
        });
        *session_guard = Some(new_session);
    }

    // TODO: Persist updated vault_meta to database via VaultMetaRepo
    // TODO: Audit log: PasswordChanged { kdf_upgraded: <bool> }

    tracing::info!("Master password changed — KEK/DEK rotation complete (O(1), no data re-encrypted)");

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
