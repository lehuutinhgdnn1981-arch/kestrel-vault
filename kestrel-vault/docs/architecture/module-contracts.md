# Module Public API Contracts — KESTREL Vault

## Dependency Graph

```
commands ──→ vault ──→ crypto
   │           │        │
   │           └──→ db ←┘
   │                  ↑
   ├──→ audit ────────┘
   ├──→ scanner ──→ crypto
   │                │
   │                └──→ db
   ├──→ security ──→ crypto
   │                │
   │                └──→ config
   └──→ config (standalone)

crypto (standalone — no internal deps)
db (standalone — no internal deps)
config (standalone — no internal deps)
```

## Module: `crypto`

### Public Types
| Type | Description |
|------|-------------|
| `MasterKey` | Master encryption key (ZeroizeOnDrop, secrecy-wrapped) |
| `DerivedKey` | Derived key from Argon2id (Zeroize) |
| `Salt` | 16-byte cryptographically random salt |
| `Ciphertext` | AES-256-GCM ciphertext (newtype) |
| `Nonce` | 96-bit AES-GCM nonce (newtype) |
| `AeadTag` | 128-bit GCM authentication tag |
| `EncryptedEnvelope` | Versioned envelope with nonce + ciphertext + tag |
| `EnvelopeVersion` | Format version enum (V1) |
| `AadContext` | Additional Authenticated Data context |

### Public Functions
| Function | Signature | Description |
|----------|-----------|-------------|
| `derive_key` | `(password, salt) → DerivedKey` | Argon2id key derivation |
| `encrypt` | `(key, plaintext, aad) → (Nonce, Ciphertext)` | AES-256-GCM encrypt with AAD |
| `decrypt` | `(key, nonce, ciphertext, aad) → Vec<u8>` | AES-256-GCM decrypt |
| `seal_envelope` | `(key, plaintext, entity_id, field) → EncryptedEnvelope` | Create encrypted envelope |
| `open_envelope` | `(key, envelope) → Vec<u8>` | Decrypt envelope |
| `random_bytes` | `(&mut [u8]) → Result` | Fill buffer with random bytes |
| `random_salt` | `() → Salt` | Generate random salt |
| `random_nonce` | `() → Nonce` | Generate random nonce |
| `random_uuid` | `() → Uuid` | Generate random UUID |

### Envelope Format
```
[version:1][nonce:12][ciphertext:N][tag:16]
```
- `version`: 1 byte (0x01 for V1)
- `nonce`: 12 bytes (96-bit, randomly generated per encryption)
- `ciphertext`: N bytes (same length as plaintext)
- `tag`: 16 bytes (128-bit GCM authentication tag)
- AAD context: `entity_id:field_name` (bound to encryption, prevents cross-field swap)

### Private (not exported)
- Argon2 parameter internals
- AES-GCM cipher construction
- Key exposure methods (only `DerivedKey::expose` is semi-public)

---

## Module: `db`

### Public Types
| Type | Description |
|------|-------------|
| `DbConnection` | SQLCipher connection pool wrapper |
| `Repository<T, C, U>` | Generic CRUD trait |
| `Pagination` | Limit/offset for list queries |
| `VaultEntryRepo` | Vault entry repository |
| `AuditEventRepo` | Audit event repository (append-only) |
| `VaultMetaRepo` | Vault metadata repository (singleton) |
| `FolderRepo` | Folder repository (hierarchical organization) |
| `SecureNoteRepo` | Secure note repository (encrypted notes) |
| `FileEntryRepo` | File entry repository (encrypted file vault) |
| `AuditEventRow` | Audit event database row |
| `CreateAuditEventRequest` | Request to create audit event |
| `VaultMeta` | Vault metadata (KDF params, test envelope) |
| `FolderRow` | Folder database row |
| `CreateFolderRequest` | Request to create folder |
| `SecureNoteRow` | Secure note database row |
| `CreateSecureNoteRequest` | Request to create secure note |
| `FileEntryRow` | File entry database row |
| `CreateFileEntryRequest` | Request to create file entry |

### Public Functions
| Function | Description |
|----------|-------------|
| `transaction(pool, f)` | Execute within a database transaction |
| `FolderRepo::would_create_cycle(pool, id, parent)` | Check for circular folder references |
| `FolderRepo::count_entries(pool, folder_id)` | Count entries in a folder |

### Private
- All SQL query strings
- Row mapping functions
- SQLCipher PRAGMA key setting

---

## Module: `vault`

### Public Types
| Type | Description |
|------|-------------|
| `VaultEntry` | Password vault entry (encrypted fields) |
| `CreateEntryRequest` | Request to create entry (plaintext input) |
| `UpdateEntryRequest` | Request to update entry (partial) |
| `Folder` | Organizational folder |
| `FolderTree` | Nested folder hierarchy |
| `VaultService` | Trait for vault operations |

### Access Pattern
- Vault module types are accessed through `commands::vault_commands`
- Direct vault module access from outside commands is discouraged

---

## Module: `audit`

### Public Types
| Type | Description |
|------|-------------|
| `AuditEvent` | Audit event with category, action, subject |
| `EventCategory` | Auth, Vault, File, System, Security |
| `ActionType` | Create, Read, Update, Delete, Login, Lock, etc. |
| `AuditLogger` | Trait for structured audit logging |

### Access Pattern
- Accessed through `commands::audit_commands`
- `AuditEventRepo` used internally by audit module

---

## Module: `scanner`

### Public Types
| Type | Description |
|------|-------------|
| `ThreatLevel` | Critical, High, Medium, Low, Info |
| `ScanResult` | Vulnerability scan result |
| `PasswordStrength` | VeryWeak, Weak, Fair, Strong, VeryStrong |

### Access Pattern
- Accessed through `commands::scanner_commands`
- All scanning is local-only, no network calls

---

## Module: `security`

### Public Types
| Type | Description |
|------|-------------|
| `Session` | Active vault session (no secrets) |
| `SessionId` | UUID-based session identifier |
| `SessionState` | Locked or Unlocked |
| `VaultState` | Uninitialized, Locked, Unlocked |
| `VaultStateMachine` | Lifecycle state machine |
| `VaultTransition` | Initialize, Unlock, Lock, AutoLock, Destroy |
| `TransitionResult` | from_state, to_state, transition, timestamp |
| `VaultStateEvent` | State change event for audit logging |
| `VaultContext` | Context for guard evaluation |
| `RateLimiter` | Per-operation rate limiting |
| `Operation` | Login, Command, FileOperation |
| `LockoutState` | Allowed, Delayed(seconds), LockedOut |
| `FailedAttemptTracker` | Progressive lockout tracking |

### Vault Lifecycle State Machine
```
                    ┌──────────────┐
                    │ Uninitialized │
                    └──────┬───────┘
                           │ Initialize
                           ▼
                    ┌──────────────┐
            ┌──────│    Locked     │──────┐
            │      └──────┬───────┘      │
            │             │ Unlock       │ Lock / Auto-lock
            │             ▼              │
            │      ┌──────────────┐      │
            │      │   Unlocked   │──────┘
            │      └──────┬───────┘
            │             │
            │  Lock /     │ Destroy
            │  Auto-lock  │
            └─────────────┘
```

### Access Pattern
- `VaultStateMachine` used by `commands::auth_commands` via `AppState`
- `RateLimiter` used by `AppState` for command middleware
- `FailedAttemptTracker` used by `AppState` for auth flow

---

## Module: `config`

### Public Types
| Type | Description |
|------|-------------|
| `AppConfig` | Application configuration with secure defaults |

### Public Functions
| Function | Description |
|----------|-------------|
| `AppConfig::default()` | Create with secure defaults |
| `AppConfig::validate()` | Clamp values to safe ranges |
| `load()` | Load from app data directory (stub) |
| `save()` | Persist to app data directory (stub) |

---

## Module: `commands`

### Public Types
| Type | Description |
|------|-------------|
| `CommandResult<T>` | Ok(data) or Err(CommandError) |
| `CommandError` | User-safe error (code + message) |
| `VaultEntryResponse` | Entry metadata (NO password) |
| `PasswordRevealResponse` | Temporary password reveal |
| `SessionResponse` | Session metadata |
| `VaultStatusResponse` | Vault state + lockout info |
| `VaultInitResponse` | Vault initialization result |
| `VaultLockResponse` | Lock/unlock operation result |
| `InitializeVaultRequest` | Vault init request (typed) |
| `UnlockVaultRequest` | Vault unlock request (typed) |
| `ChangePasswordRequest` | Password change request (typed) |
| `PasswordStrengthResponse` | Strength analysis result |
| `VulnerabilityItemResponse` | Vulnerability finding |
| `AuditEventResponse` | Audit event for frontend |
| `AuditPageResponse` | Paginated audit results |
| `AppSettingsResponse` | Application settings |
| `FolderResponse` | Folder metadata |
| `CreateFolderRequest` | Folder creation request |
| `SecureNoteResponse` | Note metadata (no content) |
| `SecureNoteRevealResponse` | Note content (temporary) |
| `FileEntryResponse` | File entry metadata |
| `SecurityScoreResponse` | Overall security score |
| `SecurityBreakdown` | Score breakdown by category |

### AppState (Shared Tauri State)
| Field | Type | Description |
|-------|------|-------------|
| `vault_state_machine` | `RwLock<VaultStateMachine>` | Vault lifecycle FSM |
| `rate_limiter` | `RwLock<RateLimiter>` | Per-operation rate limiting |
| `lockout_tracker` | `RwLock<FailedAttemptTracker>` | Progressive lockout |
| `master_key_present` | `RwLock<bool>` | Whether key is in memory |

### State Guard Methods (AppState)
| Method | Description |
|--------|-------------|
| `require_state(required)` | Enforce specific vault state |
| `require_unlocked()` | Shorthand for `require_state(Unlocked)` |
| `require_initialized()` | Enforce vault exists (Locked or Unlocked) |
| `check_lockout()` | Check progressive lockout state |

### Validation Constants
| Constant | Value |
|----------|-------|
| `MAX_TITLE_LEN` | 256 |
| `MAX_USERNAME_LEN` | 256 |
| `MAX_PASSWORD_LEN` | 1024 |
| `MAX_NOTES_LEN` | 10,000 |
| `MAX_URL_LEN` | 2,048 |
| `MAX_FOLDER_NAME_LEN` | 128 |
| `MIN_MASTER_PASSWORD_LEN` | 8 |
| `MAX_HINT_LEN` | 100 |
| `MAX_QUERY_LEN` | 256 |

### Command List (23 total)
See `docs/security-notes/ipc-model.md` for complete inventory.
