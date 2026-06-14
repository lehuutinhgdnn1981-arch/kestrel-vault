# Data Flow Security Notes

> **Scope:** How data moves through KESTREL Vault — where it exists in plaintext, where it's encrypted, and how it transitions between states
> **Audience:** Security auditors, developers, penetration testers
> **Last Updated:** 2025-03-04
> **Classification:** Internal — Security Sensitive

---

## 1. Where Data Exists in Plaintext

### 1.1 The Golden Rule

**Plaintext exists ONLY in Rust process memory, NEVER in JavaScript memory (except transiently for display), NEVER on disk, NEVER in network transit, and NEVER in logs.**

### 1.2 Plaintext Locations

The following table enumerates every location where plaintext data may exist, even transiently:

| Data | Location | Duration | Protection | Justification |
|------|----------|----------|------------|---------------|
| Master password | Rust stack/heap (during `derive_key()`) | ~1 second | `ZeroizeOnDrop` after KDF | Required for key derivation |
| Derived key (MasterKey) | Rust heap (`secrecy::Secret`) | Until vault lock | `ZeroizeOnDrop`, `secrecy::Secret`, no Debug/Clone | Required for encrypt/decrypt operations |
| SQLCipher PRAGMA key | Rust heap (transient String) | ~milliseconds | `zeroize_string()` after PRAGMA set | Required for database connection |
| Decrypted entry fields | Rust heap (during `get_entry`) | ~milliseconds | Dropped at end of function scope | Required for IPC response |
| Decrypted entry in IPC response | Tauri IPC serialization buffer | ~milliseconds | JSON serialized and sent to WebView | Required for UI display |
| Decrypted entry in JS memory | WebView V8 heap | Until component unmounts or vault lock | Cleared on lock; no persistence | Required for user to see their data |
| Password in create/update request | Tauri IPC serialization buffer | ~milliseconds | Zeroized after encryption on Rust side | Required for encryption operation |
| Password on JS heap | WebView V8 heap | Until IPC call completes | Not easily controllable in JS GC | Required to send password to backend |
| Clipboard contents | OS clipboard buffer | Until auto-clear timeout (30s default) | Overwritten with empty string | Required for password copy/paste |
| TOTP secret (during setup) | Rust heap + JS heap | ~seconds | Same as entry fields | Required for TOTP configuration |

### 1.3 Where Plaintext NEVER Exists

| Location | Guarantee |
|----------|-----------|
| **Disk (database file)** | All data encrypted by SQLCipher at page level + AES-256-GCM at field level |
| **Disk (WAL journal)** | WAL pages are encrypted by SQLCipher before writing |
| **Disk (swap/page file)** | Key material may be paged (mitigated by mlock in Phase 2); plaintext data generally not paged due to short lifetime |
| **Network** | No network communication in Phase 1; all operations are local |
| **Logs** | Audit events never contain passwords, keys, or decrypted data; tracing logs never contain sensitive values (enforced by `secrecy::Secret`) |
| **Session tokens** | No keys stored in session tokens; session state is a boolean (locked/unlocked) + reference to Rust-side MasterKey |
| **Error messages** | Errors never include decrypted data; crypto errors report operation failure, not key or plaintext values |
| **Browser local storage** | No sensitive data in localStorage, sessionStorage, or IndexedDB |
| **Configuration files** | No keys or passwords in config files; only non-sensitive settings |

### 1.4 Plaintext Lifetime Minimization

Every plaintext value has a defined maximum lifetime. The design principle is to minimize the window of exposure:

| Value | Max Lifetime | How Reduced |
|-------|-------------|-------------|
| Master password | ~1 second | Zeroized immediately after Argon2id returns |
| Derived key (MasterKey) | Until vault lock | `ZeroizeOnDrop` on lock; auto-lock at 5 min inactivity |
| Decrypted entry (Rust) | ~milliseconds | Stack-local variable dropped at function end |
| Decrypted entry (JS) | Until unmount/lock | Component state cleared on lock; no caching in stores |
| SQLCipher PRAGMA key | ~milliseconds | `zeroize_string()` called after PRAGMA set |
| Clipboard password | 30 seconds | Auto-clear timer overwrites clipboard |
| Plaintext password in IPC | ~milliseconds | Zeroized after encryption in Rust; short serialization window |

---

## 2. Encryption at Rest

### 2.1 Dual Encryption Model

KESTREL Vault employs two independent layers of encryption for data at rest:

```
┌───────────────────────────────────────────────────────┐
│  Layer 2: Field-Level Encryption (AES-256-GCM)        │
│  ┌─────────────────────────────────────────────────┐  │
│  │  Each sensitive field is independently encrypted │  │
│  │  with AES-256-GCM before being stored.          │  │
│  │  Nonce: 96-bit random per row                   │  │
│  │  Key: Master derived key (Argon2id output)      │  │
│  └─────────────────────────────────────────────────┘  │
│                                                       │
│  Layer 1: Page-Level Encryption (SQLCipher)           │
│  ┌─────────────────────────────────────────────────┐  │
│  │  The entire database file is encrypted at the    │  │
│  │  page level by SQLCipher. Each 4096-byte page   │  │
│  │  is encrypted with AES-256-CBC + HMAC-SHA512.   │  │
│  │  Key: PBKDF2(Argon2id output) — separate key    │  │
│  └─────────────────────────────────────────────────┘  │
│                                                       │
│  ─────── Disk ─────────────────────────────────────── │
└───────────────────────────────────────────────────────┘
```

### 2.2 Why Two Layers?

| Scenario | Layer 1 Only (SQLCipher) | Layer 1 + Layer 2 (Dual) |
|----------|-------------------------|--------------------------|
| Database file stolen, SQLCipher key compromised | All data exposed | Individual fields still require AES-256-GCM decryption |
| SQLCipher implementation bug leaks plaintext pages | All data exposed | Field-level ciphertext remains protected |
| Memory dump reveals SQLCipher's internal key | All data exposed | Attacker still needs to decrypt each field individually |
| Bug in application code writes unencrypted data to DB | Data exposed in plaintext | Data is encrypted before insertion; bug would need to bypass encrypt() |
| Cryptanalytic break of AES-256-CBC | All data exposed | AES-256-GCM uses same algorithm but different mode and key usage |

The dual model provides **defense-in-depth**: compromising one layer does not compromise all data. The layers use the same master key but through different derivation paths (SQLCipher key is hex-encoded, AES-256-GCM key is raw bytes), so a compromise of the SQLCipher PRAGMA key does not directly yield the AES-256-GCM key.

### 2.3 What Is Encrypted at Which Layer?

| Table | Column | Field-Level (AES-256-GCM) | Page-Level (SQLCipher) | Rationale |
|-------|--------|---------------------------|----------------------|-----------|
| `vault_meta` | `salt` | No | Yes | Salt is not secret; needed before vault unlock |
| `vault_meta` | `iterations`, `memory_cost`, `parallelism` | No | Yes | KDF params are not secret; needed for key derivation |
| `vault_entries` | `title` | Yes (BLOB) | Yes | Entry titles may reveal sites/services used |
| `vault_entries` | `username` | Yes (BLOB) | Yes | Usernames are PII |
| `vault_entries` | `encrypted_password` | Yes (BLOB) | Yes | Passwords are the primary secret |
| `vault_entries` | `url` | Yes (BLOB) | Yes | URLs reveal browsing patterns |
| `vault_entries` | `notes` | Yes (BLOB) | Yes | Notes may contain sensitive information |
| `vault_entries` | `totp_secret` | Yes (BLOB) | Yes | TOTP secrets enable account access |
| `vault_entries` | `tags` | Yes (BLOB) | Yes | Tags reveal organizational structure |
| `vault_entries` | `nonce` | No | Yes | Nonces are not secret |
| `vault_entries` | `id`, `folder_id`, timestamps | No | Yes | IDs and timestamps are not sensitive (SQLCipher protects at page level) |
| `folders` | `name` | Yes (BLOB) | Yes | Folder names reveal organizational structure |
| `secure_notes` | `title`, `content`, `tags` | Yes (BLOB) | Yes | All note content is potentially sensitive |
| `file_entries` | `filename`, `encrypted_path`, `file_size`, `mime_type` | Yes (BLOB) | Yes | File metadata reveals file types and storage locations |
| `audit_events` | All columns | No | Yes | Must be queryable; never contains secrets |
| `security_settings` | All columns | No | Yes | Must be readable before unlock; no secrets |
| `breach_hashes` | All columns | No | Yes | Public data; no secrets |

### 2.4 File Encryption

File attachments are stored on disk as separate encrypted files:

```
files/
├── <uuid-1>.enc    ← AES-256-GCM encrypted file content
├── <uuid-2>.enc
└── ...
```

Each encrypted file consists of:

```
[96-bit nonce] [AES-256-GCM ciphertext (includes 128-bit auth tag)]
```

The encryption key is the same master key used for field-level encryption. The nonce is generated fresh for each file. The file's UUID (stored in `file_entries.id`) is used as the filename, preventing information leakage from original filenames.

File content encryption is a separate operation from database metadata encryption. The `file_entries` table stores the encrypted metadata (filename, path, size, MIME type) and a reference to the on-disk encrypted file.

---

## 3. Encryption in Transit (IPC Boundary)

### 3.1 Tauri IPC Architecture

Tauri v2's IPC mechanism operates entirely within the same OS process:

```
┌──────────────────────────────────────────┐
│           Single OS Process              │
│                                          │
│  WebView (V8/WebKit)  ◄──IPC──►  Rust   │
│       [Frontend]                  [Backend] │
│                                          │
└──────────────────────────────────────────┘
```

The IPC channel is **not** a network socket. It is an in-process message passing mechanism:

- On Linux: Unix domain socket (within `/proc/self/` namespace) or direct function call
- On macOS: XPC service or direct function call
- On Windows: Named pipe (within same session) or direct function call

### 3.2 Data Crossing the IPC Boundary

| Direction | Data Type | Encrypted? | Risk |
|-----------|-----------|-----------|------|
| Frontend → Backend | Master password (during unlock) | No (plaintext) | Interceptable by in-process hooks (Frida, LD_PRELOAD) |
| Frontend → Backend | Entry password (during create/update) | No (plaintext) | Same as above |
| Frontend → Backend | Search queries | No | Low risk; queries are not sensitive |
| Frontend → Backend | Settings changes | No | No risk; settings are not secret |
| Backend → Frontend | Decrypted entry fields | No (plaintext) | Same intercept risk as above |
| Backend → Frontend | Search results | No (partially decrypted) | Same as above |
| Backend → Frontend | Audit events | No | Audit events never contain secrets |
| Backend → Frontend | Password strength results | No | Results are not secret |
| Backend → Frontend | Success/failure status | No | No risk |
| **NEVER** | Cryptographic keys | **Never sent** | Keys stay in Rust memory |

### 3.3 IPC Security Properties

| Property | Status | Details |
|----------|--------|---------|
| Network exposure | Not exposed | IPC is in-process only; no TCP/UDP listeners |
| Cross-origin access | Blocked | Tauri CSP restricts WebView to local origin |
| Cross-user access | Blocked | IPC is within the same OS process and user session |
| Encryption | Not encrypted (in-process) | Not needed; no network exposure |
| Authentication | Not applicable | Only one frontend instance per backend |
| Integrity | Guaranteed by Tauri | Serialized JSON with type checking on both sides |

### 3.4 IPC Threat Model

The primary IPC threat is **in-process interception**: malware running in the same process space can hook the IPC layer and read plaintext data crossing the boundary. This is a known limitation with the following mitigations:

1. **Minimize sensitive data crossing IPC:** Only the data that the user needs to see or submit crosses the boundary. Keys never cross.
2. **Short lifetime in JS:** Once the frontend receives decrypted data, it is displayed and then cleared from component state when the component unmounts or the vault locks.
3. **No caching:** The frontend does not cache decrypted passwords in Zustand stores. Passwords are fetched on-demand and cleared after display.
4. **Future mitigation:** Native password dialog (Phase 2) would allow password entry entirely in Rust, bypassing the WebView entirely for the most sensitive operation.

---

## 4. Key Lifecycle

### 4.1 Key States

A cryptographic key in KESTREL Vault goes through the following states:

```
┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
│           │     │           │     │           │     │           │
│  Created  │────►│  Active   │────►│  Locked   │────►│ Destroyed │
│  (derive) │     │  (in use) │     │  (memory  │     │ (zeroized)│
│           │     │           │     │  zeroized) │     │           │
└──────────┘     └──────────┘     └──────────┘     └──────────┘
     │                │                                  ▲
     │                │         ┌──────────┐             │
     │                └────────►│  Rotated  │─────────────┘
     │                          │  (re-key) │  (old key zeroized,
     │                          └──────────┘   new key active)
     │                                │
     │                          ┌──────────┐
     └──────────────────────────►│  Expired │
           (KDF params changed)  │  (needs  │
                                 │  re-derive)│
                                 └──────────┘
```

### 4.2 Key Creation (Derivation)

```
User Password (plaintext)
        │
        ▼
   ┌─────────────────────────────────────┐
   │  Argon2id(password, salt)           │
   │  - Memory: 256 MB                   │
   │  - Iterations: 3                    │
   │  - Parallelism: 4                   │
   │  - Output: 256-bit DerivedKey       │
   │  - Time: ~1 second                  │
   └─────────────┬───────────────────────┘
                 │
                 ▼
   ┌─────────────────────────────────────┐
   │  MasterKey::from_password()         │
   │  - Wraps DerivedKey in Secret      │
   │  - Implements ZeroizeOnDrop         │
   │  - Never logged, serialized, cloned│
   └─────────────┬───────────────────────┘
                 │
                 ▼
   ┌─────────────────────────────────────┐
   │  Zeroize password string            │
   │  - Overwrite with zeros             │
   │  - Password no longer in memory     │
   └─────────────────────────────────────┘
```

**Key invariant:** After step 3, the only representation of the key in memory is the `MasterKey` wrapped in `secrecy::Secret`. The original password has been zeroized.

### 4.3 Key Usage (Active)

While the vault is unlocked, the `MasterKey` is held in Rust-side application state:

```rust
// Conceptual state management
struct VaultState {
    master_key: Option<MasterKey>,  // Some when unlocked, None when locked
    db_connection: Option<DbConnection>,
}
```

The key is accessed only through `master_key.derived_key().expose()`, which returns a reference to the key bytes. The reference is valid only for the duration of the borrow, preventing the key from being accidentally stored elsewhere.

**Key usage patterns:**

| Operation | Key Access | Duration |
|-----------|-----------|----------|
| Encrypt entry field | `key.expose()` for AES-256-GCM encrypt | ~microseconds |
| Decrypt entry field | `key.expose()` for AES-256-GCM decrypt | ~microseconds |
| Format SQLCipher key | `key.expose()` for hex encoding | ~microseconds |
| TOTP code generation | `key.expose()` for TOTP secret decryption | ~microseconds |
| Search blind index | `HMAC(key.expose(), query)` | ~microseconds |

### 4.4 Key Locking (Memory Zeroization)

When the vault is locked (manually, auto-lock, or system event):

```
1. Trigger lock event (user action, timeout, OS event)
2. Clear all decrypted data from frontend stores
   - Set vault-store entries to empty
   - Set auth-store to locked state
   - Clear any displayed entry data
3. Clear clipboard (overwrite with empty string)
4. Drop MasterKey → ZeroizeOnDrop overwrites key bytes with zeros
5. Close database connection pool (clears SQLCipher internal state)
6. Force WAL checkpoint (merge WAL into main DB)
7. Log audit event: Auth/Lock with reason
```

After step 4, **no key material exists in Rust memory**. The vault is fully locked and cannot be accessed without re-entering the master password and repeating the full key derivation process.

### 4.5 Key Rotation

Key rotation replaces the current master key with a new one derived from a new password. See [Cryptography Security Notes §4](cryptography.md#4-key-rotation-procedure) for the detailed procedure.

Key rotation ensures:

1. The old key is zeroized after all entries are re-encrypted
2. All entries receive fresh nonces (nonce space is reset)
3. A new salt is generated and stored in `vault_meta`
4. The operation is atomic — either all entries are re-encrypted or none are

### 4.6 Key Never Written to Disk

The master key is **never** written to disk in any form:

| Storage Location | Key Present? | Reason |
|-----------------|-------------|--------|
| Database file | No | SQLCipher key is set via PRAGMA (in-memory only) |
| WAL journal | No | SQLCipher encrypts WAL pages before writing |
| Configuration file | No | Config stores only non-sensitive settings |
| Log files | No | `secrecy::Secret` prevents logging |
| Swap/page file | Possible (mitigated by mlock) | OS may page process memory; mlock (Phase 2) prevents this |
| Core dump | Possible (mitigated by PR_SET_DUMPABLE) | Core dumps may contain process memory; disabled in Phase 2 |
| Temporary files | No | No temporary files contain key material |

---

## 5. Session Security

### 5.1 Session Model

KESTREL Vault does not use traditional session tokens. The session state is:

```
┌──────────────────────────────────────────────────────┐
│  Session State (Rust-side)                           │
│                                                      │
│  vault_state:                                        │
│    locked   → MasterKey = None, DbConnection = None  │
│    unlocked → MasterKey = Some(key), DbConnection = Some(pool) │
│                                                      │
│  No session tokens, cookies, or persistent IDs       │
│  No keys stored in any session mechanism             │
└──────────────────────────────────────────────────────┘
```

### 5.2 Why No Session Tokens?

Traditional web applications use session tokens to maintain authentication state across requests. KESTREL Vault does not need session tokens because:

1. **Single-user application:** Only one user accesses the vault at a time
2. **Single-process architecture:** Frontend and backend share the same process
3. **Key in memory:** The unlocked state is represented by the MasterKey in Rust memory, not a token
4. **No server:** There is no server to validate tokens against

If session tokens were used, they would create a security risk: a stolen session token could be used to impersonate the user. By keeping the session state as a Rust-side memory reference, we eliminate this attack vector entirely.

### 5.3 Session Locking

The session transitions from unlocked to locked when:

| Trigger | Implementation | Audit Event |
|---------|---------------|-------------|
| User clicks "Lock" | Frontend → IPC → Rust: lock vault | Auth/Lock (reason: manual) |
| Auto-lock timeout | `use-auto-lock` hook detects inactivity | Auth/Lock (reason: timeout) |
| System lock (screen lock) | OS event listener triggers lock | Auth/Lock (reason: system) |
| Application minimize (optional) | Window event listener triggers lock | Auth/Lock (reason: minimize) |
| Failed auth rate limit | Security module triggers lock after N failures | Auth/Lock (reason: rate_limit) |

On lock:

1. `MasterKey` is dropped → `ZeroizeOnDrop` erases key material
2. `DbConnection` is closed → SQLCipher clears internal state
3. Frontend stores are cleared → no decrypted data in JS memory
4. Clipboard is cleared → no password in OS clipboard
5. Audit event is logged → Auth/Lock

### 5.4 Session Re-Authentication

After a lock event, the user must re-enter the master password to unlock the vault. This triggers the full key derivation process (Argon2id with 256 MB memory cost, ~1 second). There is no "quick unlock" mechanism that bypasses key derivation.

Future (Phase 2): Biometric re-authentication may use a platform-stored key reference to avoid re-entering the password, but the full key derivation still occurs internally.

---

## 6. Clipboard Security

### 6.1 Clipboard Threat Model

The system clipboard is an inherently insecure shared resource:

| Threat | Severity | Likelihood | Details |
|--------|----------|------------|---------|
| Clipboard monitoring by malware | Medium | Medium | Malware can read clipboard at any time |
| Clipboard history persistence | Medium | High | macOS ClipboardViewer, Windows Clipboard History retain clipboard content |
| Remote clipboard sync | Medium | Low | Some tools sync clipboard across devices (e.g., Universal Clipboard) |
| Other applications reading clipboard | Medium | High | Any application can read the clipboard at any time |

### 6.2 Clipboard Copy Flow

```
User clicks "Copy Password"
        │
        ▼
Frontend: invoke("get_entry", { id })
        │
        ▼ IPC
Rust: Decrypt password → Return to frontend
        │
        ▼ IPC
Frontend: navigator.clipboard.writeText(password)
        │
        ├─► Start auto-clear timer (30 seconds default)
        │
        └─► Display "Copied!" toast (password NOT shown in toast)
                │
                │  ... 30 seconds ...
                ▼
Frontend: navigator.clipboard.writeText("")  ← Auto-clear
```

### 6.3 Clipboard Auto-Clear

| Parameter | Default Value | Configurable | Range |
|-----------|--------------|-------------|-------|
| Auto-clear timeout | 30 seconds | Yes | 10–120 seconds |
| Clear on vault lock | Yes | No | Always on |
| Clear on app exit | Yes | No | Always on |
| Clear on manual lock | Yes | No | Always on |

### 6.4 Clipboard Clear on Lock

When the vault locks, the clipboard is unconditionally cleared:

```
Lock event
    │
    ├─► navigator.clipboard.writeText("")
    │   (Overwrites any KESTREL Vault content in clipboard)
    │
    └─► Note: This only clears the current clipboard content.
        It does NOT clear clipboard history maintained by the OS
        or third-party clipboard managers.
```

### 6.5 Known Clipboard Limitations

| Limitation | Mitigation | Future |
|------------|-----------|--------|
| Clipboard managers may retain history | Warn user in settings; suggest disabling clipboard managers | Detect and warn when clipboard manager is running |
| Universal Clipboard (Apple) may sync to other devices | Auto-clear limits exposure window; warn user | Detect Universal Clipboard status |
| Remote desktop clipboard sharing | Auto-clear; user awareness | N/A |
| Some OSes don't allow programmatic clipboard clear | Best-effort clear; user manual clear | Platform-specific handling |
| Clipboard clear race condition (malware reads before clear) | 30-second window is a tradeoff; shorter timeout available | Offer "copy and clear in 10s" option |

### 6.6 Drag-and-Drop

Passwords are **never** exposed via drag-and-drop. The drag-and-drop payload for vault entries contains only the entry ID and non-sensitive metadata (entry type, folder), never the decrypted password or other secrets.

---

## 7. Memory Cleanup on Lock

### 7.1 Lock Sequence (Detailed)

The vault lock sequence is carefully ordered to ensure no sensitive data remains in memory:

```
Step 1: FRONTEND CLEANUP
  ├─► vault-store: Set entries = [], selectedEntry = null
  ├─► auth-store: Set isLocked = true, clear session data
  ├─► app-store: Clear any cached decrypted data
  ├─► React components: Unmount vault views; mount UnlockScreen
  └─► Note: JS GC may not immediately reclaim memory, but references are broken

Step 2: CLIPBOARD CLEAR
  ├─► navigator.clipboard.writeText("")
  └─► Overwrites any KESTREL Vault content in OS clipboard

Step 3: RUST KEY ZEROIZATION
  ├─► VaultState.master_key = None
  │   └─► MasterKey Drop → ZeroizeOnDrop → key bytes overwritten with zeros
  └─► All DerivedKey references are out of scope and zeroized

Step 4: DATABASE CONNECTION CLOSE
  ├─► DbConnection.pool.close()
  │   └─► SQLCipher clears internal key material
  └─► PRAGMA key is no longer in SQLCipher's memory

Step 5: WAL CHECKPOINT (Phase 2)
  ├─► PRAGMA wal_checkpoint(TRUNCATE)
  └─► Merges WAL into main database file; truncates WAL

Step 6: AUDIT LOG
  ├─► Log event: Auth/Lock (reason: manual/timeout/system)
  └─► Note: Audit log does NOT contain any key material
```

### 7.2 What Gets Cleaned

| Data | Cleanup Method | Guarantee |
|------|---------------|-----------|
| MasterKey | `ZeroizeOnDrop` (Rust) | Key bytes overwritten with zeros before deallocation |
| DerivedKey | `#[zeroize(drop)]` (Rust) | Key bytes overwritten with zeros |
| Decrypted entries (Rust) | Dropped at end of function scope | Stack/heap memory freed; zeroize not applied (not wrapped in Secret) |
| Decrypted entries (JS) | Store state set to empty | V8 GC will reclaim; no guarantee of zeroization |
| SQLCipher PRAGMA key | SQLCipher internal cleanup | Implementation-specific; not controlled by KESTREL |
| SQLCipher page cache | SQLCipher internal cleanup | Implementation-specific; pages are encrypted in cache |
| Clipboard | Overwrite with empty string | Clipboard buffer overwritten |
| TOTP secrets | Same as decrypted entries | Zeroized in Rust; GC in JS |

### 7.3 What Does NOT Get Cleaned

| Data | Why Not | Risk |
|------|---------|------|
| JS heap memory (garbage collected) | V8 GC does not guarantee zeroization; memory may persist until page is reclaimed | Low: memory is in same process; no external access |
| OS memory pages (after process exit) | OS reclaims pages; no guarantee of zeroization before reuse | Low: pages are recycled by OS; data decays quickly |
| Swap file (if paged) | OS controls swap; we cannot zeroize swap pages | Medium: mitigated by mlock (Phase 2) |
| Core dump (if generated) | Core dump captures process memory at crash time | Low: core dumps disabled (Phase 2) |
| CPU cache / registers | Transient; overwritten rapidly by other operations | Negligible: persists for nanoseconds |
| GPU memory | Not used by KESTREL Vault | N/A |

### 7.4 Memory Cleanup Verification

The following strategies verify that memory cleanup is effective:

| Strategy | Method | Frequency |
|----------|--------|-----------|
| Unit tests | Verify `ZeroizeOnDrop` is derived for key types | Every build |
| Integration tests | Lock vault, attempt to read key material, verify failure | CI pipeline |
| Code review | Verify all key-holding types implement `ZeroizeOnDrop` | Every PR |
| Static analysis | `cargo clippy` lints for missing zeroize; grep for key material in non-Secret types | Every build |
| Memory audit (manual) | Run vault under valgrind/ASan, unlock and lock, check for key material in memory | Release builds |

---

## Appendix A: Data State Matrix

This matrix shows the state of each data type at each stage of the vault lifecycle.

| Data Type | On Disk (Locked) | On Disk (Unlocked) | In Rust Memory (Locked) | In Rust Memory (Unlocked) | In JS Memory (Locked) | In JS Memory (Unlocked) |
|-----------|------------------|--------------------|-----------------------|--------------------------|----------------------|------------------------|
| Master password | Never | Never | Never | Never (zeroized) | Never | Never |
| Derived key | Never | Never | Never | Secret<ZeroizeOnDrop> | Never | Never |
| Entry password (encrypted) | SQLCipher + AES-GCM | SQLCipher + AES-GCM | Never | Never | Never | Never |
| Entry password (plaintext) | Never | Never | Never | Transient (~ms) | Never | Transient (~ms) |
| Entry title (encrypted) | SQLCipher + AES-GCM | SQLCipher + AES-GCM | Never | Never | Never | Never |
| Entry title (plaintext) | Never | Never | Never | Transient (~ms) | Never | While displayed |
| Folder name (encrypted) | SQLCipher + AES-GCM | SQLCipher + AES-GCM | Never | Never | Never | Never |
| Folder name (plaintext) | Never | Never | Never | Transient (~ms) | Never | While displayed |
| Audit events | SQLCipher | SQLCipher | Never | Transient (query) | Never | While displayed |
| Security settings | SQLCipher | SQLCipher | Never | On demand | Never | While displayed |
| Breach hashes | SQLCipher | SQLCipher | Never | On demand | Never | Never |

---

## Appendix B: Threat-Data Mapping

For each data type, which attacks are relevant and what is the primary mitigation:

| Data Type | Memory Dump | Disk Theft | IPC Sniff | Clipboard | Keylog | Brute Force |
|-----------|-------------|------------|-----------|-----------|--------|-------------|
| Master password | ZeroizeOnDrop | Never on disk | Transient in IPC | N/A | Virtual KB (P2) | Argon2id |
| Derived key | secrecy+Zeroize | Never on disk | Never in IPC | N/A | N/A | N/A |
| Entry password | Transient (~ms) | Dual encryption | Transient in IPC | Auto-clear (30s) | N/A | N/A |
| Entry title | Transient (~ms) | Dual encryption | Transient in IPC | N/A | N/A | N/A |
| Folder name | Transient (~ms) | Dual encryption | Transient in IPC | N/A | N/A | N/A |
| Audit events | Not sensitive | SQLCipher only | Not sensitive | N/A | N/A | N/A |
| TOTP secret | Transient (~ms) | Dual encryption | Transient in IPC | N/A | N/A | N/A |

---

## Appendix C: Configuration Parameters Affecting Data Flow Security

| Parameter | Default | Min | Max | Effect |
|-----------|---------|-----|-----|--------|
| `auto_lock_minutes` | 5 | 1 | 60 | Time before vault auto-locks on inactivity |
| `clipboard_clear_seconds` | 30 | 10 | 120 | Time before clipboard is auto-cleared |
| `clear_clipboard_on_lock` | true | — | — | Clear clipboard when vault locks |
| `kdf_memory_cost_mb` | 256 | 64 | 1024 | Argon2id memory cost in MB |
| `kdf_iterations` | 3 | 1 | 10 | Argon2id time cost |
| `kdf_parallelism` | 4 | 1 | 8 | Argon2id parallelism |
| `max_failed_attempts` | 5 | 3 | 20 | Failed unlocks before rate limiting |
| `rate_limit_delay_seconds` | 30 | 10 | 300 | Delay after max failed attempts |
| `lockout_threshold` | 15 | 5 | 50 | Failed attempts before vault lockout |
