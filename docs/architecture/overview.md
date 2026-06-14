# KESTREL Vault — Architecture Overview

> **Version:** 0.1.0 (Phase 1)
> **Last Updated:** 2025-03-04
> **Status:** Active Development

---

## 1. System Architecture

KESTREL Vault is a **local-first, zero-knowledge** password manager and security platform built on the **Tauri v2** framework. It combines a Rust backend for cryptographic operations and data management with a React frontend for the user interface.

### Architecture Diagram (Textual)

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Operating System                             │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                    Tauri v2 Runtime                          │   │
│  │                                                              │   │
│  │  ┌─────────────────────────┐  ┌───────────────────────────┐  │   │
│  │  │   Frontend (WebView)    │  │   Backend (Rust)          │  │   │
│  │  │                         │  │                           │  │   │
│  │  │  React 18 + TypeScript  │  │  ┌─────────────────────┐  │  │   │
│  │  │  Vite (dev/bundler)     │  │  │  crypto module      │  │  │   │
│  │  │  TailwindCSS            │  │  │  ├─ kdf (Argon2id)  │  │  │   │
│  │  │  Zustand (state mgmt)   │  │  │  ├─ cipher (GCM)    │  │  │   │
│  │  │                         │  │  │  ├─ key_management   │  │  │   │
│  │  │  ┌───────────────────┐  │  │  │  └─ random (OsRng)  │  │  │   │
│  │  │  │  UI Views         │  │  │  ├─────────────────────┤  │  │   │
│  │  │  │  ├─ UnlockScreen  │  │  │  │  vault module       │  │  │   │
│  │  │  │  ├─ VaultView     │  │  │  │  ├─ entry           │  │  │   │
│  │  │  │  ├─ NotesView     │  │  │  │  ├─ folder          │  │  │   │
│  │  │  │  ├─ FilesView     │  │  │  │  └─ search           │  │  │   │
│  │  │  │  ├─ AuditView     │  │  │  ├─────────────────────┤  │  │   │
│  │  │  │  ├─ ScannerView   │  │  │  │  db module          │  │  │   │
│  │  │  │  ├─ SettingsView  │  │  │  │  ├─ connection      │  │  │   │
│  │  │  │  └─ SecurityCenter│  │  │  │  ├─ migrations      │  │  │   │
│  │  │  └───────────────────┘  │  │  │  └─ repository       │  │  │   │
│  │  │                         │  │  ├─────────────────────┤  │  │   │
│  │  │  ┌───────────────────┐  │  │  │  audit module       │  │  │   │
│  │  │  │  Stores           │  │  │  │  ├─ event           │  │  │   │
│  │  │  │  ├─ auth-store    │  │  │  │  ├─ logger          │  │  │   │
│  │  │  │  ├─ vault-store   │  │  │  │  └─ query            │  │  │   │
│  │  │  │  └─ app-store     │  │  │  ├─────────────────────┤  │  │   │
│  │  │  └───────────────────┘  │  │  │  scanner module     │  │  │   │
│  │  │                         │  │  │  ├─ password_strength│  │  │   │
│  │  │  ┌───────────────────┐  │  │  │  ├─ breach_check    │  │  │   │
│  │  │  │  Lib / Hooks      │  │  │  │  └─ vulnerability   │  │  │   │
│  │  │  │  ├─ tauri.ts      │  │  │  ├─────────────────────┤  │  │   │
│  │  │  │  ├─ constants.ts  │  │  │  │  commands module    │  │  │   │
│  │  │  │  ├─ use-auto-lock │  │  │  │  ├─ vault_commands  │  │  │   │
│  │  │  │  └─ use-kb-short  │  │  │  │  ├─ audit_commands  │  │  │   │
│  │  │  └───────────────────┘  │  │  │  ├─ scanner_commands│  │  │   │
│  │  │                         │  │  │  └─ crypto_commands  │  │  │   │
│  │  └─────────────────────────┘  │  └─────────────────────┘  │  │   │
│  │                                │                           │  │   │
│  │         ◀── IPC Boundary ──▶  │  ┌─────────────────────┐  │  │   │
│  │    (Tauri invoke / listen)     │  │  security module    │  │  │   │
│  │                                │  │  config module      │  │  │   │
│  │                                │  └─────────────────────┘  │  │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│                              ▼                                      │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                    Persistent Storage                         │   │
│  │  ┌────────────────────┐  ┌──────────────────────────────┐    │   │
│  │  │  SQLCipher DB      │  │  Encrypted Files             │    │   │
│  │  │  (AES-256-CBC      │  │  (AES-256-GCM per file)      │    │   │
│  │  │   page-level)      │  │  Stored on filesystem        │    │   │
│  │  └────────────────────┘  └──────────────────────────────┘    │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

### Key Architectural Principles

| Principle | Implementation |
|-----------|---------------|
| **Local-first** | All data stored on-device; no cloud dependency |
| **Zero-knowledge** | Server never sees plaintext; no server at all in Phase 1 |
| **Defense-in-depth** | SQLCipher + AES-256-GCM field-level encryption |
| **Least privilege** | Frontend never handles raw keys; all crypto in Rust |
| **Secure by default** | Strong KDF parameters; no weak algorithm options |

---

## 2. Module Responsibilities

### `crypto` — Cryptographic Operations

**Location:** `src-tauri/src/crypto/`

| Submodule | Responsibility |
|-----------|---------------|
| `kdf` | Argon2id key derivation from master password. Parameters: 256 MB memory, 3 iterations, parallelism 4 (OWASP recommended). Generates 128-bit random salt. Output: 256-bit key wrapped in `secrecy::Secret` with `ZeroizeOnDrop`. |
| `cipher` | AES-256-GCM authenticated encryption/decryption. Generates fresh 96-bit random nonce per encryption. Supports optional AAD (Additional Authenticated Data). This is the ONLY permitted symmetric cipher. |
| `key_management` | Master key lifecycle: derivation from password, key rotation (Phase 2), Shamir's Secret Sharing (Phase 3). Keys are `ZeroizeOnDrop` and wrapped in `secrecy::Secret`. |
| `random` | Cryptographically secure random number generation via `OsRng`. Used for salt generation, nonce generation, and UUID creation. |

**Critical invariant:** Plaintext passwords and cryptographic keys NEVER cross the IPC boundary to the frontend.

### `db` — Database Layer

**Location:** `src-tauri/src/db/`

| Submodule | Responsibility |
|-----------|---------------|
| `connection` | SQLCipher connection pool management. Sets PRAGMA key for encryption, enables WAL mode for concurrent reads, enables foreign key constraints. Verifies key correctness on connection. |
| `migrations` | Schema version tracking and sequential migration execution. Each migration runs in a transaction for atomicity. Forward-only (no rollback). Checksum verification (Phase 2). |
| `repository` | Generic `Repository<T, C, U>` trait for CRUD operations. Transaction helper. Pagination support. All database access goes through this abstraction layer. |

**Critical invariant:** The SQLCipher key is derived from the master password and set via PRAGMA before any data operation. The key is zeroized after being passed to the connection options.

### `vault` — Vault Entry Management

**Location:** `src-tauri/src/vault/`

| Submodule | Responsibility |
|-----------|---------------|
| `entry` | `VaultEntry` data model and CRUD request types. All sensitive fields stored as encrypted `Vec<u8>`. UUID v4 for IDs (no sequential leakage). |
| `folder` | `Folder` and `FolderNode` types for hierarchical organization. Tree building and circular reference prevention. Folder names are encrypted at rest. |
| `search` | Search functionality for vault entries (Phase 2). Will implement blind indexing for searchable encryption. |

**Critical invariant:** `CreateEntryRequest.password` contains plaintext ONLY during the encryption step. It is zeroized immediately after encryption.

### `audit` — Security Audit Logging

**Location:** `src-tauri/src/audit/`

| Submodule | Responsibility |
|-----------|---------------|
| `event` | `AuditEvent`, `EventCategory`, and `ActionType` type definitions. Categories: auth, vault, file, system, security. Events are immutable. |
| `logger` | `AuditLog` struct for structured event persistence. Tamper-evidence via hash chaining (Phase 2). |
| `query` | `AuditQuery` and `AuditQueryResult` for filtering and paginating audit events. |

**Critical invariant:** Audit events NEVER contain passwords, keys, or decrypted vault data. The `subject` field contains only session identifiers.

### `scanner` — Threat Scanning

**Location:** `src-tauri/src/scanner/`

| Submodule | Responsibility |
|-----------|---------------|
| `password_strength` | Password strength analysis (entropy estimation, pattern detection). |
| `breach_check` | Offline breach database checking using SHA-256 k-anonymity model. No network calls; no plaintext transmitted. |
| `vulnerability` | Cross-entry vulnerability scanning (reused passwords, weak passwords, expired credentials). |

**Critical invariant:** SHA-256 hashes for breach lookup are computed in memory and zeroized immediately. They are never logged or stored.

### `config` — Application Configuration

**Location:** `src-tauri/src/config/`

Manages application settings including auto-lock timeout, clipboard clear duration, theme preferences, and security policies. Configuration is loaded from the database (security_settings table) and platform-appropriate config files.

### `security` — Session & Policy Management

**Location:** `src-tauri/src/security/`

Handles session lifecycle (authentication, lock/unlock), rate limiting for failed authentication attempts, account lockout policies, and auto-lock timers. Enforces security policies like maximum session duration and minimum password complexity.

### `commands` — Tauri IPC Command Handlers

**Location:** `src-tauri/src/commands/`

| Submodule | Registered Commands |
|-----------|-------------------|
| `vault_commands` | `create_entry`, `get_entry`, `update_entry`, `delete_entry`, `list_entries`, `search_entries` |
| `audit_commands` | `get_audit_events`, `query_audit_log`, `export_audit_log` |
| `scanner_commands` | `scan_password_strength`, `check_breach_status`, `run_vulnerability_scan` |
| `crypto_commands` | `derive_key`, `encrypt_data`, `decrypt_data` |

**Critical invariant:** Command handlers validate all inputs, enforce authorization checks, and ensure sensitive data is not leaked in error messages.

---

## 3. Data Flow

### 3.1 Vault Unlock Flow

```
User enters password (UI)
        │
        ▼
Frontend calls invoke("derive_key", { password })
        │
        ▼ IPC Boundary (Tauri invoke)
Rust: crypto_commands::derive_key()
        │
        ├─► kdf::derive_key(password, salt) → DerivedKey
        │   └─ Argon2id(256MB, 3 iterations, parallelism 4)
        │
        ├─► key_management::MasterKey::from_password()
        │   └─ Wrapped in secrecy::Secret + ZeroizeOnDrop
        │
        ├─► db::connection::DbConnection::new(path, formatted_key)
        │   └─ PRAGMA key = x'<hex>'
        │   └─ PRAGMA journal_mode = WAL
        │   └─ PRAGMA foreign_keys = ON
        │
        └─► Store MasterKey in Rust-side state (never sent to frontend)
                │
                ▼
        Frontend receives: success/failure (no key material returned)
```

### 3.2 Entry Read Flow

```
User clicks vault entry (UI)
        │
        ▼
Frontend calls invoke("get_entry", { id })
        │
        ▼ IPC Boundary
Rust: vault_commands::get_entry()
        │
        ├─► db::repository::get_by_id(pool, id)
        │   └─ SQLCipher decrypts page → reads encrypted BLOB
        │
        ├─► cipher::decrypt_simple(key, nonce, ciphertext)
        │   └─ AES-256-GCM decrypt + verify authentication tag
        │   └─ Returns plaintext fields
        │
        ├─► Update accessed_at timestamp
        │
        ├─► audit::log_audit(category=Vault, action=Read, subject=session_id)
        │
        └─► Return decrypted entry to frontend via IPC
                │
                ▼
        Frontend displays entry (plaintext exists in JS memory temporarily)
                │
                ▼
        User copies password → clipboard (auto-cleared after timeout)
```

### 3.3 Entry Write Flow

```
User creates/updates entry (UI)
        │
        ▼
Frontend calls invoke("create_entry", { title, username, password, ... })
        │  NOTE: password crosses IPC in plaintext (within Tauri process memory)
        ▼ IPC Boundary
Rust: vault_commands::create_entry()
        │
        ├─► Validate input (sanitize, check constraints)
        │
        ├─► cipher::encrypt_simple(key, plaintext_fields)
        │   └─ Generate fresh 96-bit random nonce
        │   └─ AES-256-GCM encrypt each field
        │   └─ Returns (nonce, ciphertext) per field
        │
        ├─► Zeroize plaintext password immediately
        │
        ├─► db::repository::create(pool, encrypted_entry)
        │   └─ SQLCipher encrypts page → writes BLOB to disk
        │
        ├─► audit::log_audit(category=Vault, action=Create, subject=session_id)
        │
        └─► Return created entry (without password) to frontend
```

### 3.4 Data at Rest

```
┌───────────────────────────────────────────────────────────────┐
│                     Filesystem                                │
│                                                               │
│  kestrel-vault.db          ← SQLCipher database file          │
│  │  (AES-256-CBC encrypted at page level)                     │
│  │                                                             │
│  │  ├── vault_meta      → KDF params + salt (hex)             │
│  │  ├── vault_entries   → All fields AES-256-GCM BLOBs        │
│  │  ├── folders         → Name is AES-256-GCM BLOB            │
│  │  ├── secure_notes    → Title + content AES-256-GCM BLOBs   │
│  │  ├── file_entries    → Metadata AES-256-GCM BLOBs          │
│  │  ├── audit_events    → Plaintext (SQLCipher-only)          │
│  │  ├── security_settings → Plaintext (SQLCipher-only)        │
│  │  └── breach_hashes  → Plaintext (SQLCipher-only)           │
│  │                                                             │
│  kestrel-vault.db-wal      ← WAL journal                     │
│  kestrel-vault.db-shm      ← Shared memory                   │
│                                                               │
│  files/                                                       │
│  ├── <uuid>.enc            ← AES-256-GCM encrypted files      │
│  └── ...                                                      │
└───────────────────────────────────────────────────────────────┘
```

---

## 4. Security Boundaries

### 4.1 Trust Boundary Map

```
┌─────────────────────────────────────────────────────────┐
│  UNTRUSTED ZONE (WebView / JavaScript)                  │
│                                                         │
│  - React components and Zustand stores                  │
│  - Decrypted entry data displayed to user               │
│  - Clipboard contents (temporary)                       │
│  - Keyboard input (master password)                     │
│                                                         │
│  ⚠️  Assumption: JS memory can be read by:              │
│     - Browser devtools (debug mode only)                │
│     - Memory inspection tools                           │
│     - XSS (mitigated by Tauri's CSP)                   │
└─────────────────────┬───────────────────────────────────┘
                      │ IPC (Tauri invoke/listen)
                      │ - Serialized JSON messages
                      │ - Within same OS process
                      │ - No network exposure
                      ▼
┌─────────────────────────────────────────────────────────┐
│  TRUSTED ZONE (Rust Backend)                            │
│                                                         │
│  - MasterKey (secrecy::Secret + ZeroizeOnDrop)          │
│  - DerivedKey (secrecy::Secret + ZeroizeOnDrop)         │
│  - Encryption/decryption operations                     │
│  - Database connection and queries                      │
│  - Audit logging                                       │
│                                                         │
│  ✅  Guarantees:                                        │
│     - Keys never logged or serialized                   │
│     - Plaintext passwords zeroized after use            │
│     - All crypto operations use constant-time compare   │
└─────────────────────┬───────────────────────────────────┘
                      │ PRAGMA key / SQL queries
                      │ - Within same OS process
                      ▼
┌─────────────────────────────────────────────────────────┐
│  PERSISTENT STORAGE (SQLCipher + Encrypted Files)       │
│                                                         │
│  - All data encrypted at rest                           │
│  - No plaintext on disk (except audit_events/settings   │
│    which are SQLCipher-protected)                       │
│  - Database file permissions: owner read/write only     │
│                                                         │
│  ⚠️  Risks:                                             │
│     - Database file theft → requires SQLCipher key      │
│     - Cold boot attack → keys in RAM                    │
│     - Swap/page file → possible key leakage             │
└─────────────────────────────────────────────────────────┘
```

### 4.2 Boundary Rules

| Boundary | Rule | Rationale |
|----------|------|-----------|
| Frontend → Backend | Only serialized commands, no key material | Frontend is less trusted (JS memory model) |
| Backend → Frontend | Decrypted data may be sent (never keys) | User needs to see their data |
| Backend → Disk | Always encrypted (SQLCipher + AES-256-GCM) | Disk is persistent and can be stolen |
| Frontend → Disk | Never; frontend has no filesystem access | Tauri security model |
| Audit log → Anywhere | Never contains secrets | Audit log may be exported/shared |
| IPC channel | Within process memory only | No network exposure for IPC |

### 4.3 What Runs Where

| Component | Execution Environment | Access to Keys | Access to Plaintext |
|-----------|----------------------|----------------|-------------------|
| React UI | WebView (V8/WebKit) | Never | Transiently (display) |
| Zustand stores | WebView (V8/WebKit) | Never | Transiently (state) |
| Tauri commands | Rust (native) | Yes (in memory) | Yes (during encryption/decryption) |
| Crypto operations | Rust (native) | Yes (in memory) | Yes (during operation) |
| Database queries | Rust (via SQLx) | Via PRAGMA (set once) | SQLCipher handles transparently |
| File operations | Rust (native + OS) | No (keys in Rust memory) | No (files encrypted) |

---

## 5. Threat Model Summary

KESTREL Vault follows a threat-model-driven development process. Detailed threat models are maintained in `docs/threat-models/`.

### Primary Threats

| Threat | Severity | Mitigation | Detailed Model |
|--------|----------|------------|----------------|
| Database theft (offline) | Critical | SQLCipher + AES-256-GCM dual encryption | `vault-core.md` |
| Memory dumping | High | ZeroizeOnDrop, secrecy::Secret, mlock (future) | `vault-core.md` |
| Keylogging | High | Virtual keyboard option (Phase 2) | `vault-core.md` |
| Brute force (master password) | High | Argon2id with 256 MB memory cost | `vault-core.md` |
| IPC sniffing | Medium | In-process IPC only; no network exposure | `vault-core.md` |
| Clipboard scraping | Medium | Auto-clear after configurable timeout | `vault-core.md` |
| Shoulder surfing | Medium | Masked password fields, auto-lock | `vault-core.md` |
| Side-channel attacks | Low | Constant-time comparison; Argon2id (not Argon2d) | `vault-core.md` |

### Out of Scope (Phase 1)

- Remote server attacks (no server component)
- Supply chain attacks on dependencies (mitigated by cargo lockfile auditing)
- Physical device theft with unlocked vault (mitigated by auto-lock)
- Nation-state actors with zero-day exploits (beyond reasonable threat model)

For the full threat model, see [`docs/threat-models/vault-core.md`](../threat-models/vault-core.md).

---

## 6. Technology Decisions

### Why Rust?

| Factor | Decision Rationale |
|--------|-------------------|
| **Memory safety** | No buffer overflows, use-after-free, or dangling pointers — critical for a security application |
| **Zeroize support** | Rust's ownership model enables deterministic destruction (`Drop`), making secure memory cleanup reliable |
| **secrecy crate** | `secrecy::Secret` prevents accidental logging, serialization, or Debug printing of sensitive data |
| **Performance** | Argon2id with 256 MB memory cost runs in ~1 second on modern hardware; would be significantly slower in JS |
| **Crypto ecosystem** | Mature crates: `aes-gcm`, `argon2`, `sha2`, all audited and widely used |
| **No GC pauses** | Predictable latency for security operations; no garbage collector that might retain sensitive data |

### Why Tauri v2?

| Factor | Decision Rationale |
|--------|-------------------|
| **Smaller attack surface** | Tauri apps bundle at ~5-10 MB vs. Electron's ~150+ MB; fewer dependencies |
| **No Node.js runtime** | Eliminates entire Node.js attack surface (npm supply chain, Node vulnerabilities) |
| **Native IPC** | Type-safe Rust ↔ JS communication via `tauri::command` with automatic serialization |
| **Security model** | Granular capability-based permissions; no blanket filesystem/network access |
| **Cross-platform** | Single Rust codebase for Windows, macOS, Linux |
| **WebView-based UI** | Leverages system WebView (no Chromium bundling) for smaller footprint |

### Why SQLCipher?

| Factor | Decision Rationale |
|--------|-------------------|
| **Transparent encryption** | Page-level encryption with no application code changes; SQLx works as-is |
| **AES-256-CBC** | Well-analyzed, NIST-standardized encryption for database pages |
| **HMAC-SHA512** | Per-page integrity verification detects tampering |
| **Performance** | ~5-15% overhead vs. plain SQLite; acceptable for local-first app |
| **Maturity** | Used by Signal, Facebook, Mozilla; extensively audited |
| **PRAGMA key** | Simple key management via hex-encoded key derived from master password |

### Why AES-256-GCM (field-level)?

| Factor | Decision Rationale |
|--------|-------------------|
| **Authenticated encryption** | Provides both confidentiality AND integrity in a single operation |
| **No padding** | Stream cipher mode — no padding oracle attacks possible |
| **Hardware acceleration** | AES-NI instructions on modern CPUs for near-zero overhead |
| **Standard nonce size** | 96-bit nonce provides 2^32 birthday bound safety |
| **NIST recommended** | Widely analyzed; no known practical attacks |
| **Why not XChaCha20-Poly1305?** | Considered but rejected for Phase 1 due to less hardware acceleration. May be added as an option in Phase 3 for platforms without AES-NI. |

### Why Argon2id?

| Factor | Decision Rationale |
|--------|-------------------|
| **Hybrid resistance** | Combines Argon2i (side-channel resistance) and Argon2d (GPU resistance) |
| **OWASP recommended** | Industry standard for password hashing |
| **RFC 9106** | Formally standardized IETF RFC |
| **Tunable parameters** | Memory, iterations, and parallelism can be adjusted for hardware evolution |
| **Why not PBKDF2?** | GPU-parallelizable; insufficient memory hardness |
| **Why not scrypt?** | Argon2id is the successor; better analyzed and standardized |
| **Why not bcrypt?** | No memory hardness; limited to 448-bit password length |

### Why Not Electron?

| Factor | Reason |
|--------|--------|
| **Bundle size** | ~150 MB vs. Tauri's ~10 MB |
| **Chromium attack surface** | Full Chromium runtime includes numerous attack vectors |
| **Node.js in backend** | Node.js runtime introduces supply chain risk and GC unpredictability |
| **Memory usage** | Electron apps typically use 200-500 MB RAM vs. Tauri's 50-100 MB |
| **IPC security** | Electron's IPC is more complex and has had historical vulnerabilities |

---

## Appendix A: File Structure

```
kestrel-vault/
├── src-tauri/                    # Rust backend
│   ├── src/
│   │   ├── crypto/              # Cryptographic operations
│   │   ├── db/                  # Database layer
│   │   ├── vault/               # Vault entry management
│   │   ├── audit/               # Audit logging
│   │   ├── scanner/             # Threat scanning
│   │   ├── commands/            # Tauri IPC handlers
│   │   ├── config/              # Configuration
│   │   ├── security/            # Session & policy
│   │   ├── error.rs             # Error types
│   │   ├── lib.rs               # Library entry point
│   │   └── main.rs              # Binary entry point
│   ├── migrations/              # SQL migration files
│   └── Cargo.toml               # Rust dependencies
├── src/                          # React frontend
│   ├── app/                     # View components
│   ├── components/              # Reusable components
│   ├── hooks/                   # Custom React hooks
│   ├── stores/                  # Zustand state management
│   ├── lib/                     # Utilities
│   ├── types/                   # TypeScript types
│   └── styles/                  # CSS/TailwindCSS
├── docs/                         # Documentation
│   ├── architecture/            # Architecture docs
│   ├── threat-models/           # Threat models
│   └── security-notes/          # Security notes
└── package.json                  # Frontend dependencies
```

## Appendix B: Dependency Security

### Rust Dependencies (Critical Path)

| Crate | Version | Purpose | Audit Status |
|-------|---------|---------|-------------|
| `aes-gcm` | ^0.10 | AES-256-GCM encryption | RustCrypto audited |
| `argon2` | ^0.5 | Argon2id key derivation | RustCrypto audited |
| `sha2` | ^0.10 | SHA-256 for breach lookup | RustCrypto audited |
| `secrecy` | ^0.8 | Secret wrapper (no Debug/Clone) | Well-established |
| `zeroize` | ^1.7 | Secure memory zeroization | RustCrypto audited |
| `sqlx` | ^0.8 | Async SQLite driver | Community audited |
| `uuid` | ^1.0 | UUID v4 generation | Well-established |
| `chrono` | ^0.4 | Timestamp handling | Well-established |

### Frontend Dependencies

| Package | Purpose |
|---------|---------|
| React 18 | UI framework |
| Zustand | State management |
| TailwindCSS | Styling |
| Vite | Build tooling |

**No cryptographic operations occur in the frontend.** All crypto is handled by the Rust backend.
