# Threat Model: Vault Core

> **Feature:** Core vault module — password storage, retrieval, encryption, and key management
> **Module:** `vault`, `crypto`, `db`
> **Author:** KESTREL Security Team
> **Date:** 2025-03-04
> **Status:** Approved
> **Reviewers:** Lead Architect, Security Engineer

---

## Overview

The core vault module is the heart of KESTREL Vault. It manages the lifecycle of user credentials from the moment the master password is entered through key derivation, vault unlock, entry encryption/decryption, and vault lock. It encompasses three Rust modules:

- **`crypto`**: Key derivation (Argon2id), authenticated encryption (AES-256-GCM), key management, and random number generation.
- **`vault`**: Vault entry and folder data models, CRUD operations, and search.
- **`db`**: SQLCipher-encrypted SQLite connection management, migrations, and repository pattern.

The core vault operates on the fundamental principle that **plaintext passwords and cryptographic keys exist only in Rust memory, never on disk, never in JavaScript memory, and never in transit over any network**. The master password is entered by the user, used to derive a 256-bit key via Argon2id, and then immediately zeroized. The derived key persists in Rust memory (wrapped in `secrecy::Secret` with `ZeroizeOnDrop`) only while the vault is unlocked.

This threat model focuses on the core vault's security boundaries and does not cover the scanner, audit, or configuration modules in detail (those have their own threat models when features are added).

---

## Assets

| Asset | Classification | Location | Access |
|-------|---------------|----------|--------|
| Master password | Secret | Rust memory (transient, zeroized after KDF) | Backend only, during unlock |
| Derived key (MasterKey) | Secret | Rust memory (`secrecy::Secret` + `ZeroizeOnDrop`) | Backend only, while vault is unlocked |
| Argon2id salt | Confidential | `vault_meta` table (SQLCipher-protected) | Backend (via PRAGMA key) |
| KDF parameters (iterations, memory, parallelism) | Internal | `vault_meta` table (SQLCipher-protected) | Backend |
| Encrypted entry BLOBs | Confidential | `vault_entries` table (SQLCipher + AES-256-GCM) | Backend (after dual decryption) |
| Encrypted password BLOBs | Confidential | `vault_entries.encrypted_password` | Backend (after dual decryption) |
| Encrypted folder names | Confidential | `folders.name` (AES-256-GCM BLOB) | Backend (after decryption) |
| Nonces (96-bit AES-GCM) | Internal | Stored alongside ciphertext in DB | Backend |
| Decrypted entry fields (title, username, password, notes) | Secret | Rust memory (transient, during operation) | Backend only, zeroized after use |
| SQLCipher key (PRAGMA key) | Secret | Rust memory (transient, set during connection) | Backend only |
| Audit events | Internal | `audit_events` table (SQLCipher-only protection) | Backend |
| Security settings | Internal | `security_settings` table (SQLCipher-only) | Backend |

---

## Threat Actors

| Actor | Capabilities | Motivation | Sophistication |
|-------|-------------|------------|---------------|
| **Local Attacker** | Physical or remote shell access to the user's machine. Can read/write files, inspect `/proc/*/mem`, run arbitrary processes. | Credential theft, financial gain | Medium-High |
| **Malware** | Executes as user process. Can read process memory, hook system calls, log keystrokes, intercept clipboard. Cannot (easily) break out of user space. | Mass credential theft, financial gain | High |
| **Shoulder Surfer** | Physically present. Can see screen, observe keyboard. No technical access. | Credential theft, curiosity | Low |
| **Forensic Analyst** | Has physical device. Uses memory imaging, disk forensics, cold boot attacks, JTAG debugging. Well-funded. | Investigation, evidence gathering | Very High |
| **Supply Chain Attacker** | Attempts to compromise Rust crates, npm packages, or build pipeline. Can inject malicious code into dependencies. | Mass credential theft, backdoor | Very High |

---

## Attack Vectors

### AV-1: Memory Dumping (Live System)

| Attribute | Value |
|-----------|-------|
| **Description** | An attacker with process-level access reads the KESTREL Vault process memory to extract the derived master key or plaintext passwords. This can be done via `/proc/<pid>/mem`, `ptrace`, debug APIs, or malware injecting into the process. |
| **Threat Actor** | Local Attacker, Malware, Forensic Analyst |
| **Severity** | Critical |
| **Likelihood** | Medium |
| **Impact** | Complete vault compromise — all encrypted entries can be decrypted using the extracted master key |
| **Prerequisites** | Attacker has user-level code execution on the same machine while the vault is unlocked |
| **Attack Steps** | 1. Attacker gains shell or code execution on user's machine <br>2. Identifies the KESTREL Vault process <br>3. Reads process memory via `/proc/<pid>/mem` or debug API <br>4. Scans memory for patterns consistent with 32-byte key material or plaintext passwords <br>5. Uses extracted key to decrypt the SQLCipher database and/or AES-256-GCM field-level ciphertext |
| **Mitigation** | See M-1, M-2, M-3, M-4 |

### AV-2: Memory Dumping (Cold Boot)

| Attribute | Value |
|-----------|-------|
| **Description** | A forensic analyst performs a cold boot attack, rapidly cooling RAM chips to preserve their contents after power-off, then booting a minimal OS to dump memory contents. Key material in DRAM may persist for seconds to minutes. |
| **Threat Actor** | Forensic Analyst |
| **Severity** | Critical |
| **Likelihood** | Low |
| **Impact** | Complete vault compromise if keys are still present in DRAM |
| **Prerequisites** | Physical access to the machine shortly after power-off; specialized equipment |
| **Attack Steps** | 1. Gain physical access to the running machine <br>2. Cool RAM using compressed air or liquid nitrogen <br>3. Reboot into memory dumper <br>4. Search memory dump for key material <br>5. Use recovered keys to decrypt vault |
| **Mitigation** | See M-1, M-2, M-5 |

### AV-3: Keylogging

| Attribute | Value |
|-----------|-------|
| **Description** | Malware or a hardware keylogger captures the user's master password as it is typed. With the master password and access to the salt (stored in the database), the attacker can derive the master key and decrypt the entire vault. |
| **Threat Actor** | Malware, Local Attacker |
| **Severity** | Critical |
| **Likelihood** | Medium |
| **Impact** | Complete vault compromise — master password enables full key derivation |
| **Prerequisites** | Keylogger installed on the system (software) or inline with keyboard (hardware) |
| **Attack Steps** | 1. Keylogger captures master password keystrokes <br>2. Attacker also obtains the vault database file (e.g., from disk theft or file access) <br>3. Attacker reads the salt from `vault_meta` <br>4. Attacker runs Argon2id(password, salt) to derive the key <br>5. Attacker uses the key to decrypt the SQLCipher database <br>6. Attacker uses the same key to decrypt AES-256-GCM field-level ciphertext |
| **Mitigation** | See M-6, M-7, M-8 |

### AV-4: Database Theft (Offline)

| Attribute | Value |
|-----------|-------|
| **Description** | An attacker copies the SQLCipher database file from disk without the master password. They attempt to decrypt it by brute-forcing the master password through the Argon2id KDF, or by exploiting weaknesses in SQLCipher configuration. |
| **Threat Actor** | Local Attacker, Forensic Analyst |
| **Severity** | High |
| **Likelihood** | Medium |
| **Impact** | If the master password is weak, complete vault compromise. If strong, attacker is limited to brute-force which should be computationally infeasible. |
| **Prerequisites** | Access to the database file on disk (e.g., stolen laptop, backup exposure, malware file exfiltration) |
| **Attack Steps** | 1. Attacker obtains the SQLCipher database file <br>2. Attacker reads the salt from the first page (SQLCipher header is unencrypted, but `vault_meta` table is encrypted; attacker would need to try passwords against the PRAGMA key) <br>3. Attacker attempts dictionary attack: for each candidate password, derive key via Argon2id and attempt to open the database <br>4. If successful, attacker can read all data protected by SQLCipher <br>5. Attacker then needs the same key for AES-256-GCM field-level decryption (defense-in-depth) |
| **Mitigation** | See M-9, M-10, M-11 |

### AV-5: IPC Sniffing / Interception

| Attribute | Value |
|-----------|-------|
| **Description** | An attacker intercepts or inspects the IPC channel between the Tauri frontend (WebView) and the Rust backend. The IPC channel carries plaintext passwords when creating or updating entries (the frontend sends the plaintext to Rust for encryption). |
| **Threat Actor** | Malware, Local Attacker |
| **Severity** | Medium |
| **Likelihood** | Low |
| **Impact** | Exposure of individual passwords as they are created or updated (not bulk vault access) |
| **Prerequisites** | Ability to inspect or hook into the Tauri IPC mechanism within the same process |
| **Attack Steps** | 1. Attacker hooks the IPC layer (e.g., via Frida or LD_PRELOAD) <br>2. Intercepts `invoke("create_entry", { ..., password: "..." })` calls <br>3. Extracts the plaintext password from the serialized message |
| **Mitigation** | See M-12, M-13 |

### AV-6: Brute Force (Online)

| Attribute | Value |
|-----------|-------|
| **Description** | An attacker with access to the running application (but not the master password) repeatedly attempts to unlock the vault by guessing passwords through the UI or IPC. Each attempt triggers the Argon2id KDF, which is deliberately expensive. |
| **Threat Actor** | Local Attacker |
| **Severity** | Medium |
| **Likelihood** | Medium |
| **Impact** | If the master password is weak, vault compromise. Otherwise, denial of service from rate limiting. |
| **Prerequisites** | Access to the running application or IPC endpoint |
| **Attack Steps** | 1. Attacker accesses the unlock screen or IPC <br>2. Attempts common passwords (dictionary attack) <br>3. Each attempt takes ~1 second due to Argon2id memory cost <br>4. After N failed attempts, rate limiting or lockout activates |
| **Mitigation** | See M-14, M-15 |

### AV-7: Clipboard Scraping

| Attribute | Value |
|-----------|-------|
| **Description** | After the user copies a password to the clipboard, malware reads the clipboard contents before the auto-clear timer expires. Clipboard data is typically accessible to all applications on the system. |
| **Threat Actor** | Malware, Local Attacker |
| **Severity** | Medium |
| **Likelihood** | Medium |
| **Impact** | Exposure of individual passwords that the user copies (not bulk vault access) |
| **Prerequisites** | Malware running on the system that monitors clipboard |
| **Attack Steps** | 1. User copies a password from KESTREL Vault <br>2. Malware monitors clipboard and captures the content <br>3. Before auto-clear activates, password is captured |
| **Mitigation** | See M-16, M-17 |

### AV-8: Side-Channel Attacks (Timing)

| Attribute | Value |
|-----------|-------|
| **Description** | An attacker measures the time taken by cryptographic operations to infer information about the key or plaintext. For example, comparing AES-GCM authentication tag verification timing to distinguish between correct and incorrect keys, or measuring Argon2id execution time to infer password length. |
| **Threat Actor** | Local Attacker, Malware |
| **Severity** | Low |
| **Likelihood** | Low |
| **Impact** | Partial information leakage about key material; unlikely to lead to direct vault compromise |
| **Prerequisites** | Very precise timing measurement capability on the same machine |
| **Attack Steps** | 1. Attacker triggers decryption operations with crafted inputs <br>2. Measures nanosecond-level timing differences <br>3. Attempts to infer key bits from timing variations |
| **Mitigation** | See M-18, M-19 |

### AV-9: Swap/Page File Leakage

| Attribute | Value |
|-----------|-------|
| **Description** | The operating system may page Rust process memory to disk (swap file / page file), including memory containing the master key or plaintext passwords. If the swap file is not securely erased, key material may persist on disk after the vault is locked or the process exits. |
| **Threat Actor** | Local Attacker, Forensic Analyst |
| **Severity** | High |
| **Likelihood** | Low |
| **Impact** | Potential recovery of key material from swap file, leading to vault compromise |
| **Prerequisites** | Access to the swap/page file on disk; system was swapping while vault was unlocked |
| **Attack Steps** | 1. System pages Rust process memory to disk <br>2. Key material or plaintext is written to swap file <br>3. Attacker images the disk and searches the swap file <br>4. Extracts key material from swap file contents |
| **Mitigation** | See M-20, M-21 |

### AV-10: Disk Forensics (After Deletion)

| Attribute | Value |
|-----------|-------|
| **Description** | When vault entries are deleted, the database pages containing the encrypted data may not be immediately overwritten. An attacker with disk forensics tools could recover deleted entries from unallocated database pages or from the WAL journal. |
| **Threat Actor** | Forensic Analyst, Local Attacker |
| **Severity** | Medium |
| **Likelihood** | Low |
| **Impact** | Recovery of previously deleted encrypted entries (still require the key to decrypt) |
| **Prerequisites** | Access to the raw disk; entries were deleted but database pages not vacuumed |
| **Attack Steps** | 1. Attacker images the disk or copies the database file <br>2. Uses SQLite forensic tools to recover deleted pages from the WAL or free page list <br>3. Recovers encrypted BLOBs from deleted entries <br>4. If attacker also has the key, decrypts recovered entries |
| **Mitigation** | See M-22, M-23 |

---

## Mitigations

### M-1: ZeroizeOnDrop for All Key Material

| Attribute | Value |
|-----------|-------|
| **Addresses** | AV-1, AV-2 |
| **Description** | All cryptographic key material implements `ZeroizeOnDrop` via the `zeroize` crate. When a `DerivedKey` or `MasterKey` goes out of scope, its memory is overwritten with zeros before deallocation. The `secrecy::Secret` wrapper additionally prevents accidental exposure through `Debug`, `Clone`, or `Serialize` implementations. |
| **Implementation** | `MasterKey` derives `ZeroizeOnDrop`; `DerivedKey` derives `Zeroize` with `#[zeroize(drop)]`. Both wrap key bytes in `secrecy::Secret<[u8; 32]>`. See `crypto/key_management.rs` and `crypto/kdf.rs`. |
| **Verification** | Code review of all types holding key material; unit tests confirming `Zeroize` trait implementations; `cargo test` for drop behavior. |
| **Status** | Implemented |

### M-2: Key Material Wrapped in secrecy::Secret

| Attribute | Value |
|-----------|-------|
| **Addresses** | AV-1 |
| **Description** | The `secrecy` crate wraps sensitive values in a `Secret` type that deliberately omits `Debug`, `Clone`, `Serialize`, and `PartialEq` implementations for the inner value. This prevents key material from being accidentally logged, serialized to JSON, or compared in a timing-sensitive way. |
| **Implementation** | `MasterKey.key: Secret<DerivedKey>`; `DerivedKey.key: Secret<[u8; 32]>`. Access only via `expose_secret()`. See `crypto/key_management.rs:32` and `crypto/kdf.rs:74`. |
| **Verification** | Code review; `cargo clippy` with strict linting; attempt to log or serialize a key should fail at compile time. |
| **Status** | Implemented |

### M-3: Plaintext Password Zeroization After Use

| Attribute | Value |
|-----------|-------|
| **Addresses** | AV-1 |
| **Description** | When a plaintext password is received (e.g., in `CreateEntryRequest.password`), it is used for encryption and then immediately zeroized. The caller is responsible for ensuring the password is not retained in any data structure after the encryption operation completes. |
| **Implementation** | Documented in `vault/entry.rs` and `commands/vault_commands.rs`. The `CreateEntryRequest.password` field must be zeroized by the command handler after encryption. |
| **Verification** | Code review of all command handlers that receive plaintext passwords; grep for `zeroize` calls after encryption operations. |
| **Status** | Implemented |

### M-4: Auto-Lock Timer

| Attribute | Value |
|-----------|-------|
| **Addresses** | AV-1, AV-2, AV-7 |
| **Description** | The vault automatically locks after a configurable period of inactivity (default: 5 minutes). When locked, the `MasterKey` is dropped, triggering `ZeroizeOnDrop` which overwrites the key material. This minimizes the window of exposure for memory-based attacks. |
| **Implementation** | `security` module enforces auto-lock; `use-auto-lock` hook in frontend triggers lock via IPC. |
| **Verification** | Functional testing: verify key material is zeroized after lock; timing test for auto-lock trigger. |
| **Status** | Implemented (frontend hook); backend enforcement pending |

### M-5: Memory Locking (mlock) — Future

| Attribute | Value |
|-----------|-------|
| **Addresses** | AV-2, AV-9 |
| **Description** | Use `mlock()` system call to prevent the OS from paging memory regions containing key material to disk. This prevents swap file leakage and makes cold boot attacks more difficult. Requires careful memory management to avoid locking too much memory (RLIMIT_MEMLOCK). |
| **Implementation** | Use the `memsec` or `secrecy` crate's optional mlock feature. Apply to `MasterKey` and `DerivedKey` allocations. Must respect OS limits on locked memory. |
| **Verification** | Integration test confirming key memory is not present in swap file; check `mlock` return values. |
| **Status** | Future (Phase 2) |

### M-6: Virtual Keyboard Option — Future

| Attribute | Value |
|-----------|-------|
| **Addresses** | AV-3 |
| **Description** | Provide an on-screen virtual keyboard for entering the master password, bypassing hardware and software keyloggers. The virtual keyboard randomizes key positions on each display to prevent position-based logging. |
| **Implementation** | React component with randomized key layout; click events produce characters without physical key presses. |
| **Verification** | Penetration testing with known keyloggers; verify keylogger captures no keystrokes during virtual keyboard use. |
| **Status** | Future (Phase 2) |

### M-7: Biometric Authentication — Future

| Attribute | Value |
|-----------|-------|
| **Addresses** | AV-3 |
| **Description** | Use platform biometric APIs (Touch ID, Windows Hello, Linux PAM) as an alternative to typing the master password. The biometric token unlocks a stored key reference, avoiding the need to type the password entirely. |
| **Implementation** | Tauri biometric plugin; platform-specific key storage (Keychain, Credential Manager, libsecret). |
| **Verification** | Functional testing on each platform; verify biometric bypass is not possible. |
| **Status** | Future (Phase 3) |

### M-8: Master Password Strength Enforcement

| Attribute | Value |
|-----------|-------|
| **Addresses** | AV-3, AV-4, AV-6 |
| **Description** | During vault creation and password change, enforce minimum password strength requirements. Reject passwords that are found in common breach lists, are too short (<12 chars), or lack complexity. Display real-time strength feedback using the scanner module. |
| **Implementation** | `scanner/password_strength.rs` evaluates password strength; `security` module enforces minimum threshold during vault creation and key rotation. |
| **Verification** | Unit tests with known-weak passwords; verify rejection of passwords below threshold. |
| **Status** | Implemented (scanner); enforcement pending |

### M-9: Argon2id with High Memory Cost

| Attribute | Value |
|-----------|-------|
| **Addresses** | AV-4, AV-6 |
| **Description** | Key derivation uses Argon2id with 256 MB memory cost, 3 iterations, and parallelism 4 (OWASP recommendations). This makes offline brute-force attacks extremely expensive: each guess requires 256 MB of memory and ~1 second of computation. An attacker with a GPU can parallelize fewer guesses than with PBKDF2 or bcrypt because each guess requires dedicated memory. |
| **Implementation** | `crypto/kdf.rs` with `MEMORY_COST = 256 * 1024`, `ITERATIONS = 3`, `PARALLELISM = 4`. Parameters stored in `vault_meta` for future upgradeability. |
| **Verification** | Benchmark: verify derivation takes >0.5s on target hardware; verify parameters match OWASP recommendations. |
| **Status** | Implemented |

### M-10: Dual Encryption (SQLCipher + AES-256-GCM)

| Attribute | Value |
|-----------|-------|
| **Addresses** | AV-4 |
| **Description** | Sensitive data is protected by two independent layers of encryption: SQLCipher page-level encryption (AES-256-CBC with HMAC-SHA512) and field-level AES-256-GCM. An attacker who compromises the SQLCipher key (e.g., through a SQLCipher vulnerability) still cannot read individual fields without the AES-256-GCM key. Both keys are derived from the same master password, but the encryption layers use different key material (the SQLCipher key is the hex-encoded derived key; the AES-256-GCM key is the raw derived key bytes). |
| **Implementation** | `db/connection.rs` sets SQLCipher PRAGMA key; `crypto/cipher.rs` performs field-level AES-256-GCM. Schema defined in `migrations/001_initial.sql`. |
| **Verification** | Integration test: verify that reading raw database pages yields only encrypted data; verify field-level ciphertext cannot be decrypted without the master key. |
| **Status** | Implemented |

### M-11: Database File Permissions

| Attribute | Value |
|-----------|-------|
| **Addresses** | AV-4, AV-10 |
| **Description** | The SQLCipher database file is created with restrictive file permissions (owner read/write only, 0600 on Unix). This prevents other user accounts on the same machine from reading the database file directly. |
| **Implementation** | SQLx connection options set file mode; Rust `std::fs` sets permissions after creation. |
| **Verification** | Check file permissions after database creation on each platform. |
| **Status** | Planned |

### M-12: In-Process IPC Only

| Attribute | Value |
|-----------|-------|
| **Addresses** | AV-5 |
| **Description** | Tauri v2's IPC mechanism operates entirely within the same OS process. The WebView communicates with the Rust backend through an in-process message passing system, not over a network socket or named pipe. This means there is no network-exposed IPC channel to sniff from another machine or user session. |
| **Implementation** | Tauri v2 architecture — `invoke()` calls are routed in-process. No external IPC endpoints are opened. |
| **Verification** | Network scanning: verify no TCP/UDP listeners during vault operation; code review of Tauri configuration. |
| **Status** | Implemented (Tauri v2 default) |

### M-13: Minimize Plaintext in IPC

| Attribute | Value |
|-----------|-------|
| **Addresses** | AV-5 |
| **Description** | Where possible, avoid sending plaintext passwords over IPC. For example, password generation should happen in Rust and return only the encrypted result, not the plaintext. For the initial create/update flow, the password must cross IPC, but it should be zeroized immediately after encryption on the Rust side. Future consideration: perform password entry entirely in a native Rust dialog that never touches the WebView. |
| **Implementation** | `commands/vault_commands.rs` handles passwords only during encryption; `commands/crypto_commands.rs` does not expose raw keys. |
| **Verification** | Code review: grep for all IPC command signatures that accept or return sensitive data; verify no keys are returned. |
| **Status** | Partially implemented; future: native password dialog |

### M-14: Rate Limiting for Failed Authentication

| Attribute | Value |
|-----------|-------|
| **Addresses** | AV-6 |
| **Description** | Implement exponential backoff for failed unlock attempts. After 5 failed attempts, impose a 30-second delay. After 10 failed attempts, impose a 5-minute delay. After 15 failed attempts, lock the vault and require a restart. This makes online brute-force attacks impractical. |
| **Implementation** | `security` module tracks failed attempt count and timestamps; enforces delay before allowing next attempt. |
| **Verification** | Functional test: attempt rapid unlocks and verify delays are enforced; verify counters reset on successful unlock. |
| **Status** | Planned |

### M-15: Argon2id Inherent Rate Limiting

| Attribute | Value |
|-----------|-------|
| **Addresses** | AV-6 |
| **Description** | Even without application-level rate limiting, each unlock attempt requires ~1 second of Argon2id computation with 256 MB memory. This provides inherent rate limiting: an attacker cannot test more than ~60 passwords per minute on a single machine, making online brute-force infeasible for any reasonably strong password. |
| **Implementation** | `crypto/kdf.rs` — inherent to Argon2id parameter selection. |
| **Verification** | Benchmark: verify derivation time on target hardware. |
| **Status** | Implemented |

### M-16: Clipboard Auto-Clear

| Attribute | Value |
|-----------|-------|
| **Addresses** | AV-7 |
| **Description** | After a password is copied to the clipboard, a timer starts (default: 30 seconds). When the timer expires, the clipboard is overwritten with an empty string. This limits the window during which clipboard-scraping malware can capture the password. |
| **Implementation** | `use-auto-lock` hook or dedicated clipboard module in Rust; uses Tauri clipboard API to clear after timeout. |
| **Verification** | Functional test: copy password, wait for timeout, verify clipboard is empty. |
| **Status** | Planned |

### M-17: Clipboard Clear on Lock

| Attribute | Value |
|-----------|-------|
| **Addresses** | AV-7 |
| **Description** | When the vault locks (manually or via auto-lock), the clipboard is immediately cleared. This prevents an attacker from accessing the clipboard after the user has walked away and the vault has auto-locked. |
| **Implementation** | Lock handler clears clipboard as part of the lock sequence. |
| **Verification** | Functional test: copy password, trigger lock, verify clipboard is empty. |
| **Status** | Planned |

### M-18: Constant-Time Comparison

| Attribute | Value |
|-----------|-------|
| **Addresses** | AV-8 |
| **Description** | All cryptographic comparisons (e.g., AES-GCM authentication tag verification) are performed in constant time. The `aes-gcm` crate handles this internally — tag verification uses constant-time comparison to prevent timing side channels. Application-level comparisons (e.g., checking if a derived key matches) also use constant-time functions. |
| **Implementation** | `aes-gcm` crate uses `subtle` for constant-time comparison; application code uses `subtle::ConstantTimeEq` where needed. |
| **Verification** | Code review; verify no `==` comparisons on secret data; verify `aes-gcm` dependency uses constant-time verification. |
| **Status** | Implemented |

### M-19: Argon2id (Not Argon2d) for Side-Channel Resistance

| Attribute | Value |
|-----------|-------|
| **Addresses** | AV-8 |
| **Description** | Argon2id is used instead of Argon2d because it provides side-channel resistance. Argon2d's memory access pattern depends on the password, making it vulnerable to cache-timing attacks. Argon2id's first pass is independent of the password (like Argon2i), providing resistance to side-channel analysis, while its subsequent passes are data-dependent (like Argon2d), providing GPU resistance. |
| **Implementation** | `crypto/kdf.rs` uses `Algorithm::Argon2id` from the `argon2` crate. |
| **Verification** | Code review: verify `Algorithm::Argon2id` is specified; verify no use of `Argon2d` or `Argon2i` alone. |
| **Status** | Implemented |

### M-20: Secure Memory Allocation — Future

| Attribute | Value |
|-----------|-------|
| **Addresses** | AV-9 |
| **Description** | Use secure memory allocators (e.g., `zeroize::secure::SecureVec` or `memsec::MallocArray`) for all key material. These allocators use `mlock()` to prevent paging and `madvise(MADV_DONTDUMP)` to exclude memory from core dumps. Combined with `ZeroizeOnDrop`, this provides comprehensive memory protection. |
| **Implementation** | Integrate `zeroize` secure allocation features or `memsec` crate. Apply to `MasterKey`, `DerivedKey`, and temporary plaintext buffers. |
| **Verification** | Integration test: verify key memory is not present in core dumps; verify `mlock` succeeds. |
| **Status** | Future (Phase 2) |

### M-21: Disable Core Dumps

| Attribute | Value |
|-----------|-------|
| **Addresses** | AV-9 |
| **Description** | On startup, the Rust backend disables core dump generation for the process. This prevents key material from being written to disk if the process crashes. On Linux, this is done via `prctl(PR_SET_DUMPABLE, 0)` or `setrlimit(RLIMIT_CORE, 0)`. On macOS, similar mechanisms exist. |
| **Implementation** | Platform-specific code in `main.rs` or `lib.rs` startup sequence. |
| **Verification** | Trigger a crash and verify no core dump is generated. |
| **Status** | Future (Phase 2) |

### M-22: SQL VACUUM After Deletion — Future

| Attribute | Value |
|-----------|-------|
| **Addresses** | AV-10 |
| **Description** | After deleting vault entries, optionally run `VACUUM` to reclaim database pages and overwrite the freed space. This prevents forensic recovery of deleted encrypted entries. VACUUM rebuilds the entire database file, eliminating free pages that might contain deleted data. |
| **Implementation** | Add a "secure delete" option in settings that triggers VACUUM after deletion operations. Warn user about performance impact. |
| **Verification** | Forensic test: delete entries, run VACUUM, image database, verify deleted data is unrecoverable. |
| **Status** | Future (Phase 2) |

### M-23: WAL Checkpoint on Lock

| Attribute | Value |
|-----------|-------|
| **Addresses** | AV-10 |
| **Description** | When the vault is locked, force a WAL checkpoint to merge the WAL journal into the main database file. This reduces the forensic surface by ensuring the WAL file (which may contain deleted page fragments) is merged and the WAL file can be safely truncated. |
| **Implementation** | Execute `PRAGMA wal_checkpoint(TRUNCATE)` during the lock sequence. |
| **Verification** | Functional test: verify WAL file size after lock is minimal. |
| **Status** | Future (Phase 2) |

---

## Residual Risks

| Risk | Severity | Justification for Acceptance | Revisit Trigger |
|------|----------|------------------------------|-----------------|
| Key material in process memory during vault unlock | Critical | Unavoidable: the key must exist in memory while the vault is unlocked. `ZeroizeOnDrop` and `secrecy::Secret` minimize exposure. `mlock` (Phase 2) will further reduce risk. | If new memory extraction techniques emerge that bypass `ZeroizeOnDrop` |
| Plaintext password crosses IPC during create/update | Medium | Tauri IPC is in-process only; no network exposure. The password exists in IPC for milliseconds before encryption. Future: native password dialog. | If Tauri IPC mechanism changes to network-based |
| Swap file may contain key material | High | `mlock` (Phase 2) will prevent paging of key memory. Current mitigation: auto-lock reduces time window. | If users report vault compromise traced to swap file |
| Clipboard exposure after copy | Medium | Auto-clear (30s default) limits window. Clipboard is inherently a shared resource. | If clipboard scraping attacks become more prevalent |
| Side-channel attacks (timing, cache) | Low | Argon2id provides side-channel resistance. Constant-time comparison for crypto ops. Practical timing attacks on AES-GCM are not demonstrated in literature. | If published research demonstrates practical side-channel on AES-GCM |
| SQLCipher implementation vulnerabilities | Medium | SQLCipher is mature and well-audited, but any implementation may have bugs. Dual encryption (AES-256-GCM) provides defense-in-depth. | If SQLCipher CVE is published |
| Weak master passwords | High | Technical mitigations (Argon2id) cannot compensate for a weak master password. Password strength enforcement and user education are the primary mitigations. | If brute-force attacks become faster due to hardware advances |
| Cold boot attacks | Critical (but unlikely) | Practical cold boot attacks require physical access and specialized equipment. Memory is zeroized on lock. `mlock` (Phase 2) provides partial mitigation. | If cold boot attack techniques become easier or more widely available |

---

## Security Requirements

### Mandatory Requirements (SHALL)

1. The vault core SHALL derive the master key using Argon2id with a minimum of 256 MB memory cost, 3 iterations, and parallelism 4.
2. All key material SHALL implement `ZeroizeOnDrop` and be wrapped in `secrecy::Secret`.
3. Plaintext passwords SHALL be zeroized immediately after encryption operations.
4. The SQLCipher database SHALL use AES-256-CBC page-level encryption with HMAC-SHA512 integrity verification.
5. All sensitive fields SHALL be encrypted with AES-256-GCM at the field level in addition to SQLCipher page-level encryption.
6. Each AES-256-GCM encryption SHALL use a fresh, cryptographically random 96-bit nonce.
7. The vault SHALL auto-lock after a configurable period of inactivity (default: 5 minutes).
8. Failed unlock attempts SHALL be rate-limited with exponential backoff.
9. Audit events SHALL NOT contain passwords, keys, or decrypted vault data.
10. The IPC channel SHALL NOT expose cryptographic keys to the frontend.
11. Database file permissions SHALL be set to owner read/write only (0600 on Unix).
12. The master key SHALL NOT be persisted to disk in any form.

### Recommended Requirements (SHOULD)

1. The vault SHOULD use `mlock()` to prevent key material from being paged to disk.
2. The vault SHOULD disable core dumps on startup.
3. The vault SHOULD offer a virtual keyboard for master password entry.
4. The vault SHOULD support biometric authentication as an alternative to password entry.
5. The clipboard SHOULD be automatically cleared after a configurable timeout (default: 30 seconds).
6. The clipboard SHOULD be cleared when the vault is locked.
7. The vault SHOULD perform a WAL checkpoint on lock to minimize forensic surface.
8. Password strength enforcement SHOULD reject master passwords below a minimum entropy threshold.

---

## Monitoring & Detection

### Audit Events

| Event | Category | Action | Trigger | Metadata |
|-------|----------|--------|---------|----------|
| Vault unlock attempt | Auth | Login/Unlock | User submits master password | `success: bool` |
| Vault locked | Auth | Lock | Manual lock, auto-lock, or system lock | `reason: manual/timeout/system` |
| Entry created | Vault | Create | New vault entry saved | `entry_id: UUID` |
| Entry read | Vault | Read | Entry viewed by user | `entry_id: UUID` |
| Entry updated | Vault | Update | Entry modified | `entry_id: UUID`, `fields_changed: [string]` |
| Entry deleted | Vault | Delete | Entry removed | `entry_id: UUID` |
| Failed unlock | Security | Violation | Incorrect master password | `attempt_count: int` |
| Rate limit triggered | Security | Violation | Too many failed attempts | `attempt_count: int`, `delay_seconds: int` |
| Key rotation | Security | ConfigChange | Master key rotated | `entries_reencrypted: int` |
| Database opened | System | Unlock | Database connection established | N/A |

### Anomaly Detection

| Anomaly | Detection Method | Alert Threshold | Response |
|---------|-----------------|-----------------|----------|
| Rapid unlock failures | Count consecutive failures per session | > 5 in 60 seconds | Exponential backoff; flag in audit log |
| Unusual access patterns | Compare access timestamps against user baseline | Access at unusual hours or excessive volume | Log warning; suggest password change |
| Mass entry export | Count entries read in rapid succession | > 50 entries in 60 seconds | Log warning; require re-authentication |
| Database file modification from outside | Check file modification timestamp against last write | Modification without corresponding app operation | Alert user; verify integrity |

### Logging Requirements

**Must log:**
- All vault unlock/lock events with timestamps and outcomes
- All entry CRUD operations with entry IDs (not entry contents)
- All failed authentication attempts with attempt counts
- All rate-limiting events
- All key rotation events

**Must NOT log:**
- Master password (plaintext or hashed)
- Derived keys or any key material
- Decrypted entry fields (passwords, usernames, notes)
- Nonce values (they are not secret, but logging them is unnecessary)
- Session tokens that could be replayed

---

## Review History

| Date | Reviewer | Result | Notes |
|------|----------|--------|-------|
| 2025-03-04 | Security Team | Approved | Initial threat model for Phase 1; Phase 2 mitigations (mlock, biometric) tracked |
