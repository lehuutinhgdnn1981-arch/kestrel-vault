# Cryptography Security Notes

> **Scope:** All cryptographic algorithms, parameters, and practices used in KESTREL Vault
> **Audience:** Security auditors, developers, penetration testers
> **Last Updated:** 2025-03-04
> **Classification:** Internal — Security Sensitive

---

## 1. Algorithms Used

### 1.1 Key Derivation: Argon2id

**Implementation:** `src-tauri/src/crypto/kdf.rs`
**Crate:** `argon2` v0.5 (RustCrypto)

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Algorithm | Argon2id | Hybrid of Argon2i (side-channel resistant) and Argon2d (GPU resistant). RFC 9106 recommended variant. |
| Memory cost | 262144 KiB (256 MB) | OWASP 2023 recommendation. Makes GPU-based attacks expensive (each parallel guess requires 256 MB of VRAM). |
| Time cost (iterations) | 3 | OWASP 2023 recommendation. Balances security with user experience (~1s derivation time on modern hardware). |
| Parallelism | 4 lanes | OWASP 2023 recommendation. Matches typical desktop CPU core count. |
| Salt length | 16 bytes (128 bits) | RFC 9106 recommendation. Generated via `OsRng`. |
| Output length | 32 bytes (256 bits) | Matches AES-256 key size. |

**Why Argon2id?**

Argon2id is the **only** KDF used in KESTREL Vault. It was selected over alternatives for the following reasons:

- **vs. PBKDF2:** PBKDF2 is GPU-friendly (low memory requirement), allowing attackers to parallelize millions of guesses per second on modern GPUs. Argon2id's 256 MB memory cost makes GPU attacks infeasible.
- **vs. bcrypt:** bcrypt has a fixed 448-bit password length limit and no memory hardness. An attacker with a GPU can still test bcrypt hashes orders of magnitude faster than Argon2id.
- **vs. scrypt:** While scrypt is memory-hard, Argon2id is its successor with better analysis, standardization (RFC 9106), and hybrid side-channel resistance.
- **vs. Argon2i:** Argon2i alone is vulnerable to tradeoff attacks that reduce memory hardness. Argon2id's first pass uses data-independent addressing (like Argon2i), providing side-channel resistance.
- **vs. Argon2d:** Argon2d alone is vulnerable to side-channel attacks because its memory access pattern depends on the password. Argon2id avoids this for the first pass.

**Parameter Evolution Plan:**

KDF parameters are stored in the `vault_meta` table, allowing future upgrades without breaking existing vaults. When parameters are updated:

1. On unlock with old parameters, derive the key using old parameters
2. Re-derive with new parameters during key rotation
3. Re-encrypt all vault entries with the new key
4. Store new parameters in `vault_meta`

This forward-compatibility design ensures that as hardware improves, KESTREL Vault can increase memory cost and iteration count without requiring users to create new vaults.

### 1.2 Symmetric Encryption: AES-256-GCM

**Implementation:** `src-tauri/src/crypto/cipher.rs`
**Crate:** `aes-gcm` v0.10 (RustCrypto)

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Algorithm | AES-256-GCM | Authenticated encryption with associated data (AEAD). Provides confidentiality + integrity in one operation. |
| Key size | 256 bits | Maximum AES key size; provides 128-bit security level (256-bit is not a mistake — AES-256 provides 256-bit key space but 128-bit security against certain attacks). |
| Nonce size | 96 bits (12 bytes) | NIST SP 800-38D standard nonce size for GCM. Enables efficient hardware implementation. |
| Tag size | 128 bits (16 bytes) | Maximum authentication tag size. Provides strongest integrity guarantee. |
| Associated data | Optional (empty by default) | Used when plaintext metadata needs integrity protection without encryption (e.g., entry ID bound to ciphertext). |

**Why AES-256-GCM?**

AES-256-GCM is the **only** symmetric cipher permitted in KESTREL Vault. It was selected for the following reasons:

- **Authenticated encryption:** Provides both confidentiality and integrity in a single atomic operation. No separate MAC needed. No padding required (stream cipher mode). No padding oracle attacks possible.
- **NIST standardized:** AES-GCM is specified in NIST SP 800-38D and widely analyzed. Used by TLS 1.3, SSH, IPsec, and countless security-critical systems.
- **Hardware acceleration:** AES-NI instructions on x86 processors provide near-zero overhead for AES operations. ARMv8 crypto extensions provide equivalent acceleration on Apple Silicon and modern ARM chips.
- **RustCrypto quality:** The `aes-gcm` crate is part of the RustCrypto project, which uses formally verified AES implementations and has been audited.
- **No known practical attacks:** There are no known attacks on AES-256-GCM that break confidentiality or integrity when used with proper nonce management.

**Why NOT other ciphers?**

- **vs. AES-256-CBC:** No built-in authentication. Requires separate HMAC. Vulnerable to padding oracle attacks. More complex to implement correctly.
- **vs. ChaCha20-Poly1305:** Considered and may be added as an alternative in Phase 3 for platforms without AES-NI. Currently, AES-NI is available on all target platforms (x86-64, ARMv8).
- **vs. XChaCha20-Poly1305:** Extended-nonce variant eliminates nonce collision risk but is less widely standardized and lacks hardware acceleration. May be adopted if nonce management becomes a concern.
- **vs. AES-256-SIV:** Nonce-misuse resistant, but adds complexity and overhead. Current nonce management (random 96-bit) is sufficient for the vault's encryption volume.

### 1.3 Hashing (Lookup Only): SHA-256

**Implementation:** `src-tauri/src/scanner/breach_check.rs`
**Crate:** `sha2` v0.10 (RustCrypto)

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Algorithm | SHA-256 | Used ONLY for breach database lookup (k-anonymity model). NOT used for password hashing. |
| Output size | 256 bits (32 bytes) | Standard SHA-256 output. |

**IMPORTANT:** SHA-256 is **never** used for password hashing or key derivation. It is used exclusively for content-addressable lookup in the breach database, following the HIBP k-anonymity model. Speed is actually desired for this use case. The hash is computed in memory, used for lookup, and immediately zeroized.

### 1.4 Random Number Generation: OsRng

**Implementation:** `src-tauri/src/crypto/random.rs`
**Source:** `rand::rngs::OsRng`

All random values in KESTREL Vault are generated using the operating system's cryptographically secure random number generator:

- **Linux:** `getrandom()` syscall or `/dev/urandom`
- **macOS:** `arc4random_buf()` backed by `ccrng`
- **Windows:** `BCryptGenRandom` or `RtlGenRandom`

`OsRng` is used for:
- Argon2id salt generation (128 bits)
- AES-GCM nonce generation (96 bits per encryption)
- UUID v4 generation (122 bits of randomness)

**No userspace PRNG is used.** There is no `rand::thread_rng()` or any seeded PRNG. All randomness comes directly from the OS CSPRNG, eliminating the risk of PRNG state compromise or seed prediction.

---

## 2. Key Derivation Parameters — Rationale

### 2.1 Memory Cost: 256 MB

The 256 MB memory cost is the most critical Argon2id parameter. It directly determines the cost of brute-force attacks:

| Attacker Hardware | Guesses/second (estimated) | Time to crack 8-char password |
|-------------------|---------------------------|-------------------------------|
| Single GPU (RTX 4090) | ~10-50 (limited by VRAM) | ~2-10 years |
| GPU cluster (10x RTX 4090) | ~100-500 | ~2-10 months |
| Custom ASIC | Unknown but expensive | Prohibitively expensive at 256 MB |

Without memory hardness (e.g., PBKDF2 with 100k iterations):

| Attacker Hardware | Guesses/second (estimated) | Time to crack 8-char password |
|-------------------|---------------------------|-------------------------------|
| Single GPU (RTX 4090) | ~10,000,000 | ~3 hours |
| GPU cluster (10x RTX 4090) | ~100,000,000 | ~20 minutes |

The 256 MB memory cost raises the cost of each guess by ~6 orders of magnitude compared to PBKDF2.

### 2.2 Iterations (Time Cost): 3

Three iterations means the memory is filled and read three times. This provides a balance between:

- **Security:** More iterations = more CPU time per guess = harder to brute-force
- **Usability:** More iterations = longer unlock time = worse user experience

OWASP recommends ≥1 iteration with 256 MB memory. We use 3 iterations, which adds ~2x CPU cost with minimal additional wall-clock time (because memory access dominates). On a modern desktop, unlock takes approximately:

- 1 iteration: ~0.5 seconds
- 3 iterations: ~1.0 seconds
- 5 iterations: ~1.5 seconds

1 second is the target; 3 iterations achieves this on typical hardware.

### 2.3 Parallelism: 4

Parallelism (lanes) determines how many threads can compute Argon2id simultaneously. Four lanes means:

- The defender (user) can use 4 CPU threads to compute the hash in ~1 second
- The attacker must allocate 4x the memory per parallel guess (4 × 256 MB = 1 GB per parallel lane)
- This further increases the attacker's cost: to test 100 passwords in parallel, the attacker needs 100 GB of memory

Four lanes matches typical desktop CPU core counts (4-8 cores). On devices with fewer cores, the computation takes longer but remains correct.

### 2.4 Salt: 128-bit Random

The salt ensures that:

1. The same password produces different derived keys on different devices/vaults
2. Precomputed rainbow tables are useless (each salt requires a separate table)
3. Different users with the same password have different keys

128 bits provides negligible collision probability: the birthday bound is 2^64, meaning you would need ~10^19 salts before a collision becomes likely.

---

## 3. Nonce Management Strategy

### 3.1 Nonce Generation

Every AES-256-GCM encryption operation generates a fresh 96-bit (12-byte) random nonce using `OsRng`. This is implemented in `crypto/cipher.rs` via `Aes256Gcm::generate_nonce(&mut OsRng)`.

### 3.2 Why 96-bit Nonces?

AES-GCM supports two nonce lengths:

- **96 bits (recommended):** The standard nonce size. GCM internally uses the nonce directly as the counter block, making encryption efficient and simple.
- **Other lengths (not recommended):** GCM hashes the nonce to produce a 96-bit value, adding complexity and a potential attack surface.

We use 96-bit nonces exclusively. The nonce collision probability is governed by the birthday bound:

- After 2^32 (~4.3 billion) encryptions with the same key, the collision probability is approximately 2^-32 (~1 in 4 billion).
- A typical vault user will perform far fewer than 4 billion encryption operations. Even with aggressive use (100 encryptions/day), it would take ~100,000 years to reach this bound.

### 3.3 Nonce Storage

Nonces are stored alongside ciphertext in the database. Each table with encrypted fields has a `nonce` column of type BLOB. The nonce is not secret — it can be stored in plaintext. Its only requirement is uniqueness per key.

### 3.4 Nonce Reuse Prevention

**Nonce reuse with the same key is catastrophic for AES-GCM.** If the same nonce is used twice with the same key:

1. XORing the two ciphertexts reveals the XOR of the two plaintexts
2. The authentication key can be recovered, allowing forgery of arbitrary messages
3. Confidentiality is completely broken for the two messages

Our prevention strategy:

1. **Random generation:** Each nonce is independently generated from `OsRng`, making intentional collision infeasible
2. **Fresh nonce per encryption:** The `encrypt()` function always generates a new nonce; there is no API to reuse nonces
3. **Key rotation:** When the master key is rotated, all entries are re-encrypted with new nonces, resetting the nonce counter

### 3.5 Future: Counter-Based Nonces

If encryption volume ever approaches the birthday bound (unlikely but possible for server-side use), we would switch to counter-based nonces:

- Maintain a persistent counter per key
- Nonce = counter (96 bits, zero-padded)
- Store counter in `vault_meta` and increment after each encryption
- Eliminates birthday bound concern entirely (counter never repeats)

This is not implemented in Phase 1 because the encryption volume of a local password manager is far below the threshold where random nonce collision becomes a concern.

---

## 4. Key Rotation Procedure

### 4.1 When to Rotate Keys

Key rotation should be performed when:

- The user changes their master password
- A security incident is detected (e.g., suspected key compromise)
- KDF parameters are updated (e.g., increasing memory cost)
- Periodically (recommended: annually, but not enforced)

### 4.2 Rotation Steps

Key rotation is a multi-step process that must be atomic (all-or-nothing):

```
1. User provides current master password and new master password
2. Verify current master password (derive key, attempt to read vault_meta)
3. Derive new key from new password + new salt
4. Begin database transaction
5. For each vault entry:
   a. Decrypt with old key
   b. Encrypt with new key (generating fresh nonce)
   c. Update database row
6. For each folder:
   a. Decrypt name with old key
   b. Encrypt with new key
   c. Update database row
7. For each secure note:
   a. Decrypt with old key
   b. Encrypt with new key
   c. Update database row
8. For each file entry:
   a. Decrypt metadata with old key
   b. Encrypt with new key
   c. Update database row
   d. Re-encrypt file contents on disk with new key
9. Update vault_meta with new salt and KDF parameters
10. Zeroize old key
11. Zeroize all intermediate plaintext
12. Commit transaction
13. If transaction fails, rollback and zeroize new key
```

### 4.3 Transaction Safety

Key rotation runs within a single database transaction. If any step fails:

- The transaction is rolled back
- All intermediate plaintext is zeroized
- The old key remains valid
- The user is notified of the failure

This ensures the vault is never left in an inconsistent state where some entries are encrypted with the old key and others with the new key.

### 4.4 Progress Reporting

For large vaults, key rotation may take significant time. The rotation process should:

- Report progress to the frontend (e.g., "Re-encrypting entry 47/342...")
- Allow cancellation (rollback on cancel)
- Estimate time remaining based on encryption speed

### 4.5 Implementation Status

Key rotation is planned for Phase 2. The current `rotate_master_key()` function in `crypto/key_management.rs` is a placeholder that returns an error. The full implementation requires the repository layer to be complete.

---

## 5. Memory Security Approach

### 5.1 Zeroize Crate

All key material uses the `zeroize` crate for secure memory erasure:

- `DerivedKey` derives `Zeroize` with `#[zeroize(drop)]` — the key bytes are overwritten with zeros when the value is dropped
- `MasterKey` derives `ZeroizeOnDrop` — same effect, but via the `ZeroizeOnDrop` derive macro
- `AeadTag` derives `Zeroize` with `#[zeroize(drop)]`
- `KeyShare` implements `Zeroize` manually

### 5.2 Secrecy Crate

The `secrecy` crate wraps sensitive values in a `Secret<T>` type that:

- Omits `Debug` impl — key material cannot be accidentally logged via `{:?}`
- Omits `Clone` impl — key material cannot be accidentally duplicated
- Omits `Serialize` / `Deserialize` — key material cannot be accidentally serialized to JSON or other formats
- Provides `ExposeSecret` trait — requires explicit call to `expose_secret()` to access the inner value

This provides compile-time protection against common programming errors that lead to key leakage.

### 5.3 Access Pattern

Key material access follows a strict pattern:

```rust
// CORRECT: Expose key only for the duration of the crypto operation
let key = master_key.derived_key();
let result = cipher.encrypt(key.expose(), plaintext, aad)?;
// key is still wrapped in Secret; expose() returns a reference

// INCORRECT: Never extract key bytes into a long-lived variable
let raw_key = *key.expose(); // BAD: copies key bytes out of Secret
```

### 5.4 Memory Lifecycle

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  User types   │     │  Argon2id    │     │  MasterKey   │
│  password     │────►│  KDF         │────►│  (secrecy +  │
│  (String)     │     │  derive_key()│     │  ZeroizeOnDrop)
└──────┬───────┘     └──────────────┘     └──────┬───────┘
       │                                          │
       │ zeroized by caller                       │ exists while vault
       │ after KDF returns                        │ is unlocked
       ▼                                          ▼
  [0x00, 0x00, ...]                       Used for encrypt/decrypt
                                           via expose_secret()
                                                  │
                                          Vault lock / drop
                                                  │
                                                  ▼
                                          [0x00, 0x00, ...]
                                          (ZeroizeOnDrop erases)
```

### 5.5 Future: mlock and Secure Allocation

Phase 2 will add:

- **`mlock()`**: Prevent the OS from paging key memory to disk. Applied to `MasterKey` and `DerivedKey` allocations.
- **`madvise(MADV_DONTDUMP)`**: Exclude key memory from core dumps.
- **Secure allocators**: Use `zeroize`'s `SecureVec` or `memsec` crate for all temporary plaintext buffers.

These measures protect against:

- Swap file leakage (mlock prevents paging)
- Core dump leakage (MADV_DONTDUMP excludes from dumps)
- Cold boot attacks (mlock keeps pages in physical RAM, which decays faster)

### 5.6 What Is NOT Protected

Despite our best efforts, some data cannot be protected from memory-level attacks:

| Data | Why Not Protected | Mitigation |
|------|-------------------|------------|
| Password in IPC payload | Must exist as a JavaScript string during create/update | In-process IPC only; password exists for milliseconds |
| Decrypted entry in WebView | Must exist in JS memory for display | Auto-lock clears state; minimize time in JS memory |
| OS clipboard contents | Clipboard is a shared OS resource | Auto-clear after timeout |
| Memory-mapped database pages | SQLCipher may memory-map database file | Pages are encrypted; plaintext never in mapped pages |

---

## 6. Banned Algorithms

The following algorithms are **strictly prohibited** in KESTREL Vault. Any use of these algorithms in new code must be rejected in code review.

### 6.1 AES-ECB (Electronic Codebook)

| Attribute | Value |
|-----------|-------|
| **Why banned** | Deterministic encryption: identical plaintext blocks produce identical ciphertext blocks. Reveals patterns in data. No authentication. The "ECB penguin" attack demonstrates that ECB mode leaks structural information. |
| **Detection** | `cargo clippy` lint; code review for `Aes256Ecb` or `Ecb` usage |
| **Exception** | None. There is no valid use case for ECB in a password manager. |

### 6.2 AES-CBC (Cipher Block Chaining) without HMAC

| Attribute | Value |
|-----------|-------|
| **Why banned** | CBC mode provides no built-in authentication. Without a separate HMAC, CBC is vulnerable to padding oracle attacks (Vaudenay, 2002) and bit-flipping attacks. Even with HMAC, CBC requires careful MAC-then-encrypt or encrypt-then-MAC construction to avoid subtle vulnerabilities. AES-GCM provides authentication natively. |
| **Detection** | Code review for `Aes256Cbc` or `Cbc` usage without paired HMAC |
| **Exception** | SQLCipher uses AES-256-CBC internally for page-level encryption, but this is acceptable because: (1) SQLCipher adds HMAC-SHA512 per page for integrity, (2) we do not control SQLCipher's internal implementation, and (3) field-level AES-256-GCM provides independent integrity. |

### 6.3 MD5

| Attribute | Value |
|-----------|-------|
| **Why banned** | Broken collision resistance. Practical collision attacks exist (2004, Wang et al.). Chosen-prefix collision attacks (2006, Stevens et al.) allow creating two documents with the same MD5 hash. Not suitable for any security purpose. |
| **Detection** | Code review for `md5` crate usage |
| **Exception** | None. Use SHA-256 for hashing or Argon2id for password derivation. |

### 6.4 SHA-1

| Attribute | Value |
|-----------|-------|
| **Why banned** | Broken collision resistance. SHAttered attack (2017) demonstrated practical collisions. While preimage resistance is not broken, collision attacks are sufficient to reject SHA-1 for any security purpose. |
| **Detection** | Code review for `sha1` crate usage |
| **Exception** | None. Use SHA-256 for hashing. |

### 6.5 RC4

| Attribute | Value |
|-----------|-------|
| **Why banned** | Multiple devastating biases in the keystream. Fluhrer-McGrew biases, Mantin-Shamir distinguisher, AlFardan et al. plaintext recovery attacks. Completely broken for any cryptographic purpose. |
| **Detection** | Code review for `rc4` crate usage |
| **Exception** | None. |

### 6.6 DES / 3DES

| Attribute | Value |
|-----------|-------|
| **Why banned** | DES: 56-bit key is brute-forceable in hours. 3DES: 112-bit effective security (meet-in-the-middle attack), slow, and vulnerable to sweet32 birthday attacks on 64-bit blocks. |
| **Detection** | Code review for `des` or `tdes` crate usage |
| **Exception** | None. Use AES-256. |

### 6.7 RSA (for local encryption)

| Attribute | Value |
|-----------|-------|
| **Why banned** | RSA is an asymmetric cipher appropriate for key exchange and digital signatures, not for local data encryption. Using RSA for local encryption would require key management that doesn't fit our symmetric key model. If asymmetric encryption is needed in the future (e.g., for sharing vault entries), we would use ECIES or HPKE, not RSA. |
| **Detection** | Code review for `rsa` crate usage in encryption context |
| **Exception** | RSA may be used for TLS (handled by system libraries) or for specific sharing features (Phase 3+), but never for local vault encryption. |

### 6.8 Any Unauthenticated Encryption

| Attribute | Value |
|-----------|-------|
| **Why banned** | Encryption without authentication is always wrong. An attacker who can modify ciphertext (e.g., by flipping bits) can cause predictable changes in the decrypted plaintext without detection. This leads to chosen-ciphertext attacks, padding oracle attacks, and other devastating vulnerabilities. Every encryption operation MUST be authenticated. |
| **Detection** | Code review: any cipher mode without "GCM", "Poly1305", "CCM", or "SIV" in the name is suspect |
| **Exception** | None. All encryption uses AES-256-GCM (AEAD). |

---

## 7. Future Considerations

### 7.1 Post-Quantum Cryptography

**Current status:** Not required in Phase 1.

AES-256-GCM and Argon2id are not believed to be vulnerable to quantum attacks in the way that RSA and ECC are:

- **AES-256:** Grover's algorithm provides a quadratic speedup, reducing the effective security from 256 bits to 128 bits. 128-bit security is still considered adequate. No action needed.
- **Argon2id:** Grover's algorithm does not apply to memory-hard functions. The best known quantum attack against Argon2id does not provide meaningful speedup over classical attacks.
- **Shor's algorithm:** Breaks RSA and ECC. KESTREL Vault does not use these algorithms for local encryption, so this is not a concern.

**Future action:** If KESTREL Vault adds sharing features that use asymmetric encryption (Phase 3+), we will evaluate post-quantum alternatives:

- **ML-KEM (Kyber):** NIST FIPS 203 key encapsulation mechanism for key exchange
- **ML-DSA (Dilithium):** NIST FIPS 204 digital signature algorithm for signing

### 7.2 HSM Support

**Current status:** Not supported. All keys are in software.

Hardware Security Modules (HSMs) and Trusted Execution Environments (TEEs) provide hardware-backed key storage and cryptographic operations. Benefits:

- Keys never leave the hardware — immune to memory dumping
- Tamper-resistant hardware — immune to physical extraction
- Hardware-enforced rate limiting — immune to brute force

Future integration options:

- **TPM 2.0:** Available on most modern PCs. Can store sealed keys that are only released when the system is in a known state.
- **Apple Secure Enclave:** Available on Apple Silicon Macs. Can store keys in dedicated hardware.
- **YubiKey:** USB security key with PIV and OpenPGP smartcard support. Can perform on-device AES and RSA operations.
- **Platform credential storage:** Keychain (macOS), Credential Manager (Windows), libsecret (Linux).

Phase 3 may add optional HSM support for users who require the highest security level.

### 7.3 XChaCha20-Poly1305

**Current status:** Not implemented. May be added as an alternative cipher.

XChaCha20-Poly1305 uses a 192-bit nonce (vs. GCM's 96-bit), eliminating any practical concern about nonce collision. It also does not require hardware acceleration for good performance, making it suitable for older or embedded platforms.

Reasons to consider XChaCha20-Poly1305:

- Larger nonce space eliminates birthday bound concerns
- No AES-NI dependency
- Simpler software implementation with constant-time guarantees
- Used by WireGuard, libsodium, and Age encryption

Reasons we chose AES-256-GCM for Phase 1:

- All target platforms have AES-NI or ARMv8 crypto extensions
- AES-GCM is NIST standardized and required by certain compliance frameworks
- The `aes-gcm` RustCrypto crate is well-audited and maintained

If AES-256-GCM encounters issues (e.g., on a platform without AES-NI), XChaCha20-Poly1305 would be the replacement.

### 7.4 Key Splitting (Shamir's Secret Sharing)

**Current status:** Placeholder in `crypto/key_management.rs`. Planned for Phase 3.

Shamir's Secret Sharing (SSS) splits the master key into N shares, any K of which can reconstruct the original key (K-of-N threshold scheme). Use cases:

- Distribute key shares across multiple devices or people
- Require multiple parties to unlock the vault (M-of-N)
- Backup key shares in separate physical locations

Implementation will use the `ssss` or `shamirsecretsharing` crate with:

- Minimum threshold: 2-of-3 or 3-of-5
- All shares wrapped in `secrecy::Secret` + `ZeroizeOnDrop`
- Share reconstruction in memory only (never persisted)

### 7.5 Blind Indexing for Search

**Current status:** Not implemented. Planned for Phase 2.

Since all sensitive fields are encrypted, they cannot be searched directly. Blind indexing enables search on encrypted data:

1. Compute HMAC-SHA256(key, lowercase(normalize(plaintext))) for each searchable field
2. Store the HMAC in a dedicated column (e.g., `title_search_hash`)
3. When searching, compute HMAC of the search query and compare

This provides:

- Search without decrypting all entries
- No leakage of plaintext content (HMAC is one-way)
- Deterministic for exact match search (not for fuzzy search)

Limitations:

- Only supports exact prefix matching (not full-text search)
- HMAC key must be derived from the master key (lost if master key is lost)
- Not suitable for sorting (encrypted data has no natural order)

---

## Appendix A: Cryptographic Dependency Audit Trail

| Crate | Version | Algorithm | Audit | CVEs |
|-------|---------|-----------|-------|------|
| `aes-gcm` | ^0.10 | AES-256-GCM | RustCrypto formally verified | None |
| `argon2` | ^0.5 | Argon2id | RustCrypto community | None |
| `sha2` | ^0.10 | SHA-256 | RustCrypto formally verified | None |
| `secrecy` | ^0.8 | Secret wrapper | Community reviewed | None |
| `zeroize` | ^1.7 | Memory zeroization | RustCrypto reviewed | None |
| `rand` | ^0.8 | OsRng wrapper | Community reviewed | None |
| `uuid` | ^1.0 | UUID v4 | Well-established | None |

**Review cadence:** Dependency versions are reviewed monthly. Critical CVEs trigger immediate updates.

## Appendix B: SQLCipher Encryption Details

SQLCipher uses the following parameters for page-level encryption:

| Parameter | Value |
|-----------|-------|
| Page size | 4096 bytes |
| KDF algorithm | PBKDF2-HMAC-SHA512 |
| KDF iterations | 256,000 |
| Cipher | AES-256-CBC |
| MAC | HMAC-SHA512 |
| MAC iterations | 2 (fast HMAC verify) |
| Plaintext header size | 0 bytes (no unencrypted header) |

Note: SQLCipher uses PBKDF2 for its own key derivation (separate from our Argon2id). This is acceptable because:

1. SQLCipher's PBKDF2 operates on the hex-encoded derived key we provide, not the user's password directly
2. The user's password is protected by Argon2id (our first layer)
3. SQLCipher's PBKDF2 adds an additional layer of protection for the database key
4. The combined derivation is: PBKDF2(Argon2id(password, salt))

## Appendix C: Encryption Volume Analysis

To justify the 96-bit random nonce strategy, we analyze the expected encryption volume:

| Scenario | Encryptions/day | Years to 2^32 encryptions | Collision probability at 2^32 |
|----------|----------------|---------------------------|-------------------------------|
| Light use (5 entries/day) | 5 | ~2.3 million | ~2^-32 ≈ 0.00000002% |
| Moderate use (50 entries/day) | 50 | ~235,000 | ~2^-32 |
| Heavy use (500 entries/day) | 500 | ~23,500 | ~2^-32 |
| Extreme (5000 entries/day) | 5000 | ~2,350 | ~2^-32 |

Even in the extreme case, 2,350 years to reach the birthday bound is well beyond any reasonable usage pattern. The 96-bit random nonce strategy is safe for KESTREL Vault.
