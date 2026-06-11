# IPC Security Model — KESTREL Vault

## Trust Boundary

```
┌─────────────────────────────────────────────────┐
│  UNTRUSTED ZONE (React)                         │
│  - Presentation only                            │
│  - No keys, no encryption, no decryption        │
│  - All Tauri calls via lib/tauri.ts             │
├─────────────── IPC BOUNDARY ────────────────────┤
│  Tauri invoke() channel                         │
│  - Typed request/response                       │
│  - Error sanitization                           │
│  - Rate limiting                                │
├─────────────────────────────────────────────────┤
│  TRUSTED ZONE (Rust)                            │
│  - Owns ALL crypto operations                   │
│  - Owns database access                         │
│  - Owns session management                      │
│  - Owns key lifecycle                           │
└─────────────────────────────────────────────────┘
```

## Data Flow Rules

### NEVER Send to Frontend

| Data Type | Reason |
|-----------|--------|
| Master password | Zeroized after key derivation |
| Derived keys | Never leave Rust memory |
| Encryption nonces | Internal detail |
| Database salt | Internal detail |
| SQL error messages | Leak internal structure |
| File paths | Leak filesystem layout |
| Stack traces | Leak implementation |
| Crypto internal errors | Leak algorithm details |

### ALLOWED to Send to Frontend

| Data Type | Conditions |
|-----------|-----------|
| Entry metadata (title, username, URL) | Always — these are plaintext-indexed |
| Session token | No secrets — just state reference |
| Password strength scores | No password included |
| Audit event metadata | Category, action, timestamp |
| Validation error messages | User input errors only |
| UI state | Theme, settings, language |
| Folder structure | IDs and names (encrypted names decrypted) |

### CONDITIONAL (Explicit User Action Only)

| Data Type | Conditions |
|-----------|-----------|
| Decrypted password | Only via `vault_reveal_password` — auto-clear after 30s |
| Decrypted note content | Only when viewing a note — never cached |
| Export data | Rate-limited, audit-logged |

## Input Validation Rules

| Input Type | Validation |
|------------|-----------|
| Strings | Max length, no null bytes, UTF-8 validated |
| UUIDs | Format validation via `uuid::Uuid::parse_str` |
| Numbers | Range check (e.g., limit 1-200, offset ≥ 0) |
| Enums | Validated against known values |
| Passwords | Min 8 chars, max 1024 chars |
| All payloads | Max 1MB total |

## Rate Limiting

| Command Category | Limit | Window |
|------------------|-------|--------|
| Auth (unlock) | 5 attempts | Per minute |
| Data (CRUD) | 60 requests | Per minute |
| Scanner | 10 requests | Per minute |
| Export | 3 requests | Per minute |
| Settings | 20 requests | Per minute |

## Progressive Lockout

| Failed Attempts | Result |
|----------------|--------|
| 1-3 | Immediate retry allowed |
| 4 | 2 second delay |
| 5 | 4 second delay |
| 6+ | Full lockout — requires vault reset |

## Audit Requirements

### Always Log

- All auth events (success AND failure)
- All data modifications (create, update, delete)
- Password reveals
- Export operations
- Settings changes
- Lock/unlock events

### NEVER Log

- Master passwords
- Derived keys
- Decrypted field values
- Encryption nonces or salts

## Error Sanitization

| KestrelError Variant | Frontend Message |
|---------------------|-----------------|
| Crypto(_) | "A cryptographic operation failed" |
| Database(_) | "A database operation failed" |
| Vault(_) | "A vault operation failed" |
| Audit(_) | "An audit operation failed" |
| Scanner(_) | "A scan operation failed" |
| Config(_) | "A configuration error occurred" |
| Serialization(_) | "A data processing error occurred" |
| Validation(msg) | msg (user input — safe to expose) |
| Io(_) | "An I/O operation failed" |
| Unauthorized(msg) | msg (auth context — safe to expose) |
| Internal(_) | "An internal error occurred" |

## Frontend Architecture Rules

1. **All Tauri calls through `lib/tauri.ts`** — no direct `invoke()` in components
2. **No `localStorage`/`sessionStorage` for secrets** — enforced by architecture
3. **Auto-clear clipboard** after 30 seconds
4. **Auto-lock** after configured timeout
5. **Auth store holds session ref only** — never master password or keys
6. **VaultEntry type has no password field** — passwords only via explicit reveal
7. **All mutations go through Tauri commands** — no direct database access from frontend

## Command Inventory

### Auth Commands (6)
- `auth_initialize_vault` — First-time setup
- `auth_unlock` — Unlock with master password
- `auth_lock` — Lock vault immediately
- `auth_get_session` — Get current session state
- `auth_is_vault_initialized` — Check if vault exists
- `auth_change_password` — Change master password

### Vault Commands (7)
- `vault_create_entry` — Create new entry (password encrypted in Rust)
- `vault_get_entry` — Get entry metadata (NO password)
- `vault_update_entry` — Update entry fields
- `vault_delete_entry` — Delete entry (requires confirmation)
- `vault_list_entries` — List with pagination/filtering
- `vault_search_entries` — Search by title/username
- `vault_reveal_password` — Explicit password reveal (audit-logged)

### Audit Commands (2)
- `audit_query_events` — Query with filters/pagination
- `audit_export_events` — Export to JSON/CSV

### Scanner Commands (3)
- `scanner_password_strength` — Local strength analysis
- `scanner_check_breach` — Local breach database check
- `scanner_run_full_scan` — Comprehensive vulnerability scan

### Crypto Commands (3) — RESTRICTED
- `crypto_derive_key` — Blocked (use auth_unlock instead)
- `crypto_encrypt_data` — Blocked (use domain commands)
- `crypto_decrypt_data` — Blocked (use domain commands)

### Settings Commands (2)
- `settings_get` — Get current settings
- `settings_update` — Update settings
