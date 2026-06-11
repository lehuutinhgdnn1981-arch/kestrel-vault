//! Tauri IPC command module for KESTREL Vault.
//!
//! This module contains all Tauri command handlers that serve as the
//! bridge between the React frontend and the Rust backend.
//!
//! # IPC Security Model
//!
//! Tauri commands are exposed to the frontend via the `invoke` API.
//! Security is enforced at multiple layers:
//!
//! 1. **Input Validation**: All command parameters are validated before use
//! 2. **Authorization**: Commands check session validity before operations
//! 3. **Error Sanitization**: Error messages never leak sensitive data
//! 4. **Rate Limiting**: Commands are rate-limited to prevent abuse
//! 5. **Audit Logging**: All security-relevant commands are logged
//!
//! # Command Design
//!
//! Commands are thin wrappers — all business logic resides in the
//! corresponding service modules. Commands handle:
//! - Parameter deserialization and validation
//! - Error conversion to frontend-safe strings
//! - Audit event creation

pub mod audit_commands;
pub mod crypto_commands;
pub mod scanner_commands;
pub mod vault_commands;
