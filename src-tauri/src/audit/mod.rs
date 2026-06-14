//! Audit logging module for KESTREL Vault.
//!
//! Provides comprehensive audit logging for all security-relevant
//! operations. Audit logs are immutable and tamper-evident,
//! providing a reliable record of all actions performed.
//!
//! # Design Goals
//!
//! - **Completeness**: All security-relevant actions are logged
//! - **Integrity**: Logs cannot be undetectably modified
//! - **Precision**: Timestamps have millisecond resolution
//! - **Privacy**: Logs never contain passwords or decrypted data
//!
//! # Submodules
//!
//! - `logger`: Audit logger implementation
//! - `event`: Event type definitions
//! - `query`: Audit log querying and filtering

pub mod event;
pub mod logger;
pub mod query;

use crate::audit::event::AuditEvent;
use crate::error::KestrelError;

/// Trait for audit logging implementations.
///
/// All audit loggers must implement this trait, allowing
/// different storage backends (SQLite, file, remote) to
/// be swapped in.
#[allow(async_fn_in_trait)]
pub trait AuditLogger {
    /// Logs an audit event.
    ///
    /// The event is persisted immediately. If logging fails,
    /// an error is returned but the original operation should
    /// still proceed (fail-open for logging).
    async fn log_event(&self, event: AuditEvent) -> Result<(), KestrelError>;

    /// Queries audit events matching the given criteria.
    async fn query_events(
        &self,
        query: query::AuditQuery,
    ) -> Result<query::AuditQueryResult, KestrelError>;

    /// Exports audit events for a given time range.
    async fn export_events(
        &self,
        start: chrono::DateTime<chrono::Utc>,
        end: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<AuditEvent>, KestrelError>;
}
