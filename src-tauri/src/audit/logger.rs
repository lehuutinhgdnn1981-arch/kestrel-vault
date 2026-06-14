//! Audit logger implementation for KESTREL Vault.
//!
//! Provides structured audit logging with precise timestamps,
//! event categorization, and tamper-evidence design.
//!
//! # Tamper Evidence
//!
//! The audit log is designed to detect tampering through:
//! - Sequential event numbering
//! - Hash chaining between consecutive events
//! - Cryptographic signatures on event batches
//!
//! # Implementation
//!
//! The `AuditLog` struct wraps `AuditEventRepo` for database persistence.
//! All events are written to the `audit_events` table with millisecond-precision
//! timestamps. Events are append-only — no update or delete is supported.
//!
//! # TODO (Phase 2)
//!
//! - Implement hash chaining for tamper evidence
//! - Add cryptographic signatures
//! - Add log rotation and archival

use crate::audit::event::{ActionType, AuditEvent, EventCategory};
use crate::audit::query::{AuditQuery, AuditQueryResult};
use crate::db::audit_event_repo::{AuditEventRepo, CreateAuditEventRequest};
use crate::error::KestrelError;
use sqlx::SqlitePool;

/// The primary audit logger for KESTREL Vault.
///
/// All security-relevant operations should be logged through
/// this struct. Events are persisted to the database with
/// millisecond-precision timestamps.
pub struct AuditLog {
    /// Database connection pool for event persistence.
    pool: Option<SqlitePool>,
}

impl AuditLog {
    /// Creates a new audit logger without a database pool.
    ///
    /// Events logged to this instance will be traced but not persisted.
    /// Use `with_pool()` to create a logger with database persistence.
    pub fn new() -> Self {
        AuditLog { pool: None }
    }

    /// Creates a new audit logger with database persistence.
    ///
    /// All events logged through this instance will be persisted
    /// to the `audit_events` table.
    pub fn with_pool(pool: SqlitePool) -> Self {
        AuditLog { pool: Some(pool) }
    }

    /// Logs an audit event to the persistent store.
    ///
    /// If no database pool is available, the event is logged via
    /// tracing only (fail-open). Logging failures should not block
    /// the primary operation.
    ///
    /// # Errors
    ///
    /// Returns `KestrelError::Audit` if the event cannot be persisted.
    pub async fn log(&self, event: AuditEvent) -> Result<(), KestrelError> {
        tracing::info!(
            category = %event.category,
            action = %event.action,
            subject = %event.subject,
            "Audit event logged"
        );

        if let Some(ref pool) = self.pool {
            let request = CreateAuditEventRequest {
                category: event.category.to_string(),
                action: event.action.to_string(),
                subject: event.subject,
                metadata_json: None,
            };
            AuditEventRepo::create(pool, request).await?;
        }

        Ok(())
    }

    /// Queries audit events matching the given criteria.
    ///
    /// # Errors
    ///
    /// Returns `KestrelError::Audit` if the query fails.
    pub async fn query(
        &self,
        query: AuditQuery,
    ) -> Result<AuditQueryResult, KestrelError> {
        if let Some(ref pool) = self.pool {
            let limit = query.limit.min(200);
            let offset = query.offset;

            let rows = match query.category {
                Some(ref cat) => AuditEventRepo::query_by_category(pool, &cat.to_string(), limit, offset).await?,
                None => AuditEventRepo::list(pool, limit, offset).await?,
            };

            let events: Vec<AuditEvent> = rows.into_iter().map(|row| {
                let category = match row.category.as_str() {
                    "Auth" | "auth" => EventCategory::Auth,
                    "Vault" | "vault" => EventCategory::Vault,
                    "File" | "file" => EventCategory::File,
                    "Security" | "security" => EventCategory::Security,
                    _ => EventCategory::System,
                };
                let action = match row.action.as_str() {
                    "create" | "Create" | "EntryCreated" | "NoteCreated" | "FolderCreated" => ActionType::Create,
                    "read" | "Read" => ActionType::Read,
                    "update" | "Update" | "EntryUpdated" => ActionType::Update,
                    "delete" | "Delete" | "EntryDeleted" => ActionType::Delete,
                    "login" | "Login" | "UnlockSucceeded" => ActionType::Login,
                    "logout" | "Logout" => ActionType::Logout,
                    "lock" | "Lock" | "VaultLocked" => ActionType::Lock,
                    "unlock" | "Unlock" => ActionType::Unlock,
                    "import" | "Import" => ActionType::Import,
                    "export" | "Export" | "EventsExported" => ActionType::Export,
                    "violation" | "Violation" | "UnlockFailed" => ActionType::Violation,
                    _ => ActionType::ConfigChange,
                };
                AuditEvent::new(category, action, row.subject)
            }).collect();

            let total_count = events.len() as i64;
            let has_more = total_count >= limit;

            Ok(AuditQueryResult {
                events,
                total_count,
                has_more,
            })
        } else {
            Ok(AuditQueryResult {
                events: Vec::new(),
                total_count: 0,
                has_more: false,
            })
        }
    }

    /// Exports audit events for a given time range.
    ///
    /// Used for compliance and forensic analysis.
    ///
    /// # Errors
    ///
    /// Returns `KestrelError::Audit` if the export fails.
    pub async fn export(
        &self,
        _start: chrono::DateTime<chrono::Utc>,
        _end: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<AuditEvent>, KestrelError> {
        if let Some(ref pool) = self.pool {
            let rows = AuditEventRepo::list(pool, 100000, 0).await?;
            let events: Vec<AuditEvent> = rows.into_iter().map(|row| {
                let category = match row.category.as_str() {
                    "Auth" | "auth" => EventCategory::Auth,
                    "Vault" | "vault" => EventCategory::Vault,
                    "File" | "file" => EventCategory::File,
                    "Security" | "security" => EventCategory::Security,
                    _ => EventCategory::System,
                };
                let action = match row.action.as_str() {
                    "create" | "Create" => ActionType::Create,
                    "read" | "Read" => ActionType::Read,
                    "update" | "Update" => ActionType::Update,
                    "delete" | "Delete" => ActionType::Delete,
                    "login" | "Login" => ActionType::Login,
                    "logout" | "Logout" => ActionType::Logout,
                    "lock" | "Lock" => ActionType::Lock,
                    "unlock" | "Unlock" => ActionType::Unlock,
                    "import" | "Import" => ActionType::Import,
                    "export" | "Export" => ActionType::Export,
                    "violation" | "Violation" => ActionType::Violation,
                    _ => ActionType::ConfigChange,
                };
                AuditEvent::new(category, action, row.subject)
            }).collect();
            Ok(events)
        } else {
            Ok(Vec::new())
        }
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::audit::AuditLogger for AuditLog {
    async fn log_event(&self, event: AuditEvent) -> Result<(), KestrelError> {
        self.log(event).await
    }

    async fn query_events(
        &self,
        query: AuditQuery,
    ) -> Result<AuditQueryResult, KestrelError> {
        self.query(query).await
    }

    async fn export_events(
        &self,
        start: chrono::DateTime<chrono::Utc>,
        end: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<AuditEvent>, KestrelError> {
        self.export(start, end).await
    }
}

/// Helper function to create and log an audit event in one step.
///
/// # Arguments
///
/// * `logger` - The audit logger
/// * `category` - Event category
/// * `action` - Action type
/// * `subject` - Who/what performed the action
///
/// # Errors
///
/// Returns an error if logging fails. The caller should log the
/// error but not fail the primary operation.
pub async fn log_audit(
    logger: &AuditLog,
    category: EventCategory,
    action: ActionType,
    subject: &str,
) -> Result<(), KestrelError> {
    let event = AuditEvent::new(category, action, subject.to_string());
    logger.log(event).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn log_audit_event_no_pool() {
        let logger = AuditLog::new();
        let event = AuditEvent::new(
            EventCategory::Auth,
            ActionType::Login,
            "test-session".to_string(),
        );
        let result = logger.log(event).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn log_audit_helper() {
        let logger = AuditLog::new();
        let result = log_audit(
            &logger,
            EventCategory::Vault,
            ActionType::Create,
            "test-session",
        )
        .await;
        assert!(result.is_ok());
    }

    #[test]
    fn audit_log_default() {
        let _logger = AuditLog::default();
    }

    #[tokio::test]
    async fn query_no_pool_returns_empty() {
        let logger = AuditLog::new();
        let query = AuditQuery {
            category: None,
            subject: None,
            start_time: None,
            end_time: None,
            limit: 10,
            offset: 0,
        };
        let result = logger.query(query).await.unwrap();
        assert_eq!(result.events.len(), 0);
        assert_eq!(result.total_count, 0);
    }
}
