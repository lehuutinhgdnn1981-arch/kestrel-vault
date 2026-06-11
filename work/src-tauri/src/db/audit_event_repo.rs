//! Audit event repository for database operations.
//!
//! Audit events are append-only — no update or delete operations.
//! This ensures the audit trail cannot be tampered with.
//!
//! # Query Capabilities
//!
//! - Filter by category, action, or time range
//! - Paginated results
//! - Aggregate counts by category

use crate::error::{KestrelError, KestrelResult};
use sqlx::SqlitePool;
use uuid::Uuid;

/// An audit event record from the database.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditEventRow {
    pub id: String,
    pub category: String,
    pub action: String,
    pub subject: String,
    pub metadata_json: Option<String>,
    pub timestamp: String,
}

/// Request to create a new audit event.
#[derive(Debug, Clone)]
pub struct CreateAuditEventRequest {
    pub category: String,
    pub action: String,
    pub subject: String,
    pub metadata_json: Option<String>,
}

/// Audit event repository — append-only.
pub struct AuditEventRepo;

impl AuditEventRepo {
    /// Records a new audit event.
    ///
    /// Audit events are immutable — once written, they cannot be
    /// modified or deleted.
    pub async fn create(
        pool: &SqlitePool,
        request: CreateAuditEventRequest,
    ) -> KestrelResult<AuditEventRow> {
        let id = Uuid::new_v4().to_string();
        let timestamp = chrono::Utc::now().to_rfc3339();

        sqlx::query(
            "INSERT INTO audit_events (id, category, action, subject, metadata_json, timestamp) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
        )
        .bind(&id)
        .bind(&request.category)
        .bind(&request.action)
        .bind(&request.subject)
        .bind(&request.metadata_json)
        .bind(&timestamp)
        .execute(pool)
        .await
        .map_err(|e| KestrelError::Audit(format!("Failed to record event: {e}")))?;

        Ok(AuditEventRow {
            id,
            category: request.category,
            action: request.action,
            subject: request.subject,
            metadata_json: request.metadata_json,
            timestamp,
        })
    }

    /// Lists audit events with pagination.
    pub async fn list(
        pool: &SqlitePool,
        limit: i64,
        offset: i64,
    ) -> KestrelResult<Vec<AuditEventRow>> {
        let rows = sqlx::query_as::<_, AuditEventRow>(
            "SELECT id, category, action, subject, metadata_json, timestamp \
             FROM audit_events ORDER BY timestamp DESC LIMIT ?1 OFFSET ?2"
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
        .map_err(|e| KestrelError::Audit(format!("Failed to list events: {e}")))?;

        Ok(rows)
    }

    /// Queries events by category.
    pub async fn query_by_category(
        pool: &SqlitePool,
        category: &str,
        limit: i64,
        offset: i64,
    ) -> KestrelResult<Vec<AuditEventRow>> {
        let rows = sqlx::query_as::<_, AuditEventRow>(
            "SELECT id, category, action, subject, metadata_json, timestamp \
             FROM audit_events WHERE category = ?1 \
             ORDER BY timestamp DESC LIMIT ?2 OFFSET ?3"
        )
        .bind(category)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
        .map_err(|e| KestrelError::Audit(format!("Failed to query by category: {e}")))?;

        Ok(rows)
    }

    /// Queries events by time range.
    pub async fn query_by_time_range(
        pool: &SqlitePool,
        from: &str,
        to: &str,
        limit: i64,
        offset: i64,
    ) -> KestrelResult<Vec<AuditEventRow>> {
        let rows = sqlx::query_as::<_, AuditEventRow>(
            "SELECT id, category, action, subject, metadata_json, timestamp \
             FROM audit_events WHERE timestamp >= ?1 AND timestamp <= ?2 \
             ORDER BY timestamp DESC LIMIT ?3 OFFSET ?4"
        )
        .bind(from)
        .bind(to)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
        .map_err(|e| KestrelError::Audit(format!("Failed to query by time: {e}")))?;

        Ok(rows)
    }

    /// Returns aggregate counts by category.
    pub async fn count_by_category(
        pool: &SqlitePool,
    ) -> KestrelResult<Vec<(String, i64)>> {
        let rows = sqlx::query_as::<_, (String, i64)>(
            "SELECT category, COUNT(*) as count \
             FROM audit_events GROUP BY category ORDER BY count DESC"
        )
        .fetch_all(pool)
        .await
        .map_err(|e| KestrelError::Audit(format!("Failed to count by category: {e}")))?;

        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_request_builds() {
        let req = CreateAuditEventRequest {
            category: "Auth".to_string(),
            action: "UnlockSucceeded".to_string(),
            subject: "user".to_string(),
            metadata_json: None,
        };
        assert_eq!(req.category, "Auth");
        assert_eq!(req.action, "UnlockSucceeded");
    }

    #[test]
    fn audit_event_row_serializes() {
        let row = AuditEventRow {
            id: "test-id".to_string(),
            category: "Auth".to_string(),
            action: "UnlockSucceeded".to_string(),
            subject: "user".to_string(),
            metadata_json: None,
            timestamp: "2025-01-01T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&row).unwrap();
        assert!(json.contains("Auth"));
    }
}
