//! Audit log querying for KESTREL Vault.
//!
//! Provides query types and result structures for searching
//! and filtering audit events. Supports time-range queries,
//! category filtering, and pagination.
//!
//! # Privacy
//!
//! Query results contain only non-sensitive metadata.
//! Passwords and decrypted data are never included in
//! audit query results.

use crate::audit::event::{AuditEvent, EventCategory};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Query parameters for searching audit events.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditQuery {
    /// Start of the time range (inclusive).
    pub start_time: Option<DateTime<Utc>>,
    /// End of the time range (inclusive).
    pub end_time: Option<DateTime<Utc>>,
    /// Filter by event category.
    pub category: Option<EventCategory>,
    /// Filter by subject (partial match).
    pub subject: Option<String>,
    /// Maximum number of results to return.
    pub limit: i64,
    /// Number of results to skip (for pagination).
    pub offset: i64,
}

impl Default for AuditQuery {
    fn default() -> Self {
        AuditQuery {
            start_time: None,
            end_time: None,
            category: None,
            subject: None,
            limit: 100,
            offset: 0,
        }
    }
}

impl AuditQuery {
    /// Creates a new query with default pagination.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the time range for the query.
    pub fn with_time_range(mut self, start: DateTime<Utc>, end: DateTime<Utc>) -> Self {
        self.start_time = Some(start);
        self.end_time = Some(end);
        self
    }

    /// Filters by event category.
    pub fn with_category(mut self, category: EventCategory) -> Self {
        self.category = Some(category);
        self
    }

    /// Filters by subject (partial match).
    pub fn with_subject(mut self, subject: String) -> Self {
        self.subject = Some(subject);
        self
    }

    /// Sets pagination parameters.
    pub fn with_pagination(mut self, limit: i64, offset: i64) -> Self {
        self.limit = limit;
        self.offset = offset;
        self
    }

    /// Validates the query parameters.
    pub fn validate(&self) -> Result<(), crate::error::KestrelError> {
        if self.limit < 0 {
            return Err(crate::error::KestrelError::Validation(
                "Limit must be non-negative".to_string(),
            ));
        }
        if self.offset < 0 {
            return Err(crate::error::KestrelError::Validation(
                "Offset must be non-negative".to_string(),
            ));
        }
        if self.limit > 10000 {
            return Err(crate::error::KestrelError::Validation(
                "Limit too large (max 10000)".to_string(),
            ));
        }
        if let (Some(start), Some(end)) = (self.start_time, self.end_time) {
            if start > end {
                return Err(crate::error::KestrelError::Validation(
                    "Start time must be before end time".to_string(),
                ));
            }
        }
        Ok(())
    }
}

/// Result of an audit query.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditQueryResult {
    /// The matching audit events.
    pub events: Vec<AuditEvent>,
    /// Total number of matching events (for pagination).
    pub total_count: i64,
    /// Whether there are more results beyond this page.
    pub has_more: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_query() {
        let query = AuditQuery::default();
        assert!(query.start_time.is_none());
        assert!(query.end_time.is_none());
        assert!(query.category.is_none());
        assert_eq!(query.limit, 100);
        assert_eq!(query.offset, 0);
    }

    #[test]
    fn query_builder() {
        let start = Utc::now() - chrono::Duration::hours(24);
        let end = Utc::now();
        let query = AuditQuery::new()
            .with_time_range(start, end)
            .with_category(EventCategory::Auth)
            .with_subject("user-123".to_string())
            .with_pagination(50, 0);
        assert!(query.start_time.is_some());
        assert_eq!(query.category, Some(EventCategory::Auth));
        assert_eq!(query.limit, 50);
    }

    #[test]
    fn query_validates_limit() {
        let query = AuditQuery {
            limit: -1,
            ..Default::default()
        };
        assert!(query.validate().is_err());
    }

    #[test]
    fn query_validates_max_limit() {
        let query = AuditQuery {
            limit: 20000,
            ..Default::default()
        };
        assert!(query.validate().is_err());
    }
}
