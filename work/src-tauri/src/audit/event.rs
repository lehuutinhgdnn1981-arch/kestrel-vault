//! Audit event type definitions for KESTREL Vault.
//!
//! Defines the structure and categories of audit events.
//! All security-relevant operations produce audit events
//! that are logged to the immutable audit trail.
//!
//! # Privacy
//!
//! Audit events NEVER contain:
//! - Passwords (plaintext or encrypted)
//! - Decrypted vault data
//! - Cryptographic keys
//! - Personal information beyond user identifiers

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Category of an audit event.
///
/// Events are categorized to allow filtering and analysis
/// by security domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventCategory {
    /// Authentication events (login, logout, lock, unlock).
    Auth,
    /// Vault entry operations (create, read, update, delete).
    Vault,
    /// File operations (import, export, backup).
    File,
    /// System operations (startup, shutdown, update).
    System,
    /// Security events (failed auth, rate limit, lockout).
    Security,
}

impl std::fmt::Display for EventCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventCategory::Auth => write!(f, "auth"),
            EventCategory::Vault => write!(f, "vault"),
            EventCategory::File => write!(f, "file"),
            EventCategory::System => write!(f, "system"),
            EventCategory::Security => write!(f, "security"),
        }
    }
}

/// Type of action performed in an audit event.
///
/// Provides fine-grained classification of the operation
/// that triggered the audit event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionType {
    /// A resource was created.
    Create,
    /// A resource was read/viewed.
    Read,
    /// A resource was updated/modified.
    Update,
    /// A resource was deleted.
    Delete,
    /// A user logged in.
    Login,
    /// A user logged out.
    Logout,
    /// The vault was locked.
    Lock,
    /// The vault was unlocked.
    Unlock,
    /// Data was imported.
    Import,
    /// Data was exported.
    Export,
    /// A security violation was detected.
    Violation,
    /// A configuration was changed.
    ConfigChange,
}

impl std::fmt::Display for ActionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ActionType::Create => write!(f, "create"),
            ActionType::Read => write!(f, "read"),
            ActionType::Update => write!(f, "update"),
            ActionType::Delete => write!(f, "delete"),
            ActionType::Login => write!(f, "login"),
            ActionType::Logout => write!(f, "logout"),
            ActionType::Lock => write!(f, "lock"),
            ActionType::Unlock => write!(f, "unlock"),
            ActionType::Import => write!(f, "import"),
            ActionType::Export => write!(f, "export"),
            ActionType::Violation => write!(f, "violation"),
            ActionType::ConfigChange => write!(f, "config_change"),
        }
    }
}

/// A single audit event record.
///
/// Represents a security-relevant action that was performed
/// in the system. Audit events are immutable — once created,
/// they cannot be modified or deleted.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unique identifier for this event.
    pub id: Uuid,
    /// Category of the event.
    pub category: EventCategory,
    /// Type of action performed.
    pub action: ActionType,
    /// Subject of the action (e.g., user ID, session ID).
    /// Never contains passwords or secrets.
    pub subject: String,
    /// Timestamp when the event occurred (UTC, millisecond precision).
    pub timestamp: DateTime<Utc>,
    /// Additional metadata about the event.
    /// Keys should be descriptive; values must not contain secrets.
    pub metadata: HashMap<String, String>,
}

impl AuditEvent {
    /// Creates a new audit event with the current timestamp.
    ///
    /// # Arguments
    ///
    /// * `category` - The event category
    /// * `action` - The action type
    /// * `subject` - Who/what performed the action
    ///
    /// # Security
    ///
    /// The `subject` field should contain only non-sensitive
    /// identifiers (e.g., session IDs, not passwords).
    pub fn new(
        category: EventCategory,
        action: ActionType,
        subject: String,
    ) -> Self {
        AuditEvent {
            id: Uuid::new_v4(),
            category,
            action,
            subject,
            timestamp: Utc::now(),
            metadata: HashMap::new(),
        }
    }

    /// Adds a metadata entry to this event.
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_audit_event() {
        let event = AuditEvent::new(
            EventCategory::Auth,
            ActionType::Login,
            "session-123".to_string(),
        );
        assert_eq!(event.category, EventCategory::Auth);
        assert_eq!(event.action, ActionType::Login);
        assert_eq!(event.subject, "session-123");
    }

    #[test]
    fn audit_event_with_metadata() {
        let event = AuditEvent::new(
            EventCategory::Vault,
            ActionType::Create,
            "user-session".to_string(),
        )
        .with_metadata("entry_id".to_string(), "abc-123".to_string());

        assert_eq!(event.metadata.get("entry_id"), Some(&"abc-123".to_string()));
    }

    #[test]
    fn event_category_display() {
        assert_eq!(EventCategory::Auth.to_string(), "auth");
        assert_eq!(EventCategory::Security.to_string(), "security");
    }

    #[test]
    fn action_type_display() {
        assert_eq!(ActionType::Login.to_string(), "login");
        assert_eq!(ActionType::ConfigChange.to_string(), "config_change");
    }
}
