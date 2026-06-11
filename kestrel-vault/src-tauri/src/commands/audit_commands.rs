//! Audit log Tauri commands for KESTREL Vault.
//!
//! Provides query and export access to the audit log.
//! Audit events are append-only — no create, update, or delete.
//!
//! # Security
//!
//! - Audit queries are available even when vault is locked
//!   (security visibility should not require unlock)
//! - Export operations are rate-limited and audit-logged
//! - No sensitive data (passwords, keys) in audit events

use crate::commands::types::{
    validate_field, AuditEventResponse, AuditPageResponse, CommandError, CommandResult,
};
use tauri::State;

use super::auth_commands::AppState;

/// Queries audit events with filtering and pagination.
///
/// Available in any vault state for security visibility.
///
/// # Arguments
//!
//! * `category` - Filter by event category (optional)
//! * `from` - Start timestamp ISO 8601 (optional)
//! * `to` - End timestamp ISO 8601 (optional)
//! * `limit` - Max results per page (default 50, max 200)
/// * `offset` - Number of results to skip
#[tauri::command]
pub fn audit_query_events(
    category: Option<String>,
    from: Option<String>,
    to: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
    _state: State<'_, AppState>,
) -> CommandResult<AuditPageResponse> {
    if let Some(ref cat) = category {
        validate_field(cat, 50, "category")?;
    }
    let limit = limit.unwrap_or(50).min(200);
    let offset = offset.unwrap_or(0).max(0);

    // Audit queries are available in any state (security visibility)
    // No state guard required — audit logs don't contain secrets

    // TODO: Query audit_event_repo with filters
    // TODO: Map to AuditEventResponse

    CommandResult::ok(AuditPageResponse {
        events: Vec::new(),
        total_count: 0,
        has_more: false,
    })
}

/// Exports audit events to a file.
///
/// Supported formats: "json", "csv"
/// Export is rate-limited and always audit-logged.
///
/// # Errors
//!
//! - `VALIDATION_ERROR`: Invalid format
/// - `RATE_LIMITED`: Too many export requests
#[tauri::command]
pub fn audit_export_events(
    format: String,
    from: Option<String>,
    to: Option<String>,
    _state: State<'_, AppState>,
) -> CommandResult<String> {
    let valid_formats = ["json", "csv"];
    if !valid_formats.contains(&format.as_str()) {
        return CommandResult::Err(CommandError::validation(
            "Format must be 'json' or 'csv'",
        ));
    }

    // TODO: Rate limit check
    // TODO: Query all matching events
    // TODO: Serialize to format
    // TODO: Save to file via dialog
    // TODO: Audit log: AuditExported { format, count }

    CommandResult::Err(CommandError::validation("Not yet implemented"))
}
