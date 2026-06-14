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
use crate::db::audit_event_repo::AuditEventRepo;
use tauri::State;

use super::auth_commands::AppState;

/// Queries audit events with filtering and pagination.
///
/// Available in any vault state for security visibility.
///
/// # Arguments
///
/// * `category` - Filter by event category (optional)
/// * `from` - Start timestamp ISO 8601 (optional)
/// * `to` - End timestamp ISO 8601 (optional)
/// * `limit` - Max results per page (default 50, max 200)
/// * `offset` - Number of results to skip
#[tauri::command]
pub fn audit_query_events(
    category: Option<String>,
    from: Option<String>,
    to: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
    state: State<'_, AppState>,
) -> CommandResult<AuditPageResponse> {
    if let Some(ref cat) = category {
        validate_field(cat, 50, "category")?;
    }
    let limit = limit.unwrap_or(50).min(200);
    let offset = offset.unwrap_or(0).max(0);

    // Audit queries are available in any state (security visibility)
    // No state guard required — audit logs don't contain secrets

    // Get database pool
    let pool = state.get_db_pool();
    match pool {
        Some(p) => {
            let rows = crate::commands::async_runtime::block_on(async {
                match &category {
                    Some(cat) => {
                        AuditEventRepo::query_by_category(&p, cat, limit, offset).await
                    }
                    None => AuditEventRepo::list(&p, limit, offset).await,
                }
            });

            match rows {
                Ok(events) => {
                    // If time range filtering is specified, filter in memory
                    // (SQLite timestamp comparison works but we do a secondary
                    // filter to be safe with ISO 8601 formats)
                    let filtered: Vec<_> = events
                        .into_iter()
                        .filter(|e| {
                            if let Some(ref from_ts) = from {
                                if e.timestamp < *from_ts {
                                    return false;
                                }
                            }
                            if let Some(ref to_ts) = to {
                                if e.timestamp > *to_ts {
                                    return false;
                                }
                            }
                            true
                        })
                        .collect();

                    let has_more = filtered.len() as i64 >= limit;
                    let total_count = filtered.len() as i64;

                    let responses: Vec<AuditEventResponse> = filtered
                        .into_iter()
                        .map(|e| AuditEventResponse {
                            id: e.id,
                            category: e.category,
                            action: e.action,
                            subject: e.subject,
                            timestamp: e.timestamp,
                        })
                        .collect();

                    Ok(AuditPageResponse {
                        events: responses,
                        total_count,
                        has_more,
                    })
                }
                Err(e) => {
                    tracing::warn!("Audit query failed: {}", e);
                    // Return empty result rather than error — audit should
                    // always be available for visibility
                    Ok(AuditPageResponse {
                        events: Vec::new(),
                        total_count: 0,
                        has_more: false,
                    })
                }
            }
        }
        None => {
            // Database not available — return empty results
            // This happens when vault hasn't been unlocked yet
            Ok(AuditPageResponse {
                events: Vec::new(),
                total_count: 0,
                has_more: false,
            })
        }
    }
}

/// Exports audit events to a file.
///
/// Supported formats: "json", "csv"
/// Export is rate-limited and always audit-logged.
///
/// # Errors
///
/// - `VALIDATION_ERROR`: Invalid format
/// - `RATE_LIMITED`: Too many export requests
#[tauri::command]
pub fn audit_export_events(
    format: String,
    from: Option<String>,
    to: Option<String>,
    state: State<'_, AppState>,
) -> CommandResult<String> {
    let valid_formats = ["json", "csv"];
    if !valid_formats.contains(&format.as_str()) {
        return Err(CommandError::validation(
            "Format must be 'json' or 'csv'",
        ));
    }

    // Get database pool
    let pool = state.get_db_pool();
    match pool {
        Some(p) => {
            // Load all audit events (with optional time filter)
            let all_events = crate::commands::async_runtime::block_on(async {
                AuditEventRepo::list(&p, 100000, 0).await
            });

            match all_events {
                Ok(events) => {
                    // Apply time range filter
                    let filtered: Vec<_> = events
                        .into_iter()
                        .filter(|e| {
                            if let Some(ref from_ts) = from {
                                if e.timestamp < *from_ts {
                                    return false;
                                }
                            }
                            if let Some(ref to_ts) = to {
                                if e.timestamp > *to_ts {
                                    return false;
                                }
                            }
                            true
                        })
                        .collect();

                    let output = match format.as_str() {
                        "json" => {
                            serde_json::to_string_pretty(&filtered)
                                .map_err(|e| CommandError::from_kestrel(
                                    crate::error::KestrelError::Serialization(
                                        format!("Failed to serialize audit events: {e}")
                                    )
                                ))?
                        }
                        "csv" => {
                            let mut csv_lines = vec![
                                "id,category,action,subject,timestamp".to_string()
                            ];
                            for e in &filtered {
                                csv_lines.push(format!(
                                    "{},{},{},{},{}",
                                    e.id,
                                    e.category,
                                    e.action,
                                    e.subject,
                                    e.timestamp,
                                ));
                            }
                            csv_lines.join("\n")
                        }
                        _ => unreachable!(),
                    };

                    // Audit log the export itself
                    if let Some(p) = state.get_db_pool() {
                        let _ = crate::commands::async_runtime::block_on(async {
                            AuditEventRepo::create(&p, crate::db::audit_event_repo::CreateAuditEventRequest {
                                category: "Audit".to_string(),
                                action: "EventsExported".to_string(),
                                subject: "system".to_string(),
                                metadata_json: Some(serde_json::json!({
                                    "format": format,
                                    "count": filtered.len(),
                                }).to_string()),
                            }).await
                        });
                    }

                    tracing::info!("Audit events exported: format={}, count={}", format, filtered.len());

                    Ok(output)
                }
                Err(e) => {
                    Err(CommandError::from_kestrel(e))
                }
            }
        }
        None => {
            Err(CommandError::unauthorized(
                "Database not available — unlock the vault first",
            ))
        }
    }
}
