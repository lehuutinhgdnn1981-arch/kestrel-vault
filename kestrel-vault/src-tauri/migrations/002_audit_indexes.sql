-- ============================================================================
-- KESTREL Vault - Audit Event Indexes Migration (002)
-- ============================================================================
--
-- This migration creates dedicated indexes for the audit_events table.
-- Although the initial schema migration (001) already included these indexes,
-- this migration exists as a standalone file to:
--
--   1. Serve as documentation for the index strategy on audit_events
--   2. Allow independent re-creation if indexes were dropped for maintenance
--   3. Provide a template for adding future audit-specific indexes
--
-- IMPORTANT: If running against a database that already has these indexes
-- from migration 001, the IF NOT EXISTS clauses ensure idempotency.
--
-- QUERY PATTERNS SUPPORTED:
--
--   P1: "Show me all auth events" → WHERE category = 'auth'
--       → idx_audit_events_category
--
--   P2: "Show me recent events" → ORDER BY timestamp DESC LIMIT N
--       → idx_audit_events_timestamp
--
--   P3: "Show me auth events from the last 7 days"
--       → WHERE category = 'auth' AND timestamp > ? ORDER BY timestamp DESC
--       → idx_audit_events_category_timestamp (composite covering index)
--
--   P4: "Show me all login events" → WHERE action = 'login'
--       → idx_audit_events_action
--
--   P5: "Show me all security violations" → WHERE category = 'security'
--       → idx_audit_events_category
--
--   P6: "Count events by category in a time range"
--       → WHERE timestamp BETWEEN ? AND ? GROUP BY category
--       → idx_audit_events_timestamp (partial support)
--
-- INDEX DESIGN NOTES:
--
--   The composite index (category, timestamp) is the most important index
--   for the security center UI, which primarily displays filtered event
--   timelines. The individual indexes on category and timestamp support
--   queries that don't match the composite leading pattern.
--
--   SQLite's query planner uses the "multi-column index" rule: a composite
--   index (A, B) can serve queries on A alone, but NOT queries on B alone.
--   Therefore, idx_audit_events_category is technically redundant with the
--   composite index's leading column. However, we keep it because:
--     - It covers queries that need only category filtering without timestamp
--     - It may be chosen by the planner for COUNT(DISTINCT) on category
--     - The storage overhead is minimal for text-based category values
--
--   The timestamp index is NOT redundant because the composite index cannot
--   serve timestamp-only queries efficiently.
--
-- FUTURE INDEX CONSIDERATIONS:
--
--   - idx_audit_events_subject: If per-user/per-session filtering becomes
--     important, add an index on subject.
--   - idx_audit_events_category_action: If queries like "all login events
--     in the auth category" become common, a (category, action) composite
--     index would be more selective than either individual index.
--   - Partial indexes: If the audit_events table grows very large, consider
--     partial indexes like WHERE category = 'security' to reduce index size.
--
-- ============================================================================

-- Index for filtering audit events by category.
-- Supports P1: "Show me all auth events"
-- Supports P5: "Show me all security violations"
-- Note: Partially redundant with idx_audit_events_category_timestamp leading
-- column, but kept for query planner flexibility and COUNT optimizations.
CREATE INDEX IF NOT EXISTS idx_audit_events_category
    ON audit_events(category);

-- Index for time-range queries and chronological sorting.
-- Supports P2: "Show me recent events"
-- Supports P6: "Count events by category in a time range"
-- This index is NOT redundant — the composite index cannot serve
-- timestamp-only queries.
CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp
    ON audit_events(timestamp);

-- Composite index for the most common query pattern: filtering by
-- category within a time range.
-- Supports P3: "Show me auth events from the last 7 days"
-- This is the primary index for the security center event timeline.
-- The column order (category, timestamp) is intentional: category has
-- low cardinality (5 values), so it provides good selectivity when
-- combined with timestamp for range scans.
CREATE INDEX IF NOT EXISTS idx_audit_events_category_timestamp
    ON audit_events(category, timestamp);

-- Index for filtering by action type.
-- Supports P4: "Show me all login events"
-- Useful for generating reports on specific action types across
-- all categories (e.g., all create/delete actions regardless of category).
CREATE INDEX IF NOT EXISTS idx_audit_events_action
    ON audit_events(action);

-- Record this migration
INSERT INTO migration_history (version) VALUES (2);
