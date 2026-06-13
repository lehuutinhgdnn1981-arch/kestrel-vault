//! Repository pattern for database operations.
//!
//! Provides a generic trait for CRUD operations on database entities,
//! ensuring consistent error handling and transaction support across
//! all data access layers.
//!
//! # Design
//!
//! - Generic over entity types to reduce boilerplate
//! - Transaction support for atomic multi-step operations
//! - All operations return `Result` with proper error types
//! - No raw SQL exposed outside of repository implementations
//!
//! # Transaction Patterns
//!
//! Two approaches are supported:
//!
//! 1. **Closure-based** (`transaction()`): Simple, ergonomic, but
//!    cannot span multiple repository calls easily due to lifetime
//!    constraints.
//!
//! 2. **Manual** (`begin_tx()`, commit/rollback): Full control for
//!    complex multi-step operations that span multiple repos.

use crate::error::KestrelError;
use sqlx::SqlitePool;
use uuid::Uuid;

/// Generic repository trait for CRUD operations.
///
/// All database entities in KESTREL Vault implement this trait
/// to provide a consistent interface for data access.
///
/// # Type Parameters
///
/// - `T`: The entity type
/// - `C`: The creation request type
/// - `U`: The update request type
#[allow(async_fn_in_trait)]
pub trait Repository<T, C, U> {
    /// Creates a new entity in the database.
    ///
    /// # Errors
    ///
    /// Returns `KestrelError::Database` if the insert fails,
    /// e.g., due to a unique constraint violation.
    async fn create(pool: &SqlitePool, request: C) -> Result<T, KestrelError>;

    /// Retrieves an entity by its unique identifier.
    ///
    /// # Errors
    ///
    /// Returns `KestrelError::Database` if the query fails.
    /// Returns `KestrelError::Vault` if the entity is not found.
    async fn get_by_id(pool: &SqlitePool, id: Uuid) -> Result<T, KestrelError>;

    /// Updates an existing entity.
    ///
    /// # Errors
    ///
    /// Returns `KestrelError::Database` if the update fails.
    /// Returns `KestrelError::Vault` if the entity is not found.
    async fn update(pool: &SqlitePool, id: Uuid, request: U) -> Result<T, KestrelError>;

    /// Deletes an entity by its unique identifier.
    ///
    /// # Errors
    ///
    /// Returns `KestrelError::Database` if the delete fails.
    /// Returns `KestrelError::Vault` if the entity is not found.
    async fn delete(pool: &SqlitePool, id: Uuid) -> Result<(), KestrelError>;

    /// Lists all entities, with optional pagination.
    ///
    /// # Arguments
    ///
    /// * `pool` - Database connection pool
    /// * `limit` - Maximum number of results (None = no limit)
    /// * `offset` - Number of results to skip
    ///
    /// # Errors
    ///
    /// Returns `KestrelError::Database` if the query fails.
    async fn list(
        pool: &SqlitePool,
        limit: Option<i64>,
        offset: i64,
    ) -> Result<Vec<T>, KestrelError>;
}

/// Executes a function within a database transaction.
///
/// The transaction is automatically committed if the function
/// returns `Ok` and rolled back if it returns `Err`.
///
/// # Errors
///
/// Returns `KestrelError::Database` if the transaction cannot
/// be started or if the function returns an error.
///
/// # Example
///
/// ```ignore
/// transaction(&pool, |tx| {
///     Box::pin(async move {
///         sqlx::query("INSERT INTO ...").execute(&mut **tx).await?;
///         sqlx::query("UPDATE ...").execute(&mut **tx).await?;
///         Ok(())
///     })
/// }).await?;
/// ```
pub async fn transaction<F, T, E>(pool: &SqlitePool, f: F) -> Result<T, KestrelError>
where
    F: for<'a> FnOnce(
        &'a mut sqlx::Transaction<'_, sqlx::Sqlite>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<T, E>> + 'a>,
    >,
    E: Into<KestrelError>,
{
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| KestrelError::Database(format!("Failed to start transaction: {e}")))?;

    let result = f(&mut tx).await.map_err(Into::into)?;

    tx.commit()
        .await
        .map_err(|e| KestrelError::Database(format!("Failed to commit transaction: {e}")))?;

    Ok(result)
}

/// Begins a new database transaction.
///
/// Returns a `Transaction` that can be used for multi-step operations.
/// The transaction must be explicitly committed or it will be rolled
/// back when dropped.
///
/// # Errors
///
/// Returns `KestrelError::Database` if the transaction cannot be started.
pub async fn begin_tx(
    pool: &SqlitePool,
) -> Result<sqlx::Transaction<'_, sqlx::Sqlite>, KestrelError> {
    pool.begin()
        .await
        .map_err(|e| KestrelError::Database(format!("Failed to start transaction: {e}")))
}

/// Commits a transaction.
///
/// # Errors
///
/// Returns `KestrelError::Database` if the commit fails.
pub async fn commit_tx(
    tx: sqlx::Transaction<'_, sqlx::Sqlite>,
) -> Result<(), KestrelError> {
    tx.commit()
        .await
        .map_err(|e| KestrelError::Database(format!("Failed to commit transaction: {e}")))
}

/// Executes multiple operations in a single transaction with automatic
/// rollback on any failure.
///
/// This is a simplified version of `transaction()` that works with
/// a sequence of async operations. Each operation receives a mutable
/// reference to the transaction.
///
/// # Type Parameters
///
/// - `T`: The result type of the transaction
///
/// # Errors
///
/// Returns `KestrelError::Database` if the transaction fails.
pub async fn transaction_result<T>(
    pool: &SqlitePool,
    f: impl for<'a> FnOnce(
        &'a mut sqlx::Transaction<'_, sqlx::Sqlite>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<T, KestrelError>> + 'a>,
    >,
) -> Result<T, KestrelError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| KestrelError::Database(format!("Failed to start transaction: {e}")))?;

    let result = f(&mut tx).await;

    match result {
        Ok(value) => {
            tx.commit()
                .await
                .map_err(|e| KestrelError::Database(format!("Failed to commit transaction: {e}")))?;
            Ok(value)
        }
        Err(e) => {
            // Transaction will be rolled back on drop
            tracing::warn!("Transaction rolled back due to error: {e}");
            Err(e)
        }
    }
}

/// Pagination parameters for list queries.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Pagination {
    /// Maximum number of results to return.
    pub limit: i64,
    /// Number of results to skip.
    pub offset: i64,
}

impl Default for Pagination {
    fn default() -> Self {
        Pagination {
            limit: 50,
            offset: 0,
        }
    }
}

impl Pagination {
    /// Creates a new pagination with the given limit and offset.
    pub fn new(limit: i64, offset: i64) -> Self {
        Pagination { limit, offset }
    }

    /// Creates pagination for the first page.
    pub fn first_page(page_size: i64) -> Self {
        Pagination {
            limit: page_size,
            offset: 0,
        }
    }

    /// Creates pagination for a specific page number (0-indexed).
    pub fn page(page: i64, page_size: i64) -> Self {
        Pagination {
            limit: page_size,
            offset: page * page_size,
        }
    }

    /// Returns the next page's pagination.
    pub fn next(&self) -> Self {
        Pagination {
            limit: self.limit,
            offset: self.offset + self.limit,
        }
    }

    /// Returns the previous page's pagination, if possible.
    pub fn previous(&self) -> Option<Self> {
        if self.offset >= self.limit {
            Some(Pagination {
                limit: self.limit,
                offset: self.offset - self.limit,
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pagination_default() {
        let p = Pagination::default();
        assert_eq!(p.limit, 50);
        assert_eq!(p.offset, 0);
    }

    #[test]
    fn pagination_custom() {
        let p = Pagination::new(100, 200);
        assert_eq!(p.limit, 100);
        assert_eq!(p.offset, 200);
    }

    #[test]
    fn pagination_first_page() {
        let p = Pagination::first_page(25);
        assert_eq!(p.limit, 25);
        assert_eq!(p.offset, 0);
    }

    #[test]
    fn pagination_specific_page() {
        let p = Pagination::page(2, 20); // Page 2 (0-indexed), 20 per page
        assert_eq!(p.limit, 20);
        assert_eq!(p.offset, 40);
    }

    #[test]
    fn pagination_next() {
        let p = Pagination::page(0, 10);
        let next = p.next();
        assert_eq!(next.offset, 10);
        assert_eq!(next.limit, 10);
    }

    #[test]
    fn pagination_previous() {
        let p = Pagination::page(2, 10);
        let prev = p.previous().unwrap();
        assert_eq!(prev.offset, 10);
        assert_eq!(prev.limit, 10);
    }

    #[test]
    fn pagination_previous_first_page() {
        let p = Pagination::first_page(10);
        assert!(p.previous().is_none());
    }

    #[test]
    fn pagination_previous_second_page() {
        let p = Pagination::page(1, 10);
        let prev = p.previous().unwrap();
        assert_eq!(prev.offset, 0);
    }
}
