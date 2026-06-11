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
pub async fn transaction<F, T, E>(pool: &SqlitePool, f: F) -> Result<T, KestrelError>
where
    F: for<'a> FnOnce(&'a mut sqlx::Transaction<'_, sqlx::Sqlite>) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, E>> + 'a>>,
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
}
