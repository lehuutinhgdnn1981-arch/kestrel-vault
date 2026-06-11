//! Vault metadata repository for database operations.
//!
//! Manages the singleton `vault_meta` row that stores KDF
//! parameters and the test envelope for vault verification.
//!
//! # Security
//!
//! - The salt is stored as hex (not binary) for SQLCipher compatibility
//! - The test envelope verifies the master password without
//!   storing it directly
//! - KDF parameters are stored for reproducible key derivation

use crate::error::{KestrelError, KestrelResult};
use sqlx::SqlitePool;

/// Vault metadata — singleton row in the database.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VaultMeta {
    /// Always 1 (singleton).
    pub id: i64,
    /// Hex-encoded salt for Argon2id.
    pub salt: String,
    /// Argon2id iterations (time cost).
    pub iterations: u32,
    /// Argon2id memory cost in KiB.
    pub memory_cost: u32,
    /// Argon2id parallelism.
    pub parallelism: u32,
    /// Encrypted test envelope for password verification.
    pub test_envelope: Vec<u8>,
    /// Optional password hint (stored in plaintext — NOT secure).
    pub hint: Option<String>,
    /// When the vault was created.
    pub created_at: String,
    /// When vault_meta was last updated.
    pub updated_at: String,
}

/// Vault metadata repository.
pub struct VaultMetaRepo;

impl VaultMetaRepo {
    /// Initializes the vault metadata.
    ///
    /// This should only be called once during vault creation.
    /// Returns an error if vault_meta already exists.
    pub async fn initialize(
        pool: &SqlitePool,
        salt: String,
        iterations: u32,
        memory_cost: u32,
        parallelism: u32,
        test_envelope: Vec<u8>,
        hint: Option<String>,
    ) -> KestrelResult<VaultMeta> {
        let now = chrono::Utc::now().to_rfc3339();

        // Check if already initialized
        if Self::exists(pool).await? {
            return Err(KestrelError::Config(
                "Vault is already initialized".to_string(),
            ));
        }

        sqlx::query(
            "INSERT INTO vault_meta (id, salt, iterations, memory_cost, parallelism, \
             test_envelope, hint, created_at, updated_at) \
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"
        )
        .bind(&salt)
        .bind(iterations)
        .bind(memory_cost)
        .bind(parallelism)
        .bind(&test_envelope)
        .bind(&hint)
        .bind(&now)
        .bind(&now)
        .execute(pool)
        .await
        .map_err(|e| KestrelError::Database(format!("Failed to initialize vault_meta: {e}")))?;

        Ok(VaultMeta {
            id: 1,
            salt,
            iterations,
            memory_cost,
            parallelism,
            test_envelope,
            hint,
            created_at: now.clone(),
            updated_at: now,
        })
    }

    /// Gets the singleton vault metadata.
    ///
    /// Returns None if the vault has not been initialized.
    pub async fn get(pool: &SqlitePool) -> KestrelResult<Option<VaultMeta>> {
        let result = sqlx::query_as::<_, (i64, String, u32, u32, u32, Vec<u8>, Option<String>, String, String)>(
            "SELECT id, salt, iterations, memory_cost, parallelism, \
             test_envelope, hint, created_at, updated_at \
             FROM vault_meta WHERE id = 1"
        )
        .fetch_optional(pool)
        .await
        .map_err(|e| KestrelError::Database(format!("Failed to get vault_meta: {e}")))?

        if let Some((id, salt, iterations, memory_cost, parallelism, test_envelope, hint, created_at, updated_at)) = result {
            Ok(Some(VaultMeta {
                id, salt, iterations, memory_cost, parallelism, test_envelope, hint, created_at, updated_at,
            }))
        } else {
            Ok(None)
        }
    }

    /// Checks if the vault has been initialized.
    pub async fn exists(pool: &SqlitePool) -> KestrelResult<bool> {
        let result: Option<(i64,)> = sqlx::query_as(
            "SELECT id FROM vault_meta WHERE id = 1"
        )
        .fetch_optional(pool)
        .await
        .map_err(|e| KestrelError::Database(format!("Failed to check vault_meta: {e}")))?;

        Ok(result.is_some())
    }

    /// Updates the salt and test envelope (for password change).
    ///
    /// This should be called within a transaction that also
    /// re-encrypts all vault data.
    pub async fn update_salt(
        pool: &SqlitePool,
        salt: String,
        test_envelope: Vec<u8>,
    ) -> KestrelResult<()> {
        let now = chrono::Utc::now().to_rfc3339();

        let result = sqlx::query(
            "UPDATE vault_meta SET salt = ?1, test_envelope = ?2, updated_at = ?3 \
             WHERE id = 1"
        )
        .bind(&salt)
        .bind(&test_envelope)
        .bind(&now)
        .execute(pool)
        .await
        .map_err(|e| KestrelError::Database(format!("Failed to update salt: {e}")))?;

        if result.rows_affected() == 0 {
            return Err(KestrelError::Config(
                "Vault meta not found".to_string(),
            ));
        }
        Ok(())
    }

    /// Updates the password hint.
    pub async fn update_hint(
        pool: &SqlitePool,
        hint: Option<String>,
    ) -> KestrelResult<()> {
        let now = chrono::Utc::now().to_rfc3339();

        sqlx::query(
            "UPDATE vault_meta SET hint = ?1, updated_at = ?2 WHERE id = 1"
        )
        .bind(&hint)
        .bind(&now)
        .execute(pool)
        .await
        .map_err(|e| KestrelError::Database(format!("Failed to update hint: {e}")))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_meta_serializes() {
        let meta = VaultMeta {
            id: 1,
            salt: "abcd1234".to_string(),
            iterations: 3,
            memory_cost: 262144,
            parallelism: 4,
            test_envelope: vec![1, 2, 3],
            hint: Some("my hint".to_string()),
            created_at: "2025-01-01T00:00:00Z".to_string(),
            updated_at: "2025-01-01T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&meta).unwrap();
        assert!(json.contains("abcd1234"));
    }
}
