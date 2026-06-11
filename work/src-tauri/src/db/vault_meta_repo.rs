//! Vault metadata repository for database operations.
//!
//! Manages the singleton `vault_meta` row that stores KDF parameters,
//! the test envelope for vault verification, and the wrapped DEK for
//! the KEK/DEK key hierarchy.
//!
//! # KEK/DEK Hierarchy
//!
//! The vault_meta table stores:
//! - **Salt**: Hex-encoded salt for Argon2id key derivation
//! - **KDF parameters**: iterations, memory_cost, parallelism, kdf_version
//! - **Test envelope**: Encrypted known plaintext for password verification
//! - **Wrapped DEK**: The Data Encryption Key encrypted by the KEK
//!
//! When the vault is unlocked:
//! 1. The KEK is derived from the master password using Argon2id + salt
//! 2. The KEK verifies the test envelope
//! 3. The KEK unwraps the DEK from wrapped_dek
//! 4. The DEK is used for all field-level encryption/decryption
//!
//! # Security
//!
//! - The salt is stored as hex (not binary) for SQLCipher compatibility
//! - The test envelope verifies the master password without storing it
//! - The wrapped DEK ensures O(1) password rotation (no re-encryption of data)
//! - KDF parameters are stored for reproducible key derivation
//! - kdf_version enables parameter upgrade detection

use crate::error::{KestrelError, KestrelResult};
use sqlx::SqlitePool;

/// Vault metadata — singleton row in the database.
///
/// This struct holds all the cryptographic parameters needed to:
/// 1. Derive the KEK from the master password (salt + KDF params)
/// 2. Verify the master password (test_envelope)
/// 3. Unwrap the DEK (wrapped_dek)
/// 4. Detect if KDF parameters need upgrading (kdf_version)
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
    /// KDF parameter version (for upgrade detection).
    pub kdf_version: u32,
    /// Encrypted test envelope for password verification.
    pub test_envelope: Vec<u8>,
    /// The DEK wrapped (encrypted) by the KEK.
    /// This is the core of the KEK/DEK hierarchy — the DEK is never
    /// stored in plaintext, only in this wrapped form.
    pub wrapped_dek: Vec<u8>,
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
    ///
    /// # Arguments
    ///
    /// * `pool` - Database connection pool
    /// * `salt` - Hex-encoded salt for Argon2id
    /// * `iterations` - Argon2id iteration count
    /// * `memory_cost` - Argon2id memory cost in KiB
    /// * `parallelism` - Argon2id parallelism
    /// * `kdf_version` - KDF parameter version (for upgrade detection)
    /// * `test_envelope` - Encrypted test envelope for password verification
    /// * `wrapped_dek` - DEK encrypted by the KEK
    /// * `hint` - Optional password hint
    pub async fn initialize(
        pool: &SqlitePool,
        salt: String,
        iterations: u32,
        memory_cost: u32,
        parallelism: u32,
        kdf_version: u32,
        test_envelope: Vec<u8>,
        wrapped_dek: Vec<u8>,
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
             kdf_version, test_envelope, wrapped_dek, hint, created_at, updated_at) \
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"
        )
        .bind(&salt)
        .bind(iterations)
        .bind(memory_cost)
        .bind(parallelism)
        .bind(kdf_version)
        .bind(&test_envelope)
        .bind(&wrapped_dek)
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
            kdf_version,
            test_envelope,
            wrapped_dek,
            hint,
            created_at: now.clone(),
            updated_at: now,
        })
    }

    /// Gets the singleton vault metadata.
    ///
    /// Returns None if the vault has not been initialized.
    pub async fn get(pool: &SqlitePool) -> KestrelResult<Option<VaultMeta>> {
        let result = sqlx::query_as::<_, (i64, String, u32, u32, u32, u32, Vec<u8>, Vec<u8>, Option<String>, String, String)>(
            "SELECT id, salt, iterations, memory_cost, parallelism, \
             kdf_version, test_envelope, wrapped_dek, hint, created_at, updated_at \
             FROM vault_meta WHERE id = 1"
        )
        .fetch_optional(pool)
        .await
        .map_err(|e| KestrelError::Database(format!("Failed to get vault_meta: {e}")))?;

        if let Some((id, salt, iterations, memory_cost, parallelism, kdf_version, test_envelope, wrapped_dek, hint, created_at, updated_at)) = result {
            Ok(Some(VaultMeta {
                id, salt, iterations, memory_cost, parallelism, kdf_version,
                test_envelope, wrapped_dek, hint, created_at, updated_at,
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

    /// Updates the salt, test envelope, and wrapped DEK (for password change).
    ///
    /// This is the core operation for key rotation (password change).
    /// With the KEK/DEK hierarchy, password change only requires:
    /// 1. Derive new KEK from new password
    /// 2. Re-wrap the DEK with the new KEK (O(1) — no data re-encryption)
    /// 3. Store the new salt, test envelope, and wrapped DEK
    ///
    /// This should be called within a transaction to ensure atomicity.
    pub async fn update_key_material(
        pool: &SqlitePool,
        salt: String,
        test_envelope: Vec<u8>,
        wrapped_dek: Vec<u8>,
        iterations: u32,
        memory_cost: u32,
        parallelism: u32,
        kdf_version: u32,
    ) -> KestrelResult<()> {
        let now = chrono::Utc::now().to_rfc3339();

        let result = sqlx::query(
            "UPDATE vault_meta SET salt = ?1, test_envelope = ?2, wrapped_dek = ?3, \
             iterations = ?4, memory_cost = ?5, parallelism = ?6, kdf_version = ?7, \
             updated_at = ?8 WHERE id = 1"
        )
        .bind(&salt)
        .bind(&test_envelope)
        .bind(&wrapped_dek)
        .bind(iterations)
        .bind(memory_cost)
        .bind(parallelism)
        .bind(kdf_version)
        .bind(&now)
        .execute(pool)
        .await
        .map_err(|e| KestrelError::Database(format!("Failed to update key material: {e}")))?;

        if result.rows_affected() == 0 {
            return Err(KestrelError::Config(
                "Vault meta not found".to_string(),
            ));
        }

        tracing::info!(
            "Vault key material updated: kdf_version={}, memory={}KiB, iterations={}, parallelism={}",
            kdf_version, memory_cost, iterations, parallelism
        );
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

    /// Gets the wrapped DEK bytes without loading the full metadata.
    ///
    /// This is useful during vault unlock when we only need the
    /// wrapped DEK to unwrap it with the KEK.
    pub async fn get_wrapped_dek(pool: &SqlitePool) -> KestrelResult<Option<Vec<u8>>> {
        let result: Option<(Vec<u8>,)> = sqlx::query_as(
            "SELECT wrapped_dek FROM vault_meta WHERE id = 1"
        )
        .fetch_optional(pool)
        .await
        .map_err(|e| KestrelError::Database(format!("Failed to get wrapped_dek: {e}")))?;

        Ok(result.map(|(dek,)| dek))
    }

    /// Gets the test envelope bytes without loading the full metadata.
    pub async fn get_test_envelope(pool: &SqlitePool) -> KestrelResult<Option<Vec<u8>>> {
        let result: Option<(Vec<u8>,)> = sqlx::query_as(
            "SELECT test_envelope FROM vault_meta WHERE id = 1"
        )
        .fetch_optional(pool)
        .await
        .map_err(|e| KestrelError::Database(format!("Failed to get test_envelope: {e}")))?;

        Ok(result.map(|(env,)| env))
    }

    /// Checks if KDF parameters need upgrading.
    ///
    /// Returns true if the stored parameters are below current
    /// OWASP recommendations. This should be checked during
    /// password change to prompt the user to upgrade.
    pub async fn needs_kdf_upgrade(pool: &SqlitePool) -> KestrelResult<bool> {
        let meta = Self::get(pool).await?;
        match meta {
            Some(m) => {
                use crate::crypto::kdf;
                Ok(m.kdf_version < crate::crypto::kdf_params::CURRENT_KDF_VERSION
                    || m.iterations < kdf::ITERATIONS
                    || m.memory_cost < kdf::MEMORY_COST
                    || m.parallelism < kdf::PARALLELISM)
            }
            None => Ok(false),
        }
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
            kdf_version: 1,
            test_envelope: vec![1, 2, 3],
            wrapped_dek: vec![4, 5, 6],
            hint: Some("my hint".to_string()),
            created_at: "2025-01-01T00:00:00Z".to_string(),
            updated_at: "2025-01-01T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&meta).unwrap();
        assert!(json.contains("abcd1234"));
        assert!(json.contains("wrapped_dek"));
        assert!(json.contains("kdf_version"));
    }

    #[test]
    fn vault_meta_has_wrapped_dek() {
        let meta = VaultMeta {
            id: 1,
            salt: "abcd1234".to_string(),
            iterations: 3,
            memory_cost: 262144,
            parallelism: 4,
            kdf_version: 1,
            test_envelope: vec![1, 2, 3],
            wrapped_dek: vec![4, 5, 6, 7, 8],
            hint: None,
            created_at: "2025-01-01T00:00:00Z".to_string(),
            updated_at: "2025-01-01T00:00:00Z".to_string(),
        };
        assert!(!meta.wrapped_dek.is_empty());
        assert_eq!(meta.kdf_version, 1);
    }
}
