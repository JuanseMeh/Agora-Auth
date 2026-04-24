/// SQL-backed implementation of external identity repository.
///
/// Maps to the `external_identities` table for OAuth account linking.
/// Responsibilities:
/// - Find external identity by provider + provider_user_id (sub claim)
/// - Upsert external identity link (INSERT ... ON CONFLICT DO UPDATE)
/// - Delete external identity link
///
/// Does NOT:
/// - Validate provider/user_id
/// - Handle OAuth token/state (separate concerns)
/// - Enforce linking policies (usecase layer)

use futures::future::{FutureExt, BoxFuture};
use uuid::Uuid;
use anyhow::Result;

use crate::adapters::persistence::{
    database::Database,
    error::{ConstraintError, ExecutionError, PersistenceError},
    models::ExternalIdentityRow,
};
use crate::core::usecases::ports::ExternalIdentityRepository;

#[derive(Clone)]
pub struct ExternalIdentityRepositorySql {
    db: Database,
}

impl ExternalIdentityRepositorySql {
    /// Create a new external identity repository with the given database pool.
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Find external identity by provider + provider_user_id.
    ///
    /// Returns `PersistenceError::Execution(ExecutionError::NotFound)` if no link exists.
    pub async fn find_by_provider_user_internal(
        &self,
        provider: &str,
        provider_user_id: &str,
    ) -> Result<Option<Uuid>, PersistenceError> {
        const QUERY: &str = r#"
            SELECT id, user_id, provider, provider_user_id, email, created_at, updated_at
            FROM external_identities
            WHERE provider = $1 AND provider_user_id = $2
        "#;

        let row_opt = sqlx::query_as::<_, ExternalIdentityRow>(QUERY)
            .bind(provider)
            .bind(provider_user_id)
            .fetch_optional(self.db.pool())
            .await
            .map_err(|e| {
                PersistenceError::Execution(ExecutionError::query_failed(format!(
                    "failed to query external identity by provider+user_id: {}",
                    e
                )))
            })?;

        Ok(row_opt.map(|row| row.user_id))
    }

    /// Upsert external identity link.
    ///
    /// Uses INSERT ... ON CONFLICT (provider, provider_user_id) DO UPDATE.
    /// Returns the internal user_id.
    ///
    /// # Errors
    /// Returns `PersistenceError::Constraint` if constraint violation (beyond unique).
    pub async fn upsert_internal(
        &self,
        provider: &str,
        provider_user_id: &str,
        user_id: Uuid,
        email: Option<&str>,
    ) -> Result<Uuid, PersistenceError> {
        const QUERY: &str = r#"
            INSERT INTO external_identities (user_id, provider, provider_user_id, email)
            VALUES ($1::uuid, $2, $3, $4)
            ON CONFLICT (provider, provider_user_id)
            DO UPDATE SET
                user_id = EXCLUDED.user_id,
                email = EXCLUDED.email,
                updated_at = CURRENT_TIMESTAMP
            RETURNING user_id::uuid
        "#;

        let returned_user_id: Uuid = sqlx::query_scalar(QUERY)
            .bind(user_id)
            .bind(provider)
            .bind(provider_user_id)
            .bind(email)
            .fetch_one(self.db.pool())
            .await
            .map_err(|e| {
                if e.to_string().contains("unique constraint") {
                    PersistenceError::Constraint(ConstraintError::unique_violation(
                        "provider+provider_user_id already linked to different user",
                    ))
                } else {
                    PersistenceError::Execution(ExecutionError::query_failed(format!(
                        "failed to upsert external identity: {}",
                        e
                    )))
                }
            })?;

        Ok(returned_user_id)
    }

    /// Delete external identity by provider + provider_user_id.
    ///
    /// Returns `PersistenceError::Execution(ExecutionError::NotFound)` if no link exists.
    pub async fn delete_internal(
        &self,
        provider: &str,
        provider_user_id: &str,
    ) -> Result<(), PersistenceError> {
        const QUERY: &str = r#"
            DELETE FROM external_identities
            WHERE provider = $1 AND provider_user_id = $2
        "#;

        let result = sqlx::query(QUERY)
            .bind(provider)
            .bind(provider_user_id)
            .execute(self.db.pool())
            .await
            .map_err(|e| {
                PersistenceError::Execution(ExecutionError::query_failed(format!(
                    "failed to delete external identity: {}",
                    e
                )))
            })?;

        if result.rows_affected() == 0 {
            return Err(PersistenceError::Execution(ExecutionError::not_found(
                "ExternalIdentity",
            )));
        }

        Ok(())
    }
}

impl ExternalIdentityRepository for ExternalIdentityRepositorySql {
    fn find_by_provider_user(
        &self,
        provider: &str,
        provider_user_id: &str,
    ) -> BoxFuture<'_, Result<Option<Uuid>>> {
        let repo = self.clone();
        let provider = provider.to_string();
        let provider_user_id = provider_user_id.to_string();
        async move {
            repo.find_by_provider_user_internal(&provider, &provider_user_id)
                .await
                .map_err(anyhow::Error::from)
        }
        .boxed()
    }

    fn upsert(
        &self,
        provider: &str,
        provider_user_id: &str,
        user_id: Uuid,
        email: Option<&str>,
    ) -> BoxFuture<'_, Result<Uuid>> {
        let repo = self.clone();
        let provider = provider.to_string();
        let provider_user_id = provider_user_id.to_string();
        let email = email.map(|s| s.to_string());
        async move {
            repo.upsert_internal(&provider, &provider_user_id, user_id, email.as_deref())
                .await
                .map_err(anyhow::Error::from)
        }
        .boxed()
    }

    fn delete(&self, provider: &str, provider_user_id: &str) -> BoxFuture<'_, Result<()>> {
        let repo = self.clone();
        let provider = provider.to_string();
        let provider_user_id = provider_user_id.to_string();
        async move {
            repo.delete_internal(&provider, &provider_user_id)
                .await
                .map_err(anyhow::Error::from)
        }
        .boxed()
    }
}

