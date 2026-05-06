use chrono::Utc;
use futures::future::{BoxFuture, FutureExt};
use uuid::Uuid;

use crate::adapters::persistence::{
    database::Database,
    error::{ExecutionError, PersistenceError},
    models::RecoveryTokenRow,
};
use crate::core::credentials::recovery_token::RecoveryToken;
use crate::core::error::CoreError;
use crate::core::usecases::ports::recovery_token_repository::RecoveryTokenRepository;

/// SQL-backed repository for recovery token management.
pub struct RecoveryTokenRepositorySql {
    db: Database,
}

impl RecoveryTokenRepositorySql {
    /// Create a new recovery token repository.
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Create a new recovery token.
    pub async fn create_token(&self, token: &RecoveryToken) -> Result<(), PersistenceError> {
        const QUERY: &str = r#"
            INSERT INTO credential_recovery 
                (id, user_id, token_hash, expires_at, used_at, created_at)
            VALUES ($1, $2, $3, $4, $5, $6)
        "#;

        sqlx::query(QUERY)
            .bind(token.id)
            .bind(token.user_id)
            .bind(&token.token_hash)
            .bind(token.expires_at)
            .bind(token.used_at)
            .bind(token.created_at)
            .execute(self.db.pool())
            .await
            .map_err(|e| {
                PersistenceError::Execution(ExecutionError::query_failed(format!(
                    "failed to create recovery token: {}",
                    e
                )))
            })?;

        Ok(())
    }

    /// Find a recovery token by hash.
    pub async fn find_by_hash(
        &self,
        token_hash: &str,
    ) -> Result<RecoveryTokenRow, PersistenceError> {
        const QUERY: &str = r#"
            SELECT id, user_id, token_hash, expires_at, used_at, created_at
            FROM credential_recovery
            WHERE token_hash = $1
        "#;

        let row = sqlx::query_as::<_, RecoveryTokenRow>(QUERY)
            .bind(token_hash)
            .fetch_optional(self.db.pool())
            .await
            .map_err(|e| {
                PersistenceError::Execution(ExecutionError::query_failed(format!(
                    "failed to find recovery token by hash: {}",
                    e
                )))
            })?
            .ok_or_else(|| {
                PersistenceError::Execution(ExecutionError::not_found("RecoveryToken"))
            })?;

        Ok(row)
    }

    /// Mark a token as used.
    pub async fn mark_used(&self, token_id: Uuid) -> Result<(), PersistenceError> {
        const QUERY: &str = r#"
            UPDATE credential_recovery
            SET used_at = $1
            WHERE id = $2 AND used_at IS NULL
        "#;

        let result = sqlx::query(QUERY)
            .bind(Utc::now())
            .bind(token_id)
            .execute(self.db.pool())
            .await
            .map_err(|e| {
                PersistenceError::Execution(ExecutionError::query_failed(format!(
                    "failed to mark recovery token as used: {}",
                    e
                )))
            })?;

        if result.rows_affected() == 0 {
            return Err(PersistenceError::Execution(ExecutionError::not_found(
                "RecoveryToken",
            )));
        }

        Ok(())
    }

    /// Invalidate all active tokens for a user.
    pub async fn invalidate_all_for_user(&self, user_id: Uuid) -> Result<u64, PersistenceError> {
        const QUERY: &str = r#"
            UPDATE credential_recovery
            SET used_at = $1
            WHERE user_id = $2 AND used_at IS NULL AND expires_at > CURRENT_TIMESTAMP
        "#;

        let result = sqlx::query(QUERY)
            .bind(Utc::now())
            .bind(user_id)
            .execute(self.db.pool())
            .await
            .map_err(|e| {
                PersistenceError::Execution(ExecutionError::query_failed(format!(
                    "failed to invalidate recovery tokens for user: {}",
                    e
                )))
            })?;

        Ok(result.rows_affected())
    }
}

impl RecoveryTokenRepository for RecoveryTokenRepositorySql {
    fn create(&self, token: &RecoveryToken) -> BoxFuture<'_, Result<(), CoreError>> {
        let token = token.clone();
        async move {
            self.create_token(&token).await.map_err(|e| {
                CoreError::Invariant(crate::core::error::InvariantError::violated(e.to_string()))
            })
        }
        .boxed()
    }

    fn find_by_hash(
        &self,
        token_hash: &str,
    ) -> BoxFuture<'_, Result<Option<RecoveryToken>, CoreError>> {
        let token_hash = token_hash.to_string();
        async move {
            match self.find_by_hash(&token_hash).await {
                Ok(row) => Ok(Some(row.to_domain())),
                Err(e) if e.is_not_found() => Ok(None),
                Err(e) => Err(CoreError::Invariant(
                    crate::core::error::InvariantError::violated(e.to_string()),
                )),
            }
        }
        .boxed()
    }

    fn mark_used(&self, token_id: Uuid) -> BoxFuture<'_, Result<(), CoreError>> {
        async move {
            self.mark_used(token_id).await.map_err(|e| {
                CoreError::Invariant(crate::core::error::InvariantError::violated(e.to_string()))
            })
        }
        .boxed()
    }

    fn invalidate_all_for_user(&self, user_id: Uuid) -> BoxFuture<'_, Result<(), CoreError>> {
        async move {
            let _ = self.invalidate_all_for_user(user_id).await.map_err(|e| {
                CoreError::Invariant(crate::core::error::InvariantError::violated(e.to_string()))
            })?;
            Ok(())
        }
        .boxed()
    }
}
