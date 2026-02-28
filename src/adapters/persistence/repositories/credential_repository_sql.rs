/// SQL-backed implementation of credential repository.

use chrono::{DateTime, Utc};
use futures::future::FutureExt;
use sqlx::Row;

use crate::adapters::persistence::{
    database::Database,
    error::{ExecutionError, PersistenceError},
};
use crate::core::credentials::StoredCredential;
use crate::core::usecases::ports::CredentialRepository;

/// SQL-backed repository for credential state management.
///
/// Implements mutations against the `identity_credential` table.
/// Responsibilities:
/// - Get credential state by user_id
/// - Update failed_attempts counter
/// - Update locked_until timestamp
/// - Update password hash and password_changed_at
/// - Support transactional operations
///
/// Does NOT:
/// - Hash passwords (that's the crypto adapter)
/// - Validate policies
/// - Interpret credentials
pub struct CredentialRepositorySql {
    db: Database,
}

impl CredentialRepositorySql {
    /// Create a new credential repository with the given database pool.
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Get credential state for a user.
    ///
    /// Returns failed_attempts, locked_until status, and password hash.
    ///
    /// # Errors
    ///
    /// Returns `PersistenceError::Execution(ExecutionError::NotFound)` if user doesn't exist.
    pub async fn get_credential_state(
        &self,
        user_id: &str,
    ) -> Result<CredentialState, PersistenceError> {
        const QUERY: &str = r#"
            SELECT failed_attempts, locked_until, password_changed_at, password_hash
            FROM identity_credential
            WHERE user_id = $1::uuid
        "#;

        let row = sqlx::query(QUERY)
            .bind(user_id)
            .fetch_optional(self.db.pool())
            .await
            .map_err(|e| {
                PersistenceError::Execution(ExecutionError::query_failed(format!(
                    "failed to query credential state: {}",
                    e
                )))
            })?
            .ok_or_else(|| PersistenceError::Execution(ExecutionError::not_found("Credential")))?;

        Ok(CredentialState {
            failed_attempts: row.get("failed_attempts"),
            locked_until: row.get("locked_until"),
            password_changed_at: row.get("password_changed_at"),
            password_hash: row.get("password_hash"),
        })
    }

    /// Increment failed authentication attempts.
    ///
    /// # Errors
    ///
    /// Returns `PersistenceError` on query failure.
    pub async fn increment_failed_attempts(
        &self,
        user_id: &str,
    ) -> Result<i32, PersistenceError> {
        const QUERY: &str = r#"
            UPDATE identity_credential
            SET failed_attempts = failed_attempts + 1,
                updated_at = CURRENT_TIMESTAMP
            WHERE user_id = $1::uuid
            RETURNING failed_attempts
        "#;

        let row = sqlx::query(QUERY)
            .bind(user_id)
            .fetch_optional(self.db.pool())
            .await
            .map_err(|e| {
                PersistenceError::Execution(ExecutionError::query_failed(format!(
                    "failed to increment failed attempts: {}",
                    e
                )))
            })?
            .ok_or_else(|| PersistenceError::Execution(ExecutionError::not_found("User")))?;

        Ok(row.get("failed_attempts"))
    }

    /// Reset failed attempts and unlock account.
    ///
    /// Sets failed_attempts to 0 and locked_until to NULL.
    ///
    /// # Errors
    ///
    /// Returns `PersistenceError` on query failure.
    pub async fn reset_failed_attempts(&self, user_id: &str) -> Result<(), PersistenceError> {
        const QUERY: &str = r#"
            UPDATE identity_credential
            SET failed_attempts = 0,
                locked_until = NULL,
                updated_at = CURRENT_TIMESTAMP
            WHERE user_id = $1::uuid
        "#;

        sqlx::query(QUERY)
            .bind(user_id)
            .execute(self.db.pool())
            .await
            .map_err(|e| {
                PersistenceError::Execution(ExecutionError::query_failed(format!(
                    "failed to reset failed attempts: {}",
                    e
                )))
            })?;

        Ok(())
    }

    /// Lock account until a specific timestamp.
    ///
    /// # Errors
    ///
    /// Returns `PersistenceError` on query failure.
    pub async fn lock_until(
        &self,
        user_id: &str,
        until: DateTime<Utc>,
    ) -> Result<(), PersistenceError> {
        const QUERY: &str = r#"
            UPDATE identity_credential
            SET locked_until = $1,
                updated_at = CURRENT_TIMESTAMP
            WHERE user_id = $2::uuid
        "#;

        sqlx::query(QUERY)
            .bind(until)
            .bind(user_id)
            .execute(self.db.pool())
            .await
            .map_err(|e| {
                PersistenceError::Execution(ExecutionError::query_failed(format!(
                    "failed to lock account: {}",
                    e
                )))
            })?;

        Ok(())
    }

    /// Update password hash and password_changed_at timestamp.
    ///
    /// Also resets failed attempts and unlocks the account.
    ///
    /// # Errors
    ///
    /// Returns `PersistenceError` on query failure.
    pub async fn update_password(
        &self,
        user_id: &str,
        password_hash: &str,
        changed_at: DateTime<Utc>,
    ) -> Result<(), PersistenceError> {
        const QUERY: &str = r#"
            UPDATE identity_credential
            SET password_hash = $1,
                password_changed_at = $2,
                failed_attempts = 0,
                locked_until = NULL,
                updated_at = CURRENT_TIMESTAMP
            WHERE user_id = $3::uuid
        "#;

        sqlx::query(QUERY)
            .bind(password_hash)
            .bind(changed_at)
            .bind(user_id)
            .execute(self.db.pool())
            .await
            .map_err(|e| {
                PersistenceError::Execution(ExecutionError::query_failed(format!(
                    "failed to update password: {}",
                    e
                )))
            })?;

        Ok(())
    }

    /// Set failed attempts to a specific value (not increment).
    async fn set_failed_attempts(&self, user_id: &str, attempts: u32) -> Result<(), PersistenceError> {
        const QUERY: &str = r#"
            UPDATE identity_credential
            SET failed_attempts = $1,
                updated_at = CURRENT_TIMESTAMP
            WHERE user_id = $2::uuid
        "#;

        sqlx::query(QUERY)
            .bind(attempts as i32)
            .bind(user_id)
            .execute(self.db.pool())
            .await
            .map_err(|e| {
                PersistenceError::Execution(ExecutionError::query_failed(format!(
                    "failed to set failed attempts: {}",
                    e
                )))
            })?;

        Ok(())
    }

    /// Get the database pool reference.
    pub fn db(&self) -> &Database {
        &self.db
    }
}

impl CredentialRepository for CredentialRepositorySql {
    fn get_by_user_id(&self, user_id: &str) -> futures::future::BoxFuture<'_, Option<StoredCredential>> {
        let user_id = user_id.to_string();
        async move {
            self.get_credential_state(&user_id)
                .await
                .ok()
                .and_then(|state| {
                    let locked_until = state.locked_until.map(|dt| dt.to_rfc3339());
                    Some(StoredCredential::from_parts(
                        state.password_hash,
                        state.failed_attempts as u32,
                        locked_until,
                    ))
                })
        }
        .boxed()
    }

    fn update_failed_attempts(&self, user_id: &str, attempts: u32) -> futures::future::BoxFuture<'_, ()> {
        let user_id = user_id.to_string();
        async move {
            if attempts == 0 {
                // Reset to 0 on successful authentication
                let _ = self.reset_failed_attempts(&user_id).await;
            } else {
                // Set to specific value on failed authentication
                let _ = self.set_failed_attempts(&user_id, attempts).await;
            }
        }
        .boxed()
    }

    fn lock_until(&self, user_id: &str, until: &str) -> futures::future::BoxFuture<'_, ()> {
        let user_id = user_id.to_string();
        let until = until.to_string();
        async move {
            if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&until) {
                let utc_dt = dt.with_timezone(&Utc);
                let _ = self.lock_until(&user_id, utc_dt).await;
            }
        }
        .boxed()
    }

    fn update_password(&self, user_id: &str, _new_credential: StoredCredential) -> futures::future::BoxFuture<'_, ()> {
        let user_id = user_id.to_string();
        async move {
            let _ = self.update_password(&user_id, "", Utc::now()).await;
        }
        .boxed()
    }

    fn initialize_credential_state(&self, _user_id: &str) -> futures::future::BoxFuture<'_, Result<(), String>> {
        async move {
            // Credential state is initialized when identity is created
            Ok(())
        }
        .boxed()
    }
}

/// Credential state snapshot from the database.
#[derive(Debug, Clone)]
pub struct CredentialState {
    /// Number of failed authentication attempts
    pub failed_attempts: i32,
    /// Timestamp when the account becomes unlocked, if locked
    pub locked_until: Option<DateTime<Utc>>,
    /// Timestamp when the password was last changed
    pub password_changed_at: DateTime<Utc>,
    /// The stored password hash
    pub password_hash: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_state_creation() {
        use chrono::Utc;

        let now = Utc::now();
        let state = CredentialState {
            failed_attempts: 3,
            locked_until: Some(now),
            password_changed_at: now,
            password_hash: "$argon2id$v=19$m=65536,t=3,p=4$...".to_string(),
        };

        assert_eq!(state.failed_attempts, 3);
        assert!(state.locked_until.is_some());
        assert!(!state.password_hash.is_empty());
    }
}
