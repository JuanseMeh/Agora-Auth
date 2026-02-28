/// SQL-backed implementation of session repository.

use chrono::{DateTime, Utc};
use futures::future::FutureExt;

use crate::adapters::persistence::{
    database::Database,
    error::{ConstraintError, ExecutionError, PersistenceError},
    models::SessionRow,
};
use crate::core::identity::UserIdentity;
use crate::core::usecases::ports::SessionRepository;
use crate::core::usecases::session_repository::Session;

/// SQL-backed repository for session management.
///
/// Implements operations against the `auth_session` table.
/// Responsibilities:
/// - Create new sessions
/// - Find sessions by refresh_token_hash
/// - Revoke individual sessions
/// - Revoke all sessions for a user
/// - Delete expired sessions
/// - Map database rows to domain entities
///
/// Does NOT:
/// - Generate or hash refresh tokens (that's the crypto/token adapter)
/// - Validate tokens
/// - Rotate tokens
pub struct SessionRepositorySql {
    db: Database,
}

impl SessionRepositorySql {
    /// Create a new session repository with the given database pool.
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Create a new session.
    ///
    /// # Arguments
    ///
    /// * `session_id` - Unique session identifier (UUID)
    /// * `user_id` - User identifier (UUID)
    /// * `refresh_token_hash` - Hash of the refresh token (for lookup)
    /// * `expires_at` - Session expiration timestamp
    /// * `ip_address` - Client IP address
    /// * `user_agent` - Client user agent string
    ///
    /// # Errors
    ///
    /// Returns `PersistenceError::Constraint` if the session_id is not unique.
    pub async fn create_session(
        &self,
        session_id: &str,
        user_id: &str,
        refresh_token_hash: &str,
        expires_at: DateTime<Utc>,
        ip_address: &str,
        user_agent: &str,
    ) -> Result<(), PersistenceError> {
        const QUERY: &str = r#"
            INSERT INTO auth_session
            (id, user_id, refresh_token_hash, created_at, expires_at, ip_address, user_agent, updated_at)
            VALUES ($1::uuid, $2::uuid, $3, CURRENT_TIMESTAMP, $4, $5, $6, CURRENT_TIMESTAMP)
        "#;

        sqlx::query(QUERY)
            .bind(session_id)
            .bind(user_id)
            .bind(refresh_token_hash)
            .bind(expires_at)
            .bind(ip_address)
            .bind(user_agent)
            .execute(self.db.pool())
            .await
            .map_err(|e| {
                // Check for unique constraint violation
                if e.to_string().contains("unique constraint") {
                    PersistenceError::Constraint(ConstraintError::unique_violation(
                        "session_id already exists",
                    ))
                } else {
                    PersistenceError::Execution(ExecutionError::query_failed(format!(
                        "failed to create session: {}",
                        e
                    )))
                }
            })?;

        Ok(())
    }

    /// Find an active session by refresh token hash.
    ///
    /// Returns the session only if it is not revoked and not expired.
    ///
    /// # Errors
    ///
    /// Returns `PersistenceError::Execution(ExecutionError::NotFound)` if no session exists.
    pub async fn find_by_refresh_token_hash(
        &self,
        refresh_token_hash: &str,
    ) -> Result<SessionRow, PersistenceError> {
        const QUERY: &str = r#"
            SELECT id, user_id, refresh_token_hash, created_at, expires_at,
                   revoked_at, ip_address, user_agent, updated_at
            FROM auth_session
            WHERE refresh_token_hash = $1
              AND revoked_at IS NULL
              AND expires_at > CURRENT_TIMESTAMP
        "#;

        let row = sqlx::query_as::<_, SessionRow>(QUERY)
            .bind(refresh_token_hash)
            .fetch_optional(self.db.pool())
            .await
            .map_err(|e| {
                PersistenceError::Execution(ExecutionError::query_failed(format!(
                    "failed to query session by refresh token: {}",
                    e
                )))
            })?
            .ok_or_else(|| PersistenceError::Execution(ExecutionError::not_found("Session")))?;

        Ok(row)
    }

    /// Revoke a specific session by session ID.
    ///
    /// # Errors
    ///
    /// Returns `PersistenceError::Execution(ExecutionError::NotFound)` if session doesn't exist.
    pub async fn revoke_session(&self, session_id: &str) -> Result<(), PersistenceError> {
        const QUERY: &str = r#"
            UPDATE auth_session
            SET revoked_at = CURRENT_TIMESTAMP,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = $1::uuid AND revoked_at IS NULL
        "#;

        let result = sqlx::query(QUERY)
            .bind(session_id)
            .execute(self.db.pool())
            .await
            .map_err(|e| {
                PersistenceError::Execution(ExecutionError::query_failed(format!(
                    "failed to revoke session: {}",
                    e
                )))
            })?;

        if result.rows_affected() == 0 {
            return Err(PersistenceError::Execution(ExecutionError::not_found(
                "Session",
            )));
        }

        Ok(())
    }

    /// Revoke all sessions for a user.
    ///
    /// Returns the number of sessions revoked.
    pub async fn revoke_all_for_user(&self, user_id: &str) -> Result<u64, PersistenceError> {
        const QUERY: &str = r#"
            UPDATE auth_session
            SET revoked_at = CURRENT_TIMESTAMP,
                updated_at = CURRENT_TIMESTAMP
            WHERE user_id = $1::uuid AND revoked_at IS NULL
        "#;

        let result = sqlx::query(QUERY)
            .bind(user_id)
            .execute(self.db.pool())
            .await
            .map_err(|e| {
                PersistenceError::Execution(ExecutionError::query_failed(format!(
                    "failed to revoke sessions for user: {}",
                    e
                )))
            })?;

        Ok(result.rows_affected())
    }

    /// Delete expired sessions.
    ///
    /// Returns the number of sessions deleted.
    pub async fn delete_expired(&self) -> Result<u64, PersistenceError> {
        const QUERY: &str = r#"
            DELETE FROM auth_session
            WHERE expires_at < CURRENT_TIMESTAMP
        "#;

        let result = sqlx::query(QUERY)
            .execute(self.db.pool())
            .await
            .map_err(|e| {
                PersistenceError::Execution(ExecutionError::query_failed(format!(
                    "failed to delete expired sessions: {}",
                    e
                )))
            })?;

        Ok(result.rows_affected())
    }

    /// Find a session by session ID.
    ///
    /// Returns the session only if it is not revoked and not expired.
    ///
    /// # Errors
    ///
    /// Returns `PersistenceError::Execution(ExecutionError::NotFound)` if no session exists.
    pub async fn find_by_id(
        &self,
        session_id: &str,
    ) -> Result<SessionRow, PersistenceError> {
        const QUERY: &str = r#"
            SELECT id, user_id, refresh_token_hash, created_at, expires_at,
                   revoked_at, ip_address, user_agent, updated_at
            FROM auth_session
            WHERE id = $1::uuid
              AND revoked_at IS NULL
              AND expires_at > CURRENT_TIMESTAMP
        "#;

        let row = sqlx::query_as::<_, SessionRow>(QUERY)
            .bind(session_id)
            .fetch_optional(self.db.pool())
            .await
            .map_err(|e| {
                PersistenceError::Execution(ExecutionError::query_failed(format!(
                    "failed to query session by id: {}",
                    e
                )))
            })?
            .ok_or_else(|| PersistenceError::Execution(ExecutionError::not_found("Session")))?;

        Ok(row)
    }

    /// Get the database pool reference.
    pub fn db(&self) -> &Database {
        &self.db
    }
}

impl SessionRepository for SessionRepositorySql {
    fn create_session(&self, session_id: &str, user: &UserIdentity, refresh_token_hash: &str, metadata: &str) -> futures::future::BoxFuture<'_, ()> {
        let session_id = session_id.to_string();
        let user_id = user.id.clone();
        let refresh_token_hash = refresh_token_hash.to_string();
        let metadata = metadata.to_string();
        let expires_at = Utc::now() + chrono::Duration::days(7); // Default 7-day session
        
        async move {
            let _ = self.create_session(
                &session_id,
                &user_id,
                &refresh_token_hash,
                expires_at,
                "0.0.0.0", // Default IP
                &metadata,
            )
            .await;
        }
        .boxed()
    }

    fn find_by_refresh_token_hash(&self, hash: &str) -> futures::future::BoxFuture<'_, Option<Session>> {
        let hash = hash.to_string();
        async move {
            match self.find_by_refresh_token_hash(&hash).await {
                Ok(_session) => {
                    tracing::debug!("[SESSION_REPO] Session found for hash");
                    Some(Session {})
                }
                Err(e) => {
                    tracing::error!("[SESSION_REPO] Error finding session: {:?}", e);
                    None
                }
            }
        }
        .boxed()
    }

    fn find_by_id(&self, session_id: &str) -> futures::future::BoxFuture<'_, Option<Session>> {
        let session_id = session_id.to_string();
        async move {
            match self.find_by_id(&session_id).await {
                Ok(_session) => {
                    tracing::debug!("[SESSION_REPO] Session found for id");
                    Some(Session {})
                }
                Err(e) => {
                    tracing::error!("[SESSION_REPO] Error finding session by id: {:?}", e);
                    None
                }
            }
        }
        .boxed()
    }

    fn revoke_session(&self, session_id: &str) -> futures::future::BoxFuture<'_, ()> {
        let session_id = session_id.to_string();
        async move {
            let _ = self.revoke_session(&session_id).await;
        }
        .boxed()
    }

    fn revoke_all_for_user(&self, user_id: &str) -> futures::future::BoxFuture<'_, ()> {
        let user_id = user_id.to_string();
        async move {
            let _ = self.revoke_all_for_user(&user_id).await;
        }
        .boxed()
    }

    fn delete_expired(&self) -> futures::future::BoxFuture<'_, ()> {
        async move {
            let _ = self.delete_expired().await;
        }
        .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn test_session_row_is_active() {
        use chrono::Utc;

        let now = Utc::now();
        let future = now + chrono::Duration::hours(1);
        let past = now - chrono::Duration::hours(1);

        let mut row = SessionRow {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            refresh_token_hash: "hash".to_string(),
            created_at: now,
            expires_at: future,
            revoked_at: None,
            ip_address: "127.0.0.1".to_string(),
            user_agent: "test".to_string(),
            updated_at: now,
        };

        assert!(row.is_active(now));

        // Test revoked session
        row.revoked_at = Some(now);
        assert!(!row.is_active(now));

        // Test expired session
        row.revoked_at = None;
        row.expires_at = past;
        assert!(!row.is_active(now));
    }

    #[test]
    fn test_session_row_is_expired() {
        use chrono::Utc;

        let now = Utc::now();
        let future = now + chrono::Duration::hours(1);
        let past = now - chrono::Duration::hours(1);

        let mut row = SessionRow {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            refresh_token_hash: "hash".to_string(),
            created_at: now,
            expires_at: future,
            revoked_at: None,
            ip_address: "127.0.0.1".to_string(),
            user_agent: "test".to_string(),
            updated_at: now,
        };

        assert!(!row.is_expired(now));

        row.expires_at = past;
        assert!(row.is_expired(now));
    }

    #[test]
    fn test_session_row_time_to_expiration() {
        use chrono::Utc;

        let now = Utc::now();
        let future = now + chrono::Duration::hours(1);

        let row = SessionRow {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            refresh_token_hash: "hash".to_string(),
            created_at: now,
            expires_at: future,
            revoked_at: None,
            ip_address: "127.0.0.1".to_string(),
            user_agent: "test".to_string(),
            updated_at: now,
        };

        let time_left = row.time_to_expiration(now);
        assert!(time_left.is_some());
        let duration = time_left.unwrap();
        assert!(duration.as_secs() > 3500 && duration.as_secs() < 3610);
    }
}
