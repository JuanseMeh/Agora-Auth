/// SQL-backed implementation of identity repository.

use crate::adapters::persistence::{
    database::Database,
    error::{ConstraintError, ExecutionError, PersistenceError},
    models::IdentityRow,
};

/// SQL-backed repository for user identity and credential data.
///
/// Implements queries against the `identity_credential` table.
/// Responsibilities:
/// - Retrieve identity by identifier (username/email)
/// - Retrieve identity by user_id
/// - Map database rows to domain entities
///
/// Does NOT:
/// - Hash or verify passwords
/// - Lock or unlock accounts (that's CredentialRepository)
/// - Validate policies
pub struct IdentityRepositorySql {
    db: Database,
}

impl IdentityRepositorySql {
    /// Create a new identity repository with the given database pool.
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Find identity by identifier (username/email).
    ///
    /// # Errors
    ///
    /// Returns `PersistenceError::Execution(ExecutionError::NotFound)` if no identity exists.
    /// Returns `PersistenceError::Mapping` if the row cannot be mapped to a domain entity.
    pub async fn find_by_identifier(
        &self,
        identifier: &str,
    ) -> Result<IdentityRow, PersistenceError> {
        const QUERY: &str = r#"
            SELECT user_id::TEXT, identifier, password_hash, failed_attempts, 
                   locked_until, password_changed_at, created_at, updated_at
            FROM identity_credential
            WHERE identifier = $1
        "#;

        sqlx::query_as::<_, IdentityRow>(QUERY)
            .bind(identifier)
            .fetch_optional(self.db.pool())
            .await
            .map_err(|e| {
                PersistenceError::Execution(ExecutionError::query_failed(format!(
                    "failed to query identity by identifier: {}",
                    e
                )))
            })?
            .ok_or_else(|| PersistenceError::Execution(ExecutionError::not_found("Identity")))
    }

    /// Find identity by user ID.
    ///
    /// # Errors
    ///
    /// Returns `PersistenceError::Execution(ExecutionError::NotFound)` if no identity exists.
    /// Returns `PersistenceError::Mapping` if the row cannot be mapped to a domain entity.
    pub async fn find_by_id(&self, user_id: &str) -> Result<IdentityRow, PersistenceError> {
        const QUERY: &str = r#"
            SELECT user_id::TEXT, identifier, password_hash, failed_attempts,
                   locked_until, password_changed_at, created_at, updated_at
            FROM identity_credential
            WHERE user_id = $1::uuid
        "#;

        sqlx::query_as::<_, IdentityRow>(QUERY)
            .bind(user_id)
            .fetch_optional(self.db.pool())
            .await
            .map_err(|e| {
                PersistenceError::Execution(ExecutionError::query_failed(format!(
                    "failed to query identity by user_id: {}",
                    e
                )))
            })?
            .ok_or_else(|| PersistenceError::Execution(ExecutionError::not_found("Identity")))
    }

    /// Get the database pool reference.
    ///
    /// Exposed for use by other repositories that need transaction support.
    pub fn db(&self) -> &Database {
        &self.db
    }

    /// Create a new identity record.
    ///
    /// # Arguments
    ///
    /// * `user_id` - User ID (UUID)
    /// * `identifier` - Unique identifier (username/email)
    /// * `password_hash` - Hashed password
    ///
    /// # Errors
    ///
    /// Returns `PersistenceError::Constraint` if the identifier is not unique.
    pub async fn create_identity(
        &self,
        user_id: &str,
        identifier: &str,
        password_hash: &str,
    ) -> Result<(), PersistenceError> {
        const QUERY: &str = r#"
            INSERT INTO identity_credential
            (user_id, identifier, password_hash, failed_attempts, password_changed_at, created_at, updated_at)
            VALUES ($1::uuid, $2, $3, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        "#;

        sqlx::query(QUERY)
            .bind(user_id)
            .bind(identifier)
            .bind(password_hash)
            .execute(self.db.pool())
            .await
            .map_err(|e| {
                // Check for unique constraint violation
                if e.to_string().contains("unique constraint") {
                    PersistenceError::Constraint(ConstraintError::unique_violation(
                        "identifier already exists",
                    ))
                } else {
                    PersistenceError::Execution(ExecutionError::query_failed(format!(
                        "failed to create identity: {}",
                        e
                    )))
                }
            })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_row_is_locked() {
        use chrono::Utc;

        let now = Utc::now();
        let future = now + chrono::Duration::hours(1);
        let past = now - chrono::Duration::hours(1);

        let mut row = IdentityRow {
            user_id: "user123".to_string(),
            identifier: "john@example.com".to_string(),
            password_hash: "hash".to_string(),
            failed_attempts: 0,
            locked_until: Some(future),
            password_changed_at: now,
            created_at: now,
            updated_at: now,
        };

        assert!(row.is_locked(now));

        row.locked_until = Some(past);
        assert!(!row.is_locked(now));

        row.locked_until = None;
        assert!(!row.is_locked(now));
    }

    #[test]
    fn test_identity_row_lock_remaining() {
        use chrono::Utc;

        let now = Utc::now();
        let future = now + chrono::Duration::hours(1);

        let row = IdentityRow {
            user_id: "user123".to_string(),
            identifier: "john@example.com".to_string(),
            password_hash: "hash".to_string(),
            failed_attempts: 0,
            locked_until: Some(future),
            password_changed_at: now,
            created_at: now,
            updated_at: now,
        };

        let remaining = row.lock_remaining(now);
        assert!(remaining.is_some());
        let duration = remaining.unwrap();
        assert!(duration.as_secs() > 3500 && duration.as_secs() < 3610);
    }
}
