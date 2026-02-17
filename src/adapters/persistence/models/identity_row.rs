/// Raw database row representing a user identity and credential state.
///
/// This maps to the `identity_credential` table in the database.
/// It is NOT a domain entity — it is purely for database row deserialization.

use chrono::{DateTime, Utc};
use sqlx::FromRow;

#[derive(Debug, Clone, FromRow)]
pub struct IdentityRow {
    /// User identifier (primary key)
    pub user_id: String,

    /// User identifier/username (unique constraint)
    pub identifier: String,

    /// Bcrypt or Argon2 password hash
    pub password_hash: String,

    /// Number of failed authentication attempts
    pub failed_attempts: i32,

    /// Timestamp when the account becomes unlocked (NULL if not locked)
    pub locked_until: Option<DateTime<Utc>>,

    /// Timestamp when the password was last changed
    pub password_changed_at: DateTime<Utc>,

    /// Timestamp when the record was created
    pub created_at: DateTime<Utc>,

    /// Timestamp when the record was last updated
    pub updated_at: DateTime<Utc>,
}

impl IdentityRow {
    /// Check if the account is currently locked
    pub fn is_locked(&self, now: DateTime<Utc>) -> bool {
        self.locked_until
            .map(|until| now < until)
            .unwrap_or(false)
    }

    /// Get the remaining lock time, if any
    pub fn lock_remaining(&self, now: DateTime<Utc>) -> Option<std::time::Duration> {
        self.locked_until.and_then(|until| {
            if now < until {
                Some((until - now).to_std().unwrap_or_default())
            } else {
                None
            }
        })
    }
}
