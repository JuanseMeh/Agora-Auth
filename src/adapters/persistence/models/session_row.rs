/// Raw database row representing a user session.
///
/// This maps to the `auth_session` table in the database.
/// It is NOT a domain entity — it is purely for database row deserialization.

use chrono::{DateTime, Utc};
use sqlx::FromRow;

#[derive(Debug, Clone, FromRow)]
pub struct SessionRow {
    /// Session identifier (primary key, UUID)
    pub id: String,

    /// User identifier (indexed, foreign key to identity_credential)
    pub user_id: String,

    /// Hash of the refresh token (indexed, unique per session)
    pub refresh_token_hash: String,

    /// Timestamp when the session was created
    pub created_at: DateTime<Utc>,

    /// Timestamp when the session expires (indexed)
    pub expires_at: DateTime<Utc>,

    /// Timestamp when the session was revoked (NULL if active)
    pub revoked_at: Option<DateTime<Utc>>,

    /// IP address from which the session was created
    pub ip_address: String,

    /// User agent from which the session was created
    pub user_agent: String,

    /// Timestamp when the record was last updated
    pub updated_at: DateTime<Utc>,
}

impl SessionRow {
    /// Check if the session is currently active (not revoked and not expired)
    pub fn is_active(&self, now: DateTime<Utc>) -> bool {
        self.revoked_at.is_none() && now < self.expires_at
    }

    /// Check if the session is expired
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now >= self.expires_at
    }

    /// Check if the session is revoked
    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    /// Get the time remaining until expiration, if any
    pub fn time_to_expiration(&self, now: DateTime<Utc>) -> Option<std::time::Duration> {
        if now < self.expires_at {
            Some((self.expires_at - now).to_std().unwrap_or_default())
        } else {
            None
        }
    }
}
