use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Raw unhashed token — only exists in memory transiently, sent via email.
#[derive(Debug, Clone)]
pub struct RawRecoveryToken(pub String);

impl RawRecoveryToken {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Persisted recovery token — stored hashed, never the raw value.
#[derive(Debug, Clone)]
pub struct RecoveryToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl RecoveryToken {
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now >= self.expires_at
    }

    pub fn is_used(&self) -> bool {
        self.used_at.is_some()
    }

    pub fn is_valid(&self, now: DateTime<Utc>) -> bool {
        !self.is_expired(now) && !self.is_used()
    }
}