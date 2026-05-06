use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use crate::core::credentials::recovery_token::RecoveryToken;

/// Raw database row for the `credential_recovery` table.
#[derive(Debug, Clone, FromRow)]
pub struct RecoveryTokenRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl RecoveryTokenRow {
    /// Map the database row to a domain entity.
    pub fn to_domain(self) -> RecoveryToken {
        RecoveryToken {
            id: self.id,
            user_id: self.user_id,
            token_hash: self.token_hash,
            expires_at: self.expires_at,
            used_at: self.used_at,
            created_at: self.created_at,
        }
    }
}
