/// Raw database row representing an external identity link.
///
/// This maps to the `external_identities` table.
/// Used for linking internal users with OAuth providers like Google.

use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, FromRow)]
pub struct ExternalIdentityRow {
    /// Link identifier (primary key)
    pub id: Uuid,

    /// Internal user ID (FK to identity_credential.user_id)
    pub user_id: Uuid,

    /// Provider name ('google', 'github', etc.)
    pub provider: String,

    /// Provider-specific user ID (sub claim from ID token)
    pub provider_user_id: String,

    /// Email from provider (optional)
    pub email: Option<String>,

    /// Creation timestamp
    pub created_at: DateTime<Utc>,

    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
}

impl ExternalIdentityRow {
    /// Check if this is a Google identity
    pub fn is_google(&self) -> bool {
        self.provider.eq_ignore_ascii_case("google")
    }

    /// Format provider user ID for logging/debug
    pub fn provider_display(&self) -> String {
        format!("{}:{}", self.provider, &self.provider_user_id[..self.provider_user_id.len().min(20)])
    }
}
