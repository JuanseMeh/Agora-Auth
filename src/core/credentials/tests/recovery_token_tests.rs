use chrono::{DateTime, Utc};
use uuid::Uuid;
use chrono::Duration;

/// Persisted recovery token — stored hashed, never the raw value.
#[derive(Debug, Clone)]
#[allow(dead_code)]
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

    fn make_token(expires_offset: Duration, used: bool) -> RecoveryToken {
        let now = Utc::now();
        RecoveryToken {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            token_hash: "hash".to_string(),
            expires_at: now + expires_offset,
            used_at: if used { Some(now) } else { None },
            created_at: now,
        }
    }

    #[test]
    fn valid_token_is_valid() {
        let token = make_token(Duration::minutes(15), false);
        assert!(token.is_valid(Utc::now()));
    }

    #[test]
    fn expired_token_is_invalid() {
        let token = make_token(Duration::minutes(-1), false);
        assert!(!token.is_valid(Utc::now()));
    }

    #[test]
    fn used_token_is_invalid() {
        let token = make_token(Duration::minutes(15), true);
        assert!(!token.is_valid(Utc::now()));
    }