use chrono::{Duration, Utc};
use hex;
use rand::RngExt;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;

use crate::core::credentials::recovery_token::{RawRecoveryToken, RecoveryToken};
use crate::core::error::{CoreError, InvariantError};
use crate::core::usecases::ports::{
    identity_repository::IdentityRepository, recovery_token_repository::RecoveryTokenRepository,
};

const RECOVERY_TOKEN_TTL_MINUTES: i64 = 30;
const RECOVERY_TOKEN_BYTES: usize = 32;

pub struct RequestCredentialRecovery {
    identity_repo: Arc<dyn IdentityRepository + Send + Sync>,
    recovery_token_repo: Arc<dyn RecoveryTokenRepository + Send + Sync>,
}

impl RequestCredentialRecovery {
    pub fn new(
        identity_repo: Arc<dyn IdentityRepository + Send + Sync>,
        recovery_token_repo: Arc<dyn RecoveryTokenRepository + Send + Sync>,
    ) -> Self {
        Self {
            identity_repo,
            recovery_token_repo,
        }
    }

    /// Returns the raw token so the handler can forward it to the notification service.
    /// Returns None silently if the identifier doesn't exist — the handler must
    /// respond identically in both cases to prevent identifier enumeration.
    #[tracing::instrument(skip(self))]
    pub async fn execute(&self, identifier: &str) -> Result<Option<RawRecoveryToken>, CoreError> {
        let identity = match self.identity_repo.find_by_identifier(identifier).await {
            Some(i) => i,
            None => return Ok(None),
        };

        let user_id = Uuid::parse_str(&identity.id).map_err(|_| {
            CoreError::Invariant(InvariantError::inconsistent_state(
                "User ID in identity is not a valid UUID",
            ))
        })?;

        self.recovery_token_repo
            .invalidate_all_for_user(user_id)
            .await?;

        let raw = Self::generate_raw_token();
        let hash = Self::hash_token(raw.as_str());

        let now = Utc::now();
        let record = RecoveryToken {
            id: Uuid::new_v4(),
            user_id,
            token_hash: hash,
            expires_at: now + Duration::minutes(RECOVERY_TOKEN_TTL_MINUTES),
            used_at: None,
            created_at: now,
        };

        self.recovery_token_repo.create(&record).await?;

        Ok(Some(raw))
    }

    fn generate_raw_token() -> RawRecoveryToken {
        let mut bytes = [0u8; RECOVERY_TOKEN_BYTES];
        rand::rng().fill(&mut bytes);
        RawRecoveryToken(hex::encode(bytes))
    }

    fn hash_token(raw: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(raw.as_bytes());
        hex::encode(hasher.finalize())
    }
}
