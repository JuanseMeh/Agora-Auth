use chrono::Utc;
use hex;
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::core::error::CoreError;
use crate::core::usecases::ports::{
    credential_repository::CredentialRepository, password_hasher::PasswordHasher,
    recovery_token_repository::RecoveryTokenRepository,
};

pub struct ConfirmCredentialRecovery {
    credential_repo: Arc<dyn CredentialRepository + Send + Sync>,
    recovery_token_repo: Arc<dyn RecoveryTokenRepository + Send + Sync>,
    password_hasher: Arc<dyn PasswordHasher + Send + Sync>,
}

impl ConfirmCredentialRecovery {
    pub fn new(
        credential_repo: Arc<dyn CredentialRepository + Send + Sync>,
        recovery_token_repo: Arc<dyn RecoveryTokenRepository + Send + Sync>,
        password_hasher: Arc<dyn PasswordHasher + Send + Sync>,
    ) -> Self {
        Self {
            credential_repo,
            recovery_token_repo,
            password_hasher,
        }
    }

    #[tracing::instrument(skip(self, new_password))]
    pub async fn execute(&self, raw_token: &str, new_password: &str) -> Result<(), CoreError> {
        let token_hash = Self::hash_token(raw_token);

        let record = self
            .recovery_token_repo
            .find_by_hash(&token_hash)
            .await?
            .ok_or(CoreError::Authentication(
                crate::core::error::AuthenticationError::InvalidRecoveryToken,
            ))?;

        if !record.is_valid(Utc::now()) {
            return Err(CoreError::Authentication(
                crate::core::error::AuthenticationError::InvalidRecoveryToken,
            ));
        }

        // Hash the new password.
        let new_credential = self.password_hasher.hash(new_password);

        // Update credential with the new password.
        self.credential_repo
            .update_password(&record.user_id.to_string(), new_credential)
            .await;

        // Consume the token — single use.
        self.recovery_token_repo.mark_used(record.id).await?;

        Ok(())
    }

    fn hash_token(raw: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(raw.as_bytes());
        hex::encode(hasher.finalize())
    }
}
