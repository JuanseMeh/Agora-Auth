//! Use case: IssueSessionForExternalIdentity
//!
//! Issues session tokens for a user who authenticated via an external provider
//! (Google OAuth, etc.) and has NO row in identity_credential.
//!
//! Unlike IssueSessionForIdentity, this use case does NOT query identity_credential.
//! The user_id is already verified upstream:
//! - Login path: find_by_provider_user returned it from external_identities
//! - Registration path: user_service just created the user and returned the UUID
//!
//! Responsibilities:
//! - Accept a verified user_id directly
//! - Issue access + refresh tokens
//! - Persist session
//! - Return tokens and session metadata

use uuid::Uuid;
use crate::core::error::CoreError;
use crate::core::identity::UserIdentity;
use crate::core::usecases::ports::{SessionRepository, TokenService};

pub struct IssueSessionForExternalIdentityInput {
    /// Verified user ID — caller is responsible for ensuring this user exists
    pub user_id: Uuid,
    /// Optional service ID for audit trail
    pub issued_by_service_id: Option<String>,
}

#[derive(Debug)]
pub struct IssueSessionForExternalIdentityOutput {
    pub access_token: String,
    pub refresh_token: String,
    pub session_id: String,
    pub expires_in: u64,
}

pub struct IssueSessionForExternalIdentity<'a> {
    session_repository: &'a (dyn SessionRepository + Send + Sync),
    token_service: &'a (dyn TokenService + Send + Sync),
    access_token_ttl_seconds: u64,
    refresh_token_ttl_days: u64,
}

impl<'a> IssueSessionForExternalIdentity<'a> {
    pub fn new(
        session_repository: &'a (dyn SessionRepository + Send + Sync),
        token_service: &'a (dyn TokenService + Send + Sync),
        access_token_ttl_seconds: u64,
        refresh_token_ttl_days: u64,
    ) -> Self {
        Self {
            session_repository,
            token_service,
            access_token_ttl_seconds,
            refresh_token_ttl_days,
        }
    }

    pub async fn execute(
        &self,
        input: IssueSessionForExternalIdentityInput,
    ) -> Result<IssueSessionForExternalIdentityOutput, CoreError> {
        let user_id_str = input.user_id.to_string();

        tracing::debug!(
            "[ISSUE_SESSION_FOR_EXTERNAL_IDENTITY] Issuing session for user_id={}",
            user_id_str
        );

        // Build a UserIdentity directly from the verified user_id —
        // no DB lookup needed, caller already verified this user exists
        let identity = UserIdentity::new(user_id_str.clone());

        // Generate session ID
        let session_id = Uuid::new_v7(uuid::Timestamp::now(uuid::NoContext)).to_string();

        // Issue tokens
        let access_token = self.token_service.issue_access_token(
            &user_id_str,
            &self.build_access_claims(&identity, &session_id),
        );

        let refresh_token = self.token_service.issue_refresh_token(
            &user_id_str,
            &self.build_refresh_claims(&identity, &session_id),
        );

        // Hash refresh token for storage
        let refresh_token_hash = self.hash_token(&refresh_token);

        // Build session metadata
        let metadata = self.build_session_metadata(input.issued_by_service_id.as_deref());

        // Persist session
        self.session_repository
            .create_session(&session_id, &identity, &refresh_token_hash, &metadata)
            .await;

        tracing::info!(
            "[ISSUE_SESSION_FOR_EXTERNAL_IDENTITY] Session created for user_id={}",
            user_id_str
        );

        Ok(IssueSessionForExternalIdentityOutput {
            access_token: access_token.value().to_string(),
            refresh_token: refresh_token.value().to_string(),
            session_id,
            expires_in: self.access_token_ttl_seconds,
        })
    }

    fn build_access_claims(&self, user: &UserIdentity, session_id: &str) -> String {
        format!(
            r#"{{"sub":"{}","type":"access","exp":{},"sid":"{}"}}"#,
            user.id,
            chrono::Utc::now().timestamp() + self.access_token_ttl_seconds as i64,
            session_id
        )
    }

    fn build_refresh_claims(&self, user: &UserIdentity, session_id: &str) -> String {
        format!(
            r#"{{"sub":"{}","type":"refresh","exp":{},"sid":"{}"}}"#,
            user.id,
            chrono::Utc::now().timestamp() + (self.refresh_token_ttl_days * 86400) as i64,
            session_id
        )
    }

    fn build_session_metadata(&self, issued_by_service_id: Option<&str>) -> String {
        let service_info = if let Some(service_id) = issued_by_service_id {
            format!(r#","issued_by_service":"{}""#, service_id)
        } else {
            String::new()
        };
        format!(
            r#"{{"created":"{}"{}}}"#,
            chrono::Utc::now().to_rfc3339(),
            service_info
        )
    }

    fn hash_token(&self, token: &crate::core::token::Token) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(token.value().as_bytes());
        hex::encode(hasher.finalize())
    }
}