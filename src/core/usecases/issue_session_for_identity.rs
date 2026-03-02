//! Use case: IssueSessionForIdentity
//!
//! Orchestrates session creation for an existing identity (internal service use).
//!
//! Responsibilities:
//! - Validate identity exists via IdentityRepository
//! - Issue session tokens via IssueSession primitive
//! - Track which service issued the session (for audit)
//! - Return tokens and session metadata

use crate::core::error::CoreError;
use crate::core::identity::UserIdentity;
use crate::core::usecases::ports::{IdentityRepository, SessionRepository, TokenService};

/// Input contract for IssueSessionForIdentity use case.
pub struct IssueSessionForIdentityInput {
    /// User ID (UUID) for which to issue session tokens
    pub user_id: String,
    /// Optional service ID that requested the token issuance (for audit)
    pub issued_by_service_id: Option<String>,
}

/// Output contract for IssueSessionForIdentity use case.
#[derive(Debug)]
pub struct IssueSessionForIdentityOutput {
    /// Access token for API authentication
    pub access_token: String,
    /// Refresh token for obtaining new access tokens
    pub refresh_token: String,
    /// Session ID for reference
    pub session_id: String,
    /// Access token expiration time in seconds
    pub expires_in: u64,
}

/// Use case for issuing session tokens for an existing identity.
pub struct IssueSessionForIdentity<'a> {
    identity_repository: &'a (dyn IdentityRepository + Send + Sync),
    session_repository: &'a (dyn SessionRepository + Send + Sync),
    token_service: &'a (dyn TokenService + Send + Sync),
    access_token_ttl_seconds: u64,
    refresh_token_ttl_days: u64,
}

impl<'a> IssueSessionForIdentity<'a> {
    /// Create a new IssueSessionForIdentity use case with dependencies.
    pub fn new(
        identity_repository: &'a (dyn IdentityRepository + Send + Sync),
        session_repository: &'a (dyn SessionRepository + Send + Sync),
        token_service: &'a (dyn TokenService + Send + Sync),
        access_token_ttl_seconds: u64,
        refresh_token_ttl_days: u64,
    ) -> Self {
        Self {
            identity_repository,
            session_repository,
            token_service,
            access_token_ttl_seconds,
            refresh_token_ttl_days,
        }
    }

    /// Execute the session issuance for identity use case.
    pub async fn execute(
        &self,
        input: IssueSessionForIdentityInput,
    ) -> Result<IssueSessionForIdentityOutput, CoreError> {
        tracing::debug!(
            "[ISSUE_SESSION_FOR_IDENTITY] Looking up identity: user_id={}",
            input.user_id
        );

        // Step 1: Validate identity exists
        let identity = self
            .identity_repository
            .find_by_id(&input.user_id)
            .await;

        let identity = match identity {
            Some(identity) => identity,
            None => {
                tracing::warn!(
                    "[ISSUE_SESSION_FOR_IDENTITY] Identity not found: {}",
                    input.user_id
                );
                return Err(CoreError::Authentication(
                    crate::core::error::AuthenticationError::UserNotFound {
                        reason: format!("User with ID {} not found", input.user_id),
                    },
                ));
            }
        };

        tracing::debug!(
            "[ISSUE_SESSION_FOR_IDENTITY] Identity found: {}",
            identity.id
        );

        // Step 2: Generate session ID
        let session_id = uuid::Uuid::new_v7(uuid::Timestamp::now(uuid::NoContext)).to_string();
        tracing::debug!(
            "[ISSUE_SESSION_FOR_IDENTITY] Generated session_id={}",
            session_id
        );

        // Step 3: Issue access token
        let access_token = self
            .token_service
            .issue_access_token(&identity.id, &self.build_access_claims(&identity, &session_id));

        tracing::debug!("[ISSUE_SESSION_FOR_IDENTITY] Access token issued");

        // Step 4: Issue refresh token
        let refresh_token = self.token_service.issue_refresh_token(
            &identity.id,
            &self.build_refresh_claims(&identity, &session_id),
        );

        tracing::debug!("[ISSUE_SESSION_FOR_IDENTITY] Refresh token issued");

        // Step 5: Hash refresh token for storage
        let refresh_token_hash = self.hash_token(&refresh_token);
        tracing::debug!(
            "[ISSUE_SESSION_FOR_IDENTITY] Refresh token hashed: {}",
            refresh_token_hash
        );

        // Step 6: Build session metadata including service that issued the token
        let metadata = self.build_session_metadata(input.issued_by_service_id.as_deref());

        // Step 7: Persist session
        self.session_repository
            .create_session(&session_id, &identity, &refresh_token_hash, &metadata)
            .await;

        tracing::info!(
            "[ISSUE_SESSION_FOR_IDENTITY] Session created successfully for user: {}",
            input.user_id
        );

        Ok(IssueSessionForIdentityOutput {
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
        let result = hasher.finalize();
        hex::encode(result)
    }
}
