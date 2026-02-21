//! Use case: IssueSession
//!
//! Orchestrates session creation with access and refresh token issuance.
//!
//! Responsibilities:
//! - Generate unique session ID
//! - Issue access token via TokenService
//! - Issue refresh token via TokenService
//! - Hash refresh token for storage
//! - Persist session to SessionRepository
//! - Return tokens and session metadata

use crate::core::error::CoreError;
use crate::core::identity::UserIdentity;
use crate::core::token::Token;
use crate::core::usecases::ports::{SessionRepository, TokenService};

/// Input contract for IssueSession use case.
pub struct IssueSessionInput {
    pub user: UserIdentity,
    pub ip_address: String,
    pub user_agent: String,
}

/// Output contract for IssueSession use case.
pub struct IssueSessionOutput {
    pub access_token: Token,
    pub refresh_token: Token,
    pub session_id: String,
    pub expires_in: u64,
}

/// Use case for issuing a new session with tokens.
pub struct IssueSession<'a> {
    session_repo: &'a dyn SessionRepository,
    token_service: &'a dyn TokenService,
    access_token_ttl_seconds: u64,
    refresh_token_ttl_days: u64,
}

impl<'a> IssueSession<'a> {
    /// Create a new IssueSession use case with dependencies.
    pub fn new(
        session_repo: &'a dyn SessionRepository,
        token_service: &'a dyn TokenService,
        access_token_ttl_seconds: u64,
        refresh_token_ttl_days: u64,
    ) -> Self {
        Self {
            session_repo,
            token_service,
            access_token_ttl_seconds,
            refresh_token_ttl_days,
        }
    }

    /// Execute the session issuance use case.
    pub fn execute(&self, input: IssueSessionInput) -> Result<IssueSessionOutput, CoreError> {
        // Step 1: Issue access token
        let access_token = self
            .token_service
            .issue_access_token(&input.user.id, &self.build_access_claims(&input.user));

        // Step 2: Issue refresh token
        let refresh_token = self
            .token_service
            .issue_refresh_token(&input.user.id, &self.build_refresh_claims(&input.user));

        // Step 3: Hash refresh token for storage
        let refresh_token_hash = self.hash_token(&refresh_token);

        // Step 4: Calculate expiration
        let _expires_at = chrono::Utc::now()
            + chrono::Duration::days(self.refresh_token_ttl_days as i64);

        // Step 5: Persist session
        self.session_repo.create_session(
            &input.user,
            &refresh_token_hash,
            &self.build_session_metadata(&input),
        );

        // Step 6: Generate session ID (UUID v7)
        let session_id = uuid::Uuid::new_v7(uuid::Timestamp::now(uuid::NoContext)).to_string();

        Ok(IssueSessionOutput {
            access_token,
            refresh_token,
            session_id,
            expires_in: self.access_token_ttl_seconds,
        })
    }

    fn build_access_claims(&self, user: &UserIdentity) -> String {
        // Build minimal claims for access token
        format!(
            r#"{{"sub":"{}","type":"access","exp":{}}}"#,
            user.id,
            chrono::Utc::now().timestamp() + self.access_token_ttl_seconds as i64
        )
    }

    fn build_refresh_claims(&self, user: &UserIdentity) -> String {
        // Build minimal claims for refresh token
        format!(
            r#"{{"sub":"{}","type":"refresh","exp":{}}}"#,
            user.id,
            chrono::Utc::now().timestamp() + (self.refresh_token_ttl_days * 86400) as i64
        )
    }

    fn build_session_metadata(&self, input: &IssueSessionInput) -> String {
        // Build session metadata JSON
        format!(
            r#"{{"ip":"{}","ua":"{}","created":"{}"}}"#,
            input.ip_address,
            input.user_agent,
            chrono::Utc::now().to_rfc3339()
        )
    }

    fn hash_token(&self, token: &Token) -> String {
        // Simple hash for refresh token storage
        // In production, use a proper hashing algorithm like SHA-256
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        token.value().hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }
}
