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
    session_repo: &'a (dyn SessionRepository + Send + Sync),
    token_service: &'a (dyn TokenService + Send + Sync),
    access_token_ttl_seconds: u64,
    refresh_token_ttl_days: u64,
}

impl<'a> IssueSession<'a> {
    /// Create a new IssueSession use case with dependencies.
    pub fn new(
        session_repo: &'a (dyn SessionRepository + Send + Sync),
        token_service: &'a (dyn TokenService + Send + Sync),
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
    pub async fn execute(&self, input: IssueSessionInput) -> Result<IssueSessionOutput, CoreError> {
        // Step 1: Generate v7) FIRST - needed for token session ID (UUID claims
        tracing::debug!("[ISSUE] Step 1: Generating session ID");
        let session_id = uuid::Uuid::new_v7(uuid::Timestamp::now(uuid::NoContext)).to_string();
        tracing::debug!("[ISSUE] Generated session_id={}", session_id);

        // Step 2: Issue access token with session_id in claims
        tracing::debug!("[ISSUE] Step 2: Issuing access token");
        let access_token = self
            .token_service
            .issue_access_token(&input.user.id, &self.build_access_claims(&input.user, &session_id));

        // Step 3: Issue refresh token with session_id in claims
        tracing::debug!("[ISSUE] Step 3: Issuing refresh token");
        let refresh_token = self
            .token_service
            .issue_refresh_token(&input.user.id, &self.build_refresh_claims(&input.user, &session_id));
        
        tracing::debug!("[ISSUE] Refresh token value: {}", refresh_token.value());

        // Step 4: Hash refresh token for storage
        tracing::debug!("[ISSUE] Step 4: Hashing refresh token");
        let refresh_token_hash = self.hash_token(&refresh_token);
        tracing::debug!("[ISSUE] Computed hash: {}", refresh_token_hash);

        // Step 5: Calculate expiration
        let _expires_at = chrono::Utc::now()
            + chrono::Duration::days(self.refresh_token_ttl_days as i64);

        // Step 6: Persist session
        tracing::debug!("[ISSUE] Step 6: Persisting session to database");
        self.session_repo.create_session(
            &session_id,
            &input.user,
            &refresh_token_hash,
            &self.build_session_metadata(&input),
        ).await;
        
        tracing::debug!("[ISSUE] Session created successfully");

        Ok(IssueSessionOutput {
            access_token,
            refresh_token,
            session_id,
            expires_in: self.access_token_ttl_seconds,
        })
    }

    fn build_access_claims(&self, user: &UserIdentity, session_id: &str) -> String {
        // Build claims for access token including session_id
        format!(
            r#"{{"sub":"{}","type":"access","exp":{},"sid":"{}"}}"#,
            user.id,
            chrono::Utc::now().timestamp() + self.access_token_ttl_seconds as i64,
            session_id
        )
    }

    fn build_refresh_claims(&self, user: &UserIdentity, session_id: &str) -> String {
        // Build claims for refresh token including session_id
        format!(
            r#"{{"sub":"{}","type":"refresh","exp":{},"sid":"{}"}}"#,
            user.id,
            chrono::Utc::now().timestamp() + (self.refresh_token_ttl_days * 86400) as i64,
            session_id
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
        // Use SHA-256 for deterministic hashing
        // This is critical: DefaultHasher uses SipHash which is non-deterministic
        // across program executions, causing session lookup to fail
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(token.value().as_bytes());
        let result = hasher.finalize();
        hex::encode(result)
    }
}
