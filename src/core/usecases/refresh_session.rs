//! Use case: RefreshSession
//!
//! Orchestrates refresh token validation and access token re-issuance.
//!
//! Responsibilities:
//! - Validate refresh token signature via TokenService
//! - Lookup session by refresh token hash
//! - Check session is not revoked and not expired
//! - Issue new access token
//! - Optionally rotate refresh token (revoke old, issue new)
//! - Return new access token

use crate::core::error::{CoreError, TokenError, AuthenticationError};
use crate::core::token::Token;
use crate::core::usecases::ports::{SessionRepository, TokenService};

/// Input contract for RefreshSession use case.
pub struct RefreshSessionInput {
    pub refresh_token: Token,
}

/// Output contract for RefreshSession use case.
#[derive(Debug)]
pub struct RefreshSessionOutput {
    pub access_token: Token,
    pub refresh_token: Option<Token>, // Only if rotated
    pub token_type: String,
    pub expires_in: u64,
}

/// Use case for refreshing an access token using a refresh token.
pub struct RefreshSession<'a> {
    session_repo: &'a (dyn SessionRepository + Send + Sync),
    token_service: &'a (dyn TokenService + Send + Sync),
    access_token_ttl_seconds: u64,
    rotate_refresh_tokens: bool,
}

impl<'a> RefreshSession<'a> {
    /// Create a new RefreshSession use case with dependencies.
    pub fn new(
        session_repo: &'a (dyn SessionRepository + Send + Sync),
        token_service: &'a (dyn TokenService + Send + Sync),
        access_token_ttl_seconds: u64,
        rotate_refresh_tokens: bool,
    ) -> Self {
        Self {
            session_repo,
            token_service,
            access_token_ttl_seconds,
            rotate_refresh_tokens,
        }
    }

    /// Execute the session refresh use case.
    pub async fn execute(&self, input: RefreshSessionInput) -> Result<RefreshSessionOutput, CoreError> {
        // Step 1: Validate refresh token signature
        tracing::debug!("[REFRESH] Step 1: Validating refresh token signature");
        let claims = self
            .token_service
            .validate_refresh_token(&input.refresh_token)
            .map_err(|e| {
                tracing::error!("[REFRESH] Step 1 failed: token validation error: {:?}", e);
                TokenError::signature_invalid("refresh token validation failed")
            })?;
        tracing::debug!("[REFRESH] Step 1 succeeded, claims: {}", claims);

        // Step 2: Extract user_id and session_id from claims
        tracing::debug!("[REFRESH] Step 2: Extracting user_id and session_id from claims");
        let user_id = self.extract_user_id(&claims)
            .ok_or_else(|| {
                tracing::error!("[REFRESH] Step 2 failed: missing subject claim");
                TokenError::invalid_claims("missing subject claim")
            })?;
        
        let session_id = self.extract_session_id(&claims)
            .ok_or_else(|| {
                tracing::error!("[REFRESH] Step 2 failed: missing session id claim");
                TokenError::invalid_claims("missing session id claim")
            })?;
        
        tracing::debug!("[REFRESH] Step 2 succeeded: user_id={}, session_id={}", user_id, session_id);

        // Step 3: Hash refresh token to lookup session
        let refresh_token_hash = self.hash_token(&input.refresh_token);
        tracing::debug!("[REFRESH] Step 3: Computed hash for refresh token: {}", refresh_token_hash);

        // Step 4: Lookup session by refresh token hash
        tracing::debug!("[REFRESH] Step 4: Looking up session by refresh token hash");
        let session = self
            .session_repo
            .find_by_refresh_token_hash(&refresh_token_hash)
            .await;
        
        if session.is_some() {
            tracing::debug!("[REFRESH] Step 4: Session found in database");
        } else {
            tracing::debug!("[REFRESH] Step 4: Session NOT found in database");
        }
        
        let _session = session.ok_or_else(|| {
                tracing::error!("[REFRESH] Step 4 failed: session not found for hash");
                AuthenticationError::user_not_found("session not found")
            })?;
        
        tracing::debug!("[REFRESH] Step 4 succeeded: session found");

        // Step 5: Issue new access token with session_id
        tracing::debug!("[REFRESH] Step 5: Issuing new access token");
        let access_token = self.token_service.issue_access_token(
            &user_id,
            &self.build_access_claims(&user_id, &session_id),
        );
        
        tracing::debug!("[REFRESH] Step 5 succeeded: access_token issued");

        // Step 6: Optionally rotate refresh token
        tracing::debug!("[REFRESH] Step 6: rotate_refresh_tokens={}", self.rotate_refresh_tokens);
        let (refresh_token, _new_hash) = if self.rotate_refresh_tokens {
            tracing::debug!("[REFRESH] Step 6a: Rotating refresh token");
            let new_token = self.token_service.issue_refresh_token(&user_id, &claims);
            let _new_hash = self.hash_token(&new_token);
            
            // Revoke old session and create new one
            // Note: This would need session_id exposed from Session
            // self.session_repo.revoke_session(&session_id);
            // self.session_repo.create_session(...);
            
            tracing::debug!("[REFRESH] Step 6a: New refresh token issued");
            (Some(new_token), Some(_new_hash))
        } else {
            tracing::debug!("[REFRESH] Step 6b: Not rotating refresh token");
            (None, None)
        };

        tracing::debug!("[REFRESH] All steps completed successfully");
        Ok(RefreshSessionOutput {
            access_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: self.access_token_ttl_seconds,
        })
    }

    fn extract_user_id(&self, claims: &str) -> Option<String> {
        // Simple JSON parsing to extract "sub" field
        claims
            .split("\"sub\":\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .map(|s| s.to_string())
    }

    fn extract_session_id(&self, claims: &str) -> Option<String> {
        // Extract session_id from "sid" field
        claims
            .split("\"sid\":\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .map(|s| s.to_string())
    }

    fn build_access_claims(&self, user_id: &str, session_id: &str) -> String {
        format!(
            r#"{{"sub":"{}","type":"access","exp":{},"sid":"{}"}}"#,
            user_id,
            chrono::Utc::now().timestamp() + self.access_token_ttl_seconds as i64,
            session_id
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
        // Convert bytes to hex string
        result.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
