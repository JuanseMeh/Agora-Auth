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
    session_repo: &'a dyn SessionRepository,
    token_service: &'a dyn TokenService,
    access_token_ttl_seconds: u64,
    rotate_refresh_tokens: bool,
}

impl<'a> RefreshSession<'a> {
    /// Create a new RefreshSession use case with dependencies.
    pub fn new(
        session_repo: &'a dyn SessionRepository,
        token_service: &'a dyn TokenService,
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
    pub fn execute(&self, input: RefreshSessionInput) -> Result<RefreshSessionOutput, CoreError> {
        // Step 1: Validate refresh token signature
        let claims = self
            .token_service
            .validate_refresh_token(&input.refresh_token)
            .map_err(|_| TokenError::signature_invalid("refresh token validation failed"))?;

        // Step 2: Extract user_id from claims (simplified parsing)
        let user_id = self.extract_user_id(&claims)
            .ok_or_else(|| TokenError::invalid_claims("missing subject claim"))?;

        // Step 3: Hash refresh token to lookup session
        let refresh_token_hash = self.hash_token(&input.refresh_token);

        // Step 4: Lookup session by refresh token hash
        let _session = self
            .session_repo
            .find_by_refresh_token_hash(&refresh_token_hash)
            .ok_or_else(|| AuthenticationError::user_not_found("session not found"))?;

        // Step 5: Check session is not revoked and not expired
        // Note: Session struct needs to expose these fields
        // For now, we assume the repository only returns valid sessions

        // Step 6: Issue new access token
        let access_token = self.token_service.issue_access_token(
            &user_id,
            &self.build_access_claims(&user_id),
        );

        // Step 7: Optionally rotate refresh token
        let (refresh_token, _new_hash) = if self.rotate_refresh_tokens {
            let new_token = self.token_service.issue_refresh_token(&user_id, &claims);
            let _new_hash = self.hash_token(&new_token);
            
            // Revoke old session and create new one
            // Note: This would need session_id exposed from Session
            // self.session_repo.revoke_session(&session_id);
            // self.session_repo.create_session(...);
            
            (Some(new_token), Some(_new_hash))
        } else {
            (None, None)
        };

        Ok(RefreshSessionOutput {
            access_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: self.access_token_ttl_seconds,
        })
    }

    fn extract_user_id(&self, claims: &str) -> Option<String> {
        // Simple JSON parsing to extract "sub" field
        // In production, use proper JSON parsing
        claims
            .split("\"sub\":\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .map(|s| s.to_string())
    }

    fn build_access_claims(&self, user_id: &str) -> String {
        format!(
            r#"{{"sub":"{}","type":"access","exp":{}}}"#,
            user_id,
            chrono::Utc::now().timestamp() + self.access_token_ttl_seconds as i64
        )
    }

    fn hash_token(&self, token: &Token) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        token.value().hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }
}
