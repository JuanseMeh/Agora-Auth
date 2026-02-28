//! Use case: ValidateAccessToken
//!
//! Orchestrates access token validation and domain error mapping.
//!
//! Responsibilities:
//! - Delegate to TokenService for signature validation
//! - Map failure to domain error
//! - Optionally check password version
//! - If password_changed_at > token.issued_at → token invalid
//! - Validate session is active in the database

use crate::core::error::CoreError;
use crate::core::token::Token;
use crate::core::usecases::ports::{TokenService, SessionRepository};

/// Input contract for ValidateAccessToken use case.
pub struct ValidateAccessTokenInput {
    pub access_token: Token,
}

/// Output contract for ValidateAccessToken use case.
pub struct ValidateAccessTokenOutput {
    pub valid: bool,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub reason: Option<String>,
}

/// Use case for validating an access token.
pub struct ValidateAccessToken<'a> {
    token_service: &'a (dyn TokenService + Send + Sync),
    session_repository: &'a (dyn SessionRepository + Send + Sync),
}

impl<'a> ValidateAccessToken<'a> {
    /// Create a new ValidateAccessToken use case with dependencies.
    pub fn new(
        token_service: &'a (dyn TokenService + Send + Sync),
        session_repository: &'a (dyn SessionRepository + Send + Sync),
    ) -> Self {
        Self { token_service, session_repository }
    }

    /// Execute the access token validation use case.
    pub async fn execute(&self, input: ValidateAccessTokenInput) -> Result<ValidateAccessTokenOutput, CoreError> {
        // Step 1: Validate token signature via TokenService
        let claims = match self.token_service.validate_access_token(&input.access_token) {
            Ok(claims) => claims,
            Err(_) => {
                return Ok(ValidateAccessTokenOutput {
                    valid: false,
                    user_id: None,
                    session_id: None,
                    reason: Some("token signature invalid".to_string()),
                });
            }
        };

        // Step 2: Parse claims to extract user_id and session_id
        let user_id = self.extract_user_id(&claims);
        let session_id = self.extract_session_id(&claims);

        // Step 3: Check token type is "access"
        let token_type = self.extract_token_type(&claims);
        if token_type.as_deref() != Some("access") {
            return Ok(ValidateAccessTokenOutput {
                valid: false,
                user_id,
                session_id,
                reason: Some("invalid token type".to_string()),
            });
        }

        // Step 4: Check expiration (TokenService should handle this, but double-check)
        if self.is_expired(&claims) {
            return Ok(ValidateAccessTokenOutput {
                valid: false,
                user_id,
                session_id,
                reason: Some("token expired".to_string()),
            });
        }

        // Step 5: Validate session is active in the database
        if let Some(ref sid) = session_id {
            let session = self.session_repository.find_by_id(sid).await;
            match session {
                Some(_) => {
                    // Session is active - validation successful
                }
                None => {
                    return Ok(ValidateAccessTokenOutput {
                        valid: false,
                        user_id,
                        session_id,
                        reason: Some("session revoked or expired".to_string()),
                    });
                }
            }
        } else {
            // No session_id in token - this could be a token without session
            // For now, we'll allow this but you might want to reject it depending on requirements
            tracing::warn!("Access token has no session_id - allowing without session validation");
        }

        // Step 6: Return successful validation
        Ok(ValidateAccessTokenOutput {
            valid: true,
            user_id,
            session_id,
            reason: None,
        })
    }

    fn extract_user_id(&self, claims: &str) -> Option<String> {
        // Try "sub" first (from JWT standard claims), fallback to "user_id" (from IdentityClaims)
        claims
            .split("\"sub\":\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .map(|s| s.to_string())
            .or_else(|| {
                claims
                    .split("\"user_id\":\"")
                    .nth(1)
                    .and_then(|s| s.split('"').next())
                    .map(|s| s.to_string())
            })
    }

    fn extract_session_id(&self, claims: &str) -> Option<String> {
        claims
            .split("\"sid\":\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .map(|s| s.to_string())
    }

    /// Extract exp timestamp from claims JSON
    fn extract_exp(&self, claims: &str) -> Option<i64> {
        claims
            .split("\"exp\":")
            .nth(1)
            .and_then(|s| s.split(|c| c == ',' || c == '}').next())
            .and_then(|s| s.trim().parse::<i64>().ok())
    }

    fn extract_token_type(&self, claims: &str) -> Option<String> {
        claims
            .split("\"type\":\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .map(|s| s.to_string())
    }

    fn is_expired(&self, claims: &str) -> bool {
        // Extract exp claim and compare to current time
        if let Some(exp) = self.extract_exp(claims) {
            let now = chrono::Utc::now().timestamp();
            return now > exp;
        }
        true // If we can't parse, consider it expired
    }
}
