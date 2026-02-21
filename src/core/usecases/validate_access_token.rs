//! Use case: ValidateAccessToken
//!
//! Orchestrates access token validation and domain error mapping.
//!
//! Responsibilities:
//! - Delegate to TokenService for signature validation
//! - Map failure to domain error
//! - Optionally check password version
//! - If password_changed_at > token.issued_at → token invalid

use crate::core::error::CoreError;
use crate::core::token::Token;
use crate::core::usecases::ports::TokenService;

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
    token_service: &'a dyn TokenService,
}

impl<'a> ValidateAccessToken<'a> {
    /// Create a new ValidateAccessToken use case with dependencies.
    pub fn new(token_service: &'a dyn TokenService) -> Self {
        Self { token_service }
    }

    /// Execute the access token validation use case.
    pub fn execute(&self, input: ValidateAccessTokenInput) -> Result<ValidateAccessTokenOutput, CoreError> {
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

        // Step 5: Return successful validation
        Ok(ValidateAccessTokenOutput {
            valid: true,
            user_id,
            session_id,
            reason: None,
        })
    }

    fn extract_user_id(&self, claims: &str) -> Option<String> {
        claims
            .split("\"sub\":\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .map(|s| s.to_string())
    }

    fn extract_session_id(&self, claims: &str) -> Option<String> {
        claims
            .split("\"sid\":\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .map(|s| s.to_string())
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
        if let Some(exp_part) = claims.split("\"exp\":").nth(1) {
            // Split by either comma or closing brace to get the exp value
            let exp_str = exp_part
                .split(|c| c == ',' || c == '}')
                .next()
                .unwrap_or(exp_part);
            if let Ok(exp) = exp_str.trim().parse::<i64>() {
                let now = chrono::Utc::now().timestamp();
                return now > exp;
            }
        }
        true // If we can't parse, consider it expired
    }
}
