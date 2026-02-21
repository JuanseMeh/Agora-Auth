// Public token validation DTO
use serde::{Deserialize, Serialize};

/// Request to validate an access token
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TokenValidationRequest {
    /// Access token to validate
    pub token: String,
}

impl TokenValidationRequest {
    /// Validate the request
    pub fn validate(&self) -> Result<(), String> {
        if self.token.is_empty() {
            return Err("Token required".to_string());
        }

        Ok(())
    }
}

/// Response after token validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenValidationResponse {
    /// Authenticated user ID
    pub user_id: String,
    /// Session ID
    pub session_id: String,
}
