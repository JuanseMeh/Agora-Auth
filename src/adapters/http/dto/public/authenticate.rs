// Public authentication DTO
use serde::{Deserialize, Serialize};

/// Request to authenticate a user
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthenticateRequest {
    /// User identifier (username, email, etc.)
    pub identifier: String,
    /// Password
    pub password: String,
}

impl AuthenticateRequest {
    /// Validate the request
    pub fn validate(&self) -> Result<(), String> {
        if self.identifier.is_empty() {
            return Err("Identifier required".to_string());
        }

        if self.password.is_empty() {
            return Err("Password required".to_string());
        }

        Ok(())
    }
}

/// Response after successful authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticateResponse {
    /// Access token (JWT)
    pub access_token: String,
    /// Refresh token
    pub refresh_token: String,
    /// Token type (always "Bearer")
    pub token_type: String,
    /// Expiration in seconds
    pub expires_in: u64,
    /// Session ID
    pub session_id: String,
}
