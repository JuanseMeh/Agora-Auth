// Public token refresh DTO
use serde::{Deserialize, Serialize};

/// Request to refresh an access token
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RefreshTokenRequest {
    /// Refresh token
    pub refresh_token: String,
}

impl RefreshTokenRequest {
    /// Validate the request
    pub fn validate(&self) -> Result<(), String> {
        if self.refresh_token.is_empty() {
            return Err("Refresh token required".to_string());
        }

        Ok(())
    }
}

/// Response after token refresh
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenResponse {
    /// New access token (JWT)
    pub access_token: String,
    /// Token type (always "Bearer")
    pub token_type: String,
    /// Expiration in seconds
    pub expires_in: u64,
}
