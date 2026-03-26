use serde::{Deserialize, Serialize};

/// Request for Google OAuth code exchange endpoint
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GoogleCodeExchangeRequest {
    /// OAuth authorization code from Google redirect
    pub code: String,
    /// CSRF state parameter (optional)
    pub state: Option<String>,
}

impl GoogleCodeExchangeRequest {
    pub fn validate(&self) -> Result<(), String> {
        if self.code.trim().is_empty() {
            return Err("Authorization code required".to_string());
        }
        Ok(())
    }
}

/// Response after successful Google code exchange (matches AuthenticateResponse pattern)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoogleCodeExchangeResponse {
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
