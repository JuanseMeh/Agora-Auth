//! Logout DTOs

use serde::{Deserialize, Serialize};

/// Request to logout a user
#[derive(Debug, Deserialize, Serialize)]
pub struct LogoutRequest {
    /// Session ID to revoke (optional - if not provided, will use refresh token)
    pub session_id: Option<String>,
    /// Refresh token to revoke (optional - if not provided, will use session_id)
    pub refresh_token: Option<String>,
}

impl LogoutRequest {
    /// Validate the request
    pub fn validate(&self) -> Result<(), String> {
        // At least one of session_id or refresh_token must be provided
        if self.session_id.is_none() && self.refresh_token.is_none() {
            return Err("either session_id or refresh_token must be provided".to_string());
        }
        Ok(())
    }
}

/// Response after logout
#[derive(Debug, Serialize, Deserialize)]
pub struct LogoutResponse {
    /// Whether the logout was successful
    pub success: bool,
    /// Message describing the result
    pub message: String,
    /// Session ID that was revoked
    pub session_id: Option<String>,
}
