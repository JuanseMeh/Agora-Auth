// Internal service token issuance DTOs
use serde::{Deserialize, Serialize};

/// Request to issue a service token (service-to-service authentication)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IssueServiceTokenRequest {
    /// Service identifier (e.g., "user_service")
    pub service_id: String,
    /// Service secret (will be validated against hashed secret)
    pub service_secret: String,
}

impl IssueServiceTokenRequest {
    /// Validate the request
    pub fn validate(&self) -> Result<(), String> {
        if self.service_id.is_empty() {
            return Err("Service ID cannot be empty".to_string());
        }

        if self.service_secret.is_empty() {
            return Err("Service secret cannot be empty".to_string());
        }

        Ok(())
    }
}

/// Response after service token issuance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueServiceTokenResponse {
    /// JWT token for service authentication
    pub access_token: String,
    /// Token expiration time in seconds
    pub expires_in: u64,
    /// Token type (always "Bearer")
    pub token_type: String,
}

