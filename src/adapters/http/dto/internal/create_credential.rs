// Internal credential creation DTO
use serde::{Deserialize, Serialize};

/// Request to create a new credential (internal service)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CreateCredentialRequest {
    /// User identifier (username, email, etc.)
    pub identifier: String,
    /// Raw password
    pub password: String,
}

impl CreateCredentialRequest {
    /// Validate the request
    pub fn validate(&self) -> Result<(), String> {
        if self.identifier.is_empty() {
            return Err("Identifier cannot be empty".to_string());
        }

        if self.password.is_empty() {
            return Err("Password cannot be empty".to_string());
        }

        if self.identifier.len() > 255 {
            return Err("Identifier too long (max 255 characters)".to_string());
        }

        if self.password.len() < 8 {
            return Err("Password too weak (min 8 characters)".to_string());
        }

        Ok(())
    }
}

/// Response after credential creation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCredentialResponse {
    /// The created user ID
    pub user_id: String,
    /// The identifier used
    pub identifier: String,
    /// Creation timestamp (ISO 8601)
    pub created_at: String,
}