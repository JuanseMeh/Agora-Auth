// Internal session token issuance DTOs
use serde::{Deserialize, Serialize};

/// Request to issue session tokens for an identity
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IssueSessionTokensRequest {
    /// User ID (UUID) for which to issue tokens
    pub user_id: String,
}

impl IssueSessionTokensRequest {
    /// Validate the request
    pub fn validate(&self) -> Result<(), String> {
        if self.user_id.is_empty() {
            return Err("User ID cannot be empty".to_string());
        }

        // Validate UUID format
        if !uuid::Uuid::parse_str(&self.user_id).is_ok() {
            return Err("User ID must be a valid UUID".to_string());
        }

        Ok(())
    }
}

/// Response after session token issuance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueSessionTokensResponse {
    /// Access token for API authentication
    pub access_token: String,
    /// Refresh token for obtaining new access tokens
    pub refresh_token: String,
    /// Session ID for reference
    pub session_id: String,
    /// Access token expiration time in seconds
    pub expires_in: u64,
    /// Token type (always "Bearer")
    pub token_type: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_issue_session_tokens_request_validation_empty_user_id() {
        let req = IssueSessionTokensRequest {
            user_id: "".to_string(),
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn test_issue_session_tokens_request_validation_invalid_uuid() {
        let req = IssueSessionTokensRequest {
            user_id: "not-a-uuid".to_string(),
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn test_issue_session_tokens_request_validation_valid() {
        let req = IssueSessionTokensRequest {
            user_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn test_issue_session_tokens_response_serialization() {
        let resp = IssueSessionTokensResponse {
            access_token: "access_token_123".to_string(),
            refresh_token: "refresh_token_456".to_string(),
            session_id: "session_789".to_string(),
            expires_in: 3600,
            token_type: "Bearer".to_string(),
        };

        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("access_token"));
        assert!(json.contains("refresh_token"));
        assert!(json.contains("session_id"));
        assert!(json.contains("expires_in"));
        assert!(json.contains("token_type"));
    }

    #[test]
    fn test_issue_session_tokens_response_deserialization() {
        let json = r#"{
            "access_token": "access_token_123",
            "refresh_token": "refresh_token_456",
            "session_id": "session_789",
            "expires_in": 3600,
            "token_type": "Bearer"
        }"#;

        let resp: IssueSessionTokensResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.access_token, "access_token_123");
        assert_eq!(resp.refresh_token, "refresh_token_456");
        assert_eq!(resp.session_id, "session_789");
        assert_eq!(resp.expires_in, 3600);
        assert_eq!(resp.token_type, "Bearer");
    }
}

