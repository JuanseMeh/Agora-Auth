// Tests for issue_service_token handler - focused on DTO validation and serialization

use crate::adapters::http::dto::internal::{IssueServiceTokenRequest, IssueServiceTokenResponse};

// ============================================================================
// Test Cases
// ============================================================================

#[test]
fn test_issue_service_token_valid_request() {
    // Test that a valid request passes validation
    let request = IssueServiceTokenRequest {
        service_id: "user_service".to_string(),
        service_secret: "correct_secret".to_string(),
    };

    let validation_result = request.validate();
    assert!(validation_result.is_ok(), "Valid request should pass validation");
}

#[test]
fn test_issue_service_token_empty_service_id() {
    // Test validation failure for empty service ID
    let request = IssueServiceTokenRequest {
        service_id: "".to_string(),
        service_secret: "some_secret".to_string(),
    };

    let validation_result = request.validate();
    assert!(validation_result.is_err(), "Empty service_id should fail validation");
    assert!(validation_result.unwrap_err().contains("Service ID"));
}

#[test]
fn test_issue_service_token_empty_secret() {
    // Test validation failure for empty service secret
    let request = IssueServiceTokenRequest {
        service_id: "user_service".to_string(),
        service_secret: "".to_string(),
    };

    let validation_result = request.validate();
    assert!(validation_result.is_err(), "Empty secret should fail validation");
    assert!(validation_result.unwrap_err().contains("Service secret"));
}

#[test]
fn test_issue_service_token_request_serialization() {
    // Test serialization/deserialization of the request
    let request = IssueServiceTokenRequest {
        service_id: "user_service".to_string(),
        service_secret: "my_secret".to_string(),
    };

    // Serialize to JSON
    let json = serde_json::to_string(&request).unwrap();
    assert!(json.contains("user_service"));
    assert!(json.contains("my_secret"));

    // Deserialize back
    let parsed: IssueServiceTokenRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.service_id, "user_service");
    assert_eq!(parsed.service_secret, "my_secret");
}

#[test]
fn test_issue_service_token_response_structure() {
    // Test that IssueServiceTokenResponse has the correct structure
    let response = IssueServiceTokenResponse {
        access_token: "test_token".to_string(),
        expires_in: 3600,
        token_type: "Bearer".to_string(),
    };

    // Verify all fields are present and have expected values
    assert_eq!(response.access_token, "test_token");
    assert_eq!(response.expires_in, 3600);
    assert_eq!(response.token_type, "Bearer");
}

#[test]
fn test_issue_service_token_response_serialization() {
    // Test serialization of the response
    let response = IssueServiceTokenResponse {
        access_token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9".to_string(),
        expires_in: 3600,
        token_type: "Bearer".to_string(),
    };

    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("access_token"));
    assert!(json.contains("expires_in"));
    assert!(json.contains("token_type"));
    assert!(json.contains("Bearer"));

    // Deserialize back
    let parsed: IssueServiceTokenResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.token_type, "Bearer");
    assert_eq!(parsed.expires_in, 3600);
}

#[test]
fn test_issue_service_token_response_deserialization() {
    // Test deserialization of the response
    let json = r#"{
        "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc123",
        "expires_in": 1800,
        "token_type": "Bearer"
    }"#;

    let parsed: IssueServiceTokenResponse = serde_json::from_str(json).unwrap();
    assert_eq!(parsed.access_token, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc123");
    assert_eq!(parsed.expires_in, 1800);
    assert_eq!(parsed.token_type, "Bearer");
}
