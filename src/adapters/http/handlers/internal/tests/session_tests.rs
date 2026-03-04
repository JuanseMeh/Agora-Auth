// Tests for issue_session_tokens handler - focused on DTO validation and serialization

use crate::adapters::http::dto::internal::{IssueSessionTokensRequest, IssueSessionTokensResponse};

// ============================================================================
// Test Cases
// ============================================================================

#[test]
fn test_issue_session_tokens_valid_request() {
    // Test that a valid request passes validation
    let request = IssueSessionTokensRequest {
        user_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
    };

    let validation_result = request.validate();
    assert!(validation_result.is_ok(), "Valid UUID should pass validation");
}

#[test]
fn test_issue_session_tokens_empty_user_id() {
    // Test validation failure for empty user ID
    let request = IssueSessionTokensRequest {
        user_id: "".to_string(),
    };

    let validation_result = request.validate();
    assert!(validation_result.is_err(), "Empty user_id should fail validation");
    assert!(validation_result.unwrap_err().contains("User ID"));
}

#[test]
fn test_issue_session_tokens_invalid_uuid() {
    // Test validation failure for invalid UUID format
    let request = IssueSessionTokensRequest {
        user_id: "not-a-uuid".to_string(),
    };

    let validation_result = request.validate();
    assert!(validation_result.is_err(), "Invalid UUID should fail validation");
    assert!(validation_result.unwrap_err().contains("UUID"));
}

#[test]
fn test_issue_session_tokens_valid_uuid_formats() {
    // Test various valid UUID formats
    let valid_uuids = vec![
        "550e8400-e29b-41d4-a716-446655440000",
        "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
        "6ba7b811-9dad-11d1-80b4-00c04fd430c8",
    ];

    for uuid in valid_uuids {
        let request = IssueSessionTokensRequest {
            user_id: uuid.to_string(),
        };
        assert!(
            request.validate().is_ok(),
            "UUID {} should be valid",
            uuid
        );
    }
}

#[test]
fn test_issue_session_tokens_request_serialization() {
    // Test serialization/deserialization of the request
    let request = IssueSessionTokensRequest {
        user_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
    };

    // Serialize to JSON
    let json = serde_json::to_string(&request).unwrap();
    assert!(json.contains("550e8400-e29b-41d4-a716-446655440000"));

    // Deserialize back
    let parsed: IssueSessionTokensRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.user_id, "550e8400-e29b-41d4-a716-446655440000");
}

#[test]
fn test_issue_session_tokens_response_structure() {
    // Test that IssueSessionTokensResponse has the correct structure
    let response = IssueSessionTokensResponse {
        access_token: "test_access_token".to_string(),
        refresh_token: "test_refresh_token".to_string(),
        session_id: "test_session_id".to_string(),
        expires_in: 3600,
        token_type: "Bearer".to_string(),
    };

    // Verify all fields are present and have expected values
    assert_eq!(response.access_token, "test_access_token");
    assert_eq!(response.refresh_token, "test_refresh_token");
    assert_eq!(response.session_id, "test_session_id");
    assert_eq!(response.expires_in, 3600);
    assert_eq!(response.token_type, "Bearer");
}

#[test]
fn test_issue_session_tokens_response_serialization() {
    // Test serialization of the response
    let response = IssueSessionTokensResponse {
        access_token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.access".to_string(),
        refresh_token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.refresh".to_string(),
        session_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        expires_in: 3600,
        token_type: "Bearer".to_string(),
    };

    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("access_token"));
    assert!(json.contains("refresh_token"));
    assert!(json.contains("session_id"));
    assert!(json.contains("expires_in"));
    assert!(json.contains("token_type"));
    assert!(json.contains("Bearer"));

    // Deserialize back
    let parsed: IssueSessionTokensResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.token_type, "Bearer");
    assert_eq!(parsed.expires_in, 3600);
    assert!(parsed.access_token.starts_with("eyJ"));
    assert!(parsed.refresh_token.starts_with("eyJ"));
}

#[test]
fn test_issue_session_tokens_response_deserialization() {
    // Test deserialization of the response
    let json = r#"{
        "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc123",
        "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.def456",
        "session_id": "550e8400-e29b-41d4-a716-446655440000",
        "expires_in": 3600,
        "token_type": "Bearer"
    }"#;

    let parsed: IssueSessionTokensResponse = serde_json::from_str(json).unwrap();
    assert_eq!(parsed.access_token, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc123");
    assert_eq!(parsed.refresh_token, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.def456");
    assert_eq!(parsed.session_id, "550e8400-e29b-41d4-a716-446655440000");
    assert_eq!(parsed.expires_in, 3600);
    assert_eq!(parsed.token_type, "Bearer");
}

#[test]
fn test_issue_session_tokens_request_deserialization() {
    // Test deserialization of the request
    let json = r#"{"user_id": "550e8400-e29b-41d4-a716-446655440000"}"#;

    let parsed: IssueSessionTokensRequest = serde_json::from_str(json).unwrap();
    assert_eq!(parsed.user_id, "550e8400-e29b-41d4-a716-446655440000");
}
