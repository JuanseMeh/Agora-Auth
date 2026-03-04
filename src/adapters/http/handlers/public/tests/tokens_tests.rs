// Tests for refresh_token handler - focused on DTO validation and serialization

use crate::adapters::http::dto::public::{RefreshTokenRequest, RefreshTokenResponse};

// ============================================================================
// Test Cases
// ============================================================================

#[test]
fn test_refresh_token_valid_request() {
    // Test that a valid request passes validation
    let request = RefreshTokenRequest {
        refresh_token: "refresh_token_abc123".to_string(),
    };

    let validation_result = request.validate();
    assert!(validation_result.is_ok(), "Valid request should pass validation");
}

#[test]
fn test_refresh_token_empty_refresh_token() {
    // Test validation failure for empty refresh token
    let request = RefreshTokenRequest {
        refresh_token: "".to_string(),
    };

    let validation_result = request.validate();
    assert!(validation_result.is_err(), "Empty refresh token should fail validation");
    assert!(validation_result.unwrap_err().contains("Refresh token"));
}

#[test]
fn test_refresh_token_request_serialization() {
    // Test serialization/deserialization of the request
    let request = RefreshTokenRequest {
        refresh_token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.refresh".to_string(),
    };

    // Serialize to JSON
    let json = serde_json::to_string(&request).unwrap();
    assert!(json.contains("refresh_token"));
    assert!(json.contains("eyJ"));

    // Deserialize back
    let parsed: RefreshTokenRequest = serde_json::from_str(&json).unwrap();
    assert!(parsed.refresh_token.starts_with("eyJ"));
}

#[test]
fn test_refresh_token_request_deserialization() {
    // Test deserialization of the request
    let json = r#"{"refresh_token": "refresh_token_xyz789"}"#;

    let parsed: RefreshTokenRequest = serde_json::from_str(json).unwrap();
    assert_eq!(parsed.refresh_token, "refresh_token_xyz789");
}

#[test]
fn test_refresh_token_response_structure() {
    // Test that RefreshTokenResponse has the correct structure
    let response = RefreshTokenResponse {
        access_token: "access_token_abc123".to_string(),
        token_type: "Bearer".to_string(),
        expires_in: 3600,
    };

    // Verify all fields are present
    assert_eq!(response.access_token, "access_token_abc123");
    assert_eq!(response.token_type, "Bearer");
    assert_eq!(response.expires_in, 3600);
}

#[test]
fn test_refresh_token_response_serialization() {
    // Test serialization of the response
    let response = RefreshTokenResponse {
        access_token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.new_access".to_string(),
        token_type: "Bearer".to_string(),
        expires_in: 1800,
    };

    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("access_token"));
    assert!(json.contains("token_type"));
    assert!(json.contains("expires_in"));
    assert!(json.contains("Bearer"));

    // Deserialize back
    let parsed: RefreshTokenResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.token_type, "Bearer");
    assert_eq!(parsed.expires_in, 1800);
}

#[test]
fn test_refresh_token_response_deserialization() {
    // Test deserialization of the response
    let json = r#"{
        "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.new_token",
        "token_type": "Bearer",
        "expires_in": 3600
    }"#;

    let parsed: RefreshTokenResponse = serde_json::from_str(json).unwrap();
    assert_eq!(parsed.access_token, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.new_token");
    assert_eq!(parsed.token_type, "Bearer");
    assert_eq!(parsed.expires_in, 3600);
}

#[test]
fn test_refresh_token_jwt_format() {
    // Test that JWT format tokens are accepted
    let request = RefreshTokenRequest {
        refresh_token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c".to_string(),
    };

    let validation_result = request.validate();
    assert!(validation_result.is_ok(), "JWT refresh token should be valid");
}

#[test]
fn test_refresh_token_response_zero_expires_in() {
    // Test that 0 is a valid expires_in value (immediate expiry)
    let response = RefreshTokenResponse {
        access_token: "token".to_string(),
        token_type: "Bearer".to_string(),
        expires_in: 0,
    };

    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("\"expires_in\":0"));

    let parsed: RefreshTokenResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.expires_in, 0);
}

#[test]
fn test_refresh_token_response_large_expires_in() {
    // Test that large expires_in values are allowed
    let response = RefreshTokenResponse {
        access_token: "token".to_string(),
        token_type: "Bearer".to_string(),
        expires_in: 86400 * 30, // 30 days in seconds
    };

    assert_eq!(response.expires_in, 2592000);
}
