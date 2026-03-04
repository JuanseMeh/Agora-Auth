// Tests for token_validation handler - focused on DTO validation and serialization

use crate::adapters::http::dto::public::{TokenValidationRequest, TokenValidationResponse};

// ============================================================================
// Test Cases
// ============================================================================

#[test]
fn test_token_validation_valid_request() {
    // Test that a valid request passes validation
    let request = TokenValidationRequest {
        token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token".to_string(),
    };

    let validation_result = request.validate();
    assert!(validation_result.is_ok(), "Valid request should pass validation");
}

#[test]
fn test_token_validation_empty_token() {
    // Test validation failure for empty token
    let request = TokenValidationRequest {
        token: "".to_string(),
    };

    let validation_result = request.validate();
    assert!(validation_result.is_err(), "Empty token should fail validation");
    assert!(validation_result.unwrap_err().contains("Token"));
}

#[test]
fn test_token_validation_request_serialization() {
    // Test serialization/deserialization of the request
    let request = TokenValidationRequest {
        token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.access_token".to_string(),
    };

    // Serialize to JSON
    let json = serde_json::to_string(&request).unwrap();
    assert!(json.contains("token"));
    assert!(json.contains("eyJ"));

    // Deserialize back
    let parsed: TokenValidationRequest = serde_json::from_str(&json).unwrap();
    assert!(parsed.token.starts_with("eyJ"));
}

#[test]
fn test_token_validation_request_deserialization() {
    // Test deserialization of the request
    let json = r#"{"token": "access_token_abc123"}"#;

    let parsed: TokenValidationRequest = serde_json::from_str(json).unwrap();
    assert_eq!(parsed.token, "access_token_abc123");
}

#[test]
fn test_token_validation_response_structure() {
    // Test that TokenValidationResponse has the correct structure
    let response = TokenValidationResponse {
        user_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        session_id: "session_123".to_string(),
    };

    // Verify all fields are present
    assert_eq!(response.user_id, "550e8400-e29b-41d4-a716-446655440000");
    assert_eq!(response.session_id, "session_123");
}

#[test]
fn test_token_validation_response_serialization() {
    // Test serialization of the response
    let response = TokenValidationResponse {
        user_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        session_id: "session_abc".to_string(),
    };

    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("user_id"));
    assert!(json.contains("session_id"));
    assert!(json.contains("550e8400-e29b-41d4-a716-446655440000"));
    assert!(json.contains("session_abc"));

    // Deserialize back
    let parsed: TokenValidationResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.user_id, "550e8400-e29b-41d4-a716-446655440000");
    assert_eq!(parsed.session_id, "session_abc");
}

#[test]
fn test_token_validation_response_deserialization() {
    // Test deserialization of the response
    let json = r#"{
        "user_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
        "session_id": "session_xyz789"
    }"#;

    let parsed: TokenValidationResponse = serde_json::from_str(json).unwrap();
    assert_eq!(parsed.user_id, "6ba7b810-9dad-11d1-80b4-00c04fd430c8");
    assert_eq!(parsed.session_id, "session_xyz789");
}

#[test]
fn test_token_validation_jwt_format() {
    // Test that JWT format tokens are accepted
    let request = TokenValidationRequest {
        token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c".to_string(),
    };

    let validation_result = request.validate();
    assert!(validation_result.is_ok(), "JWT token should be valid");
}

#[test]
fn test_token_validation_simple_token() {
    // Test that simple non-JWT tokens are accepted
    let request = TokenValidationRequest {
        token: "simple_token_12345".to_string(),
    };

    let validation_result = request.validate();
    assert!(validation_result.is_ok(), "Simple token should be valid");
}

#[test]
fn test_token_validation_response_with_uuid_format() {
    // Test that UUID format user_id is handled correctly
    let response = TokenValidationResponse {
        user_id: "f47ac10b-58cc-4372-a567-0e02b2c3d479".to_string(),
        session_id: "sess_001".to_string(),
    };

    let json = serde_json::to_string(&response).unwrap();
    let parsed: TokenValidationResponse = serde_json::from_str(&json).unwrap();
    
    // Verify UUID format is preserved
    assert_eq!(parsed.user_id.len(), 36); // Standard UUID length
    assert!(parsed.user_id.contains('-'));
}

#[test]
fn test_token_validation_token_with_special_chars() {
    // Test that tokens with special characters are accepted
    let request = TokenValidationRequest {
        token: "token_with_underscores-dots_and=equals".to_string(),
    };

    let validation_result = request.validate();
    assert!(validation_result.is_ok(), "Token with special chars should be valid");
}

#[test]
fn test_token_validation_request_missing_token_field() {
    // Test deserialization with missing token field
    let json = r#"{}"#;

    let result: Result<TokenValidationRequest, _> = serde_json::from_str(json);
    assert!(result.is_err(), "Missing token field should cause deserialization error");
}

#[test]
fn test_token_validation_response_empty_fields() {
    // Test response with empty strings
    let response = TokenValidationResponse {
        user_id: "".to_string(),
        session_id: "".to_string(),
    };

    let json = serde_json::to_string(&response).unwrap();
    let parsed: TokenValidationResponse = serde_json::from_str(&json).unwrap();
    
    assert!(parsed.user_id.is_empty());
    assert!(parsed.session_id.is_empty());
}
