// Tests for authenticate handler - focused on DTO validation and serialization

use crate::adapters::http::dto::public::{AuthenticateRequest, AuthenticateResponse};

// ============================================================================
// Test Cases
// ============================================================================

#[test]
fn test_authenticate_valid_request() {
    // Test that a valid request passes validation
    let request = AuthenticateRequest {
        identifier: "testuser".to_string(),
        password: "password123".to_string(),
    };

    let validation_result = request.validate();
    assert!(validation_result.is_ok(), "Valid request should pass validation");
}

#[test]
fn test_authenticate_empty_identifier() {
    // Test validation failure for empty identifier
    let request = AuthenticateRequest {
        identifier: "".to_string(),
        password: "password123".to_string(),
    };

    let validation_result = request.validate();
    assert!(validation_result.is_err(), "Empty identifier should fail validation");
    assert!(validation_result.unwrap_err().contains("Identifier"));
}

#[test]
fn test_authenticate_empty_password() {
    // Test validation failure for empty password
    let request = AuthenticateRequest {
        identifier: "testuser".to_string(),
        password: "".to_string(),
    };

    let validation_result = request.validate();
    assert!(validation_result.is_err(), "Empty password should fail validation");
    assert!(validation_result.unwrap_err().contains("Password"));
}

#[test]
fn test_authenticate_both_empty() {
    // Test validation failure for both empty
    let request = AuthenticateRequest {
        identifier: "".to_string(),
        password: "".to_string(),
    };

    let validation_result = request.validate();
    assert!(validation_result.is_err(), "Both empty should fail validation");
}

#[test]
fn test_authenticate_request_serialization() {
    // Test serialization/deserialization of the request
    let request = AuthenticateRequest {
        identifier: "testuser@example.com".to_string(),
        password: "password123".to_string(),
    };

    // Serialize to JSON
    let json = serde_json::to_string(&request).unwrap();
    assert!(json.contains("testuser@example.com"));
    assert!(json.contains("password123"));

    // Deserialize back
    let parsed: AuthenticateRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.identifier, "testuser@example.com");
    assert_eq!(parsed.password, "password123");
}

#[test]
fn test_authenticate_request_deserialization() {
    // Test deserialization of the request
    let json = r#"{"identifier": "john_doe", "password": "secret456"}"#;

    let parsed: AuthenticateRequest = serde_json::from_str(json).unwrap();
    assert_eq!(parsed.identifier, "john_doe");
    assert_eq!(parsed.password, "secret456");
}

#[test]
fn test_authenticate_response_structure() {
    // Test that AuthenticateResponse has the correct structure
    let response = AuthenticateResponse {
        access_token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.access".to_string(),
        refresh_token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.refresh".to_string(),
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        session_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
    };

    // Verify all fields are present
    assert!(response.access_token.starts_with("eyJ"));
    assert!(response.refresh_token.starts_with("eyJ"));
    assert_eq!(response.token_type, "Bearer");
    assert_eq!(response.expires_in, 3600);
    assert_eq!(response.session_id, "550e8400-e29b-41d4-a716-446655440000");
}

#[test]
fn test_authenticate_response_serialization() {
    // Test serialization of the response
    let response = AuthenticateResponse {
        access_token: "access_token_abc123".to_string(),
        refresh_token: "refresh_token_xyz789".to_string(),
        token_type: "Bearer".to_string(),
        expires_in: 1800,
        session_id: "session_123".to_string(),
    };

    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("access_token"));
    assert!(json.contains("refresh_token"));
    assert!(json.contains("token_type"));
    assert!(json.contains("expires_in"));
    assert!(json.contains("session_id"));
    assert!(json.contains("Bearer"));

    // Deserialize back
    let parsed: AuthenticateResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.token_type, "Bearer");
    assert_eq!(parsed.expires_in, 1800);
}

#[test]
fn test_authenticate_response_deserialization() {
    // Test deserialization of the response
    let json = r#"{
        "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc123",
        "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.def456",
        "token_type": "Bearer",
        "expires_in": 3600,
        "session_id": "550e8400-e29b-41d4-a716-446655440000"
    }"#;

    let parsed: AuthenticateResponse = serde_json::from_str(json).unwrap();
    assert_eq!(parsed.access_token, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc123");
    assert_eq!(parsed.refresh_token, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.def456");
    assert_eq!(parsed.token_type, "Bearer");
    assert_eq!(parsed.expires_in, 3600);
    assert_eq!(parsed.session_id, "550e8400-e29b-41d4-a716-446655440000");
}

#[test]
fn test_authenticate_email_as_identifier() {
    // Test that email can be used as identifier
    let request = AuthenticateRequest {
        identifier: "user@example.com".to_string(),
        password: "password123".to_string(),
    };

    let validation_result = request.validate();
    assert!(validation_result.is_ok(), "Email as identifier should be valid");
}

#[test]
fn test_authenticate_special_characters_in_password() {
    // Test that special characters in password are allowed
    let request = AuthenticateRequest {
        identifier: "testuser".to_string(),
        password: "p@ssw0rd!#$%^&*()".to_string(),
    };

    let validation_result = request.validate();
    assert!(validation_result.is_ok(), "Special characters in password should be valid");
}

#[test]
fn test_authenticate_long_identifier() {
    // Test that long identifier is allowed (up to reasonable length)
    let request = AuthenticateRequest {
        identifier: "a".to_string().repeat(100),
        password: "password123".to_string(),
    };

    let validation_result = request.validate();
    assert!(validation_result.is_ok(), "Long identifier should be valid");
}
