// Tests for create_credential handler - focused on DTO validation and serialization

use crate::adapters::http::dto::internal::{CreateCredentialRequest, CreateCredentialResponse};

// ============================================================================
// Test Cases
// ============================================================================

#[test]
fn test_create_credential_valid_request() {
    // Test that a valid request passes validation
    let request = CreateCredentialRequest {
        user_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        identifier: "testuser".to_string(),
        password: "password123".to_string(),
        credential_type: Some("password".to_string()),
    };

    let validation_result = request.validate();
    assert!(validation_result.is_ok(), "Valid request should pass validation");
}

#[test]
fn test_create_credential_empty_user_id() {
    // Test validation failure for empty user_id
    let request = CreateCredentialRequest {
        user_id: "".to_string(),
        identifier: "testuser".to_string(),
        password: "password123".to_string(),
        credential_type: Some("password".to_string()),
    };

    let validation_result = request.validate();
    assert!(validation_result.is_err(), "Empty user_id should fail validation");
    assert!(validation_result.unwrap_err().contains("User ID"));
}

#[test]
fn test_create_credential_empty_identifier() {
    // Test validation failure for empty identifier
    let request = CreateCredentialRequest {
        user_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        identifier: "".to_string(),
        password: "password123".to_string(),
        credential_type: Some("password".to_string()),
    };

    let validation_result = request.validate();
    assert!(validation_result.is_err(), "Empty identifier should fail validation");
    assert!(validation_result.unwrap_err().contains("Identifier"));
}

#[test]
fn test_create_credential_empty_password() {
    // Test validation failure for empty password
    let request = CreateCredentialRequest {
        user_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        identifier: "testuser".to_string(),
        password: "".to_string(),
        credential_type: Some("password".to_string()),
    };

    let validation_result = request.validate();
    assert!(validation_result.is_err(), "Empty password should fail validation");
    assert!(validation_result.unwrap_err().contains("Password"));
}

#[test]
fn test_create_credential_identifier_too_long() {
    // Test validation failure for identifier too long
    let long_identifier = "a".to_string().repeat(256);
    let request = CreateCredentialRequest {
        user_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        identifier: long_identifier,
        password: "password123".to_string(),
        credential_type: Some("password".to_string()),
    };

    let validation_result = request.validate();
    assert!(validation_result.is_err(), "Identifier too long should fail validation");
    assert!(validation_result.unwrap_err().contains("Identifier too long"));
}

#[test]
fn test_create_credential_password_too_short() {
    // Test validation failure for password too short
    let request = CreateCredentialRequest {
        user_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        identifier: "testuser".to_string(),
        password: "short".to_string(),
        credential_type: Some("password".to_string()),
    };

    let validation_result = request.validate();
    assert!(validation_result.is_err(), "Password too short should fail validation");
    assert!(validation_result.unwrap_err().contains("Password too weak"));
}

#[test]
fn test_create_credential_request_serialization() {
    // Test serialization/deserialization of the request
    let request = CreateCredentialRequest {
        user_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        identifier: "testuser".to_string(),
        password: "password123".to_string(),
        credential_type: Some("password".to_string()),
    };

    // Serialize to JSON
    let json = serde_json::to_string(&request).unwrap();
    assert!(json.contains("testuser"));
    assert!(json.contains("password123"));
    assert!(json.contains("password"));

    // Deserialize back
    let parsed: CreateCredentialRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.identifier, "testuser");
    assert_eq!(parsed.password, "password123");
    assert_eq!(parsed.credential_type, Some("password".to_string()));
}

#[test]
fn test_create_credential_request_without_credential_type() {
    // Test that credential_type is optional
    let request = CreateCredentialRequest {
        user_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        identifier: "testuser".to_string(),
        password: "password123".to_string(),
        credential_type: None,
    };

    let validation_result = request.validate();
    assert!(validation_result.is_ok(), "Request without credential_type should be valid");

    // Serialize and deserialize
    let json = serde_json::to_string(&request).unwrap();
    let parsed: CreateCredentialRequest = serde_json::from_str(&json).unwrap();
    assert!(parsed.credential_type.is_none());
}

#[test]
fn test_create_credential_response_structure() {
    // Test that CreateCredentialResponse has the correct structure
    let response = CreateCredentialResponse {
        user_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        identifier: "testuser".to_string(),
        created_at: "2024-01-01T00:00:00Z".to_string(),
    };

    // Verify all fields are present and have expected values
    assert_eq!(response.user_id, "550e8400-e29b-41d4-a716-446655440000");
    assert_eq!(response.identifier, "testuser");
    assert_eq!(response.created_at, "2024-01-01T00:00:00Z");
}

#[test]
fn test_create_credential_response_serialization() {
    // Test serialization of the response
    let response = CreateCredentialResponse {
        user_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        identifier: "testuser".to_string(),
        created_at: "2024-01-15T10:30:00Z".to_string(),
    };

    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("user_id"));
    assert!(json.contains("identifier"));
    assert!(json.contains("created_at"));
    assert!(json.contains("testuser"));

    // Deserialize back
    let parsed: CreateCredentialResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.user_id, "550e8400-e29b-41d4-a716-446655440000");
    assert_eq!(parsed.identifier, "testuser");
}

#[test]
fn test_create_credential_response_deserialization() {
    // Test deserialization of the response
    let json = r#"{
        "user_id": "550e8400-e29b-41d4-a716-446655440000",
        "identifier": "newuser",
        "created_at": "2024-02-20T12:00:00Z"
    }"#;

    let parsed: CreateCredentialResponse = serde_json::from_str(json).unwrap();
    assert_eq!(parsed.user_id, "550e8400-e29b-41d4-a716-446655440000");
    assert_eq!(parsed.identifier, "newuser");
    assert_eq!(parsed.created_at, "2024-02-20T12:00:00Z");
}

#[test]
fn test_create_credential_minimum_valid_password() {
    // Test that password with exactly 8 characters is valid
    let request = CreateCredentialRequest {
        user_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        identifier: "testuser".to_string(),
        password: "12345678".to_string(),
        credential_type: Some("password".to_string()),
    };

    let validation_result = request.validate();
    assert!(validation_result.is_ok(), "Password with 8 chars should be valid");
}

#[test]
fn test_create_credential_boundary_identifier_length() {
    // Test identifier at exactly 255 characters (max allowed)
    let identifier = "a".to_string().repeat(255);
    let request = CreateCredentialRequest {
        user_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        identifier,
        password: "password123".to_string(),
        credential_type: Some("password".to_string()),
    };

    let validation_result = request.validate();
    assert!(validation_result.is_ok(), "Identifier at 255 chars should be valid");
}
