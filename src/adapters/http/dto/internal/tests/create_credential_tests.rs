use crate::adapters::http::dto::internal::create_credential::{
    CreateCredentialRequest, CreateCredentialResponse,
};

#[test]
fn test_create_credential_request_validation_success() {
    let request = CreateCredentialRequest {
        identifier: "user@example.com".to_string(),
        password: "SecurePassword123".to_string(),
    };

    assert!(request.validate().is_ok());
}

#[test]
fn test_create_credential_request_empty_identifier() {
    let request = CreateCredentialRequest {
        identifier: "".to_string(),
        password: "ValidPassword123".to_string(),
    };

    assert!(request.validate().is_err());
}

#[test]
fn test_create_credential_request_empty_password() {
    let request = CreateCredentialRequest {
        identifier: "user@example.com".to_string(),
        password: "".to_string(),
    };

    assert!(request.validate().is_err());
}

#[test]
fn test_create_credential_request_weak_password() {
    let request = CreateCredentialRequest {
        identifier: "user@example.com".to_string(),
        password: "weak".to_string(),
    };

    assert!(request.validate().is_err());
}

#[test]
fn test_create_credential_request_identifier_too_long() {
    let request = CreateCredentialRequest {
        identifier: "a".repeat(256),
        password: "ValidPassword123".to_string(),
    };

    assert!(request.validate().is_err());
}

#[test]
fn test_create_credential_response_serialization() {
    let response = CreateCredentialResponse {
        user_id: "uuid-123".to_string(),
        identifier: "user@example.com".to_string(),
        created_at: "2025-02-21T10:30:00Z".to_string(),
    };

    assert_eq!(response.identifier, "user@example.com");
}
