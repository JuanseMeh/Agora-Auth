// Tests for Authenticate DTO
use crate::adapters::http::dto::public::authenticate::{
    AuthenticateRequest, AuthenticateResponse,
};

#[test]
fn test_authenticate_request_validation_success() {
    let request = AuthenticateRequest {
        identifier: "user@example.com".to_string(),
        password: "MyPassword123".to_string(),
    };

    assert!(request.validate().is_ok());
}

#[test]
fn test_authenticate_request_empty_identifier() {
    let request = AuthenticateRequest {
        identifier: "".to_string(),
        password: "MyPassword123".to_string(),
    };

    assert!(request.validate().is_err());
}

#[test]
fn test_authenticate_request_empty_password() {
    let request = AuthenticateRequest {
        identifier: "user@example.com".to_string(),
        password: "".to_string(),
    };

    assert!(request.validate().is_err());
}

#[test]
fn test_authenticate_response_structure() {
    let response = AuthenticateResponse {
        access_token: "token123".to_string(),
        refresh_token: "refresh123".to_string(),
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        session_id: "session123".to_string(),
    };

    assert_eq!(response.token_type, "Bearer");
    assert_eq!(response.expires_in, 3600);
}
