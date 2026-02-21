// Tests for TokenValidation DTO
use crate::adapters::http::dto::public::token_validation::{
    TokenValidationRequest, TokenValidationResponse,
};

#[test]
fn test_token_validation_request_validation_success() {
    let request = TokenValidationRequest {
        token: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9".to_string(),
    };

    assert!(request.validate().is_ok());
}

#[test]
fn test_token_validation_request_empty_token() {
    let request = TokenValidationRequest {
        token: "".to_string(),
    };

    assert!(request.validate().is_err());
}

#[test]
fn test_token_validation_response_structure() {
    let response = TokenValidationResponse {
        user_id: "uuid-123".to_string(),
        session_id: "session-456".to_string(),
    };

    assert_eq!(response.user_id, "uuid-123");
    assert_eq!(response.session_id, "session-456");
}
