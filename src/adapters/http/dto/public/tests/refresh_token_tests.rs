// Tests for RefreshToken DTO
use crate::adapters::http::dto::public::refresh_token::{
    RefreshTokenRequest, RefreshTokenResponse,
};

#[test]
fn test_refresh_token_request_validation_success() {
    let request = RefreshTokenRequest {
        refresh_token: "valid_token_123".to_string(),
    };

    assert!(request.validate().is_ok());
}

#[test]
fn test_refresh_token_request_empty_token() {
    let request = RefreshTokenRequest {
        refresh_token: "".to_string(),
    };

    assert!(request.validate().is_err());
}

#[test]
fn test_refresh_token_response_structure() {
    let response = RefreshTokenResponse {
        access_token: "new_token".to_string(),
        token_type: "Bearer".to_string(),
        expires_in: 3600,
    };

    assert_eq!(response.token_type, "Bearer");
    assert_eq!(response.expires_in, 3600);
}
