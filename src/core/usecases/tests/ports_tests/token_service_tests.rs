
//! Tests for TokenService port.

use crate::core::token::Token;
use crate::core::usecases::ports::TokenService;

struct MockTokenService;
impl TokenService for MockTokenService {
    fn issue_access_token(&self, subject: &str, _claims: &str) -> Token {
        Token::new(format!("access_{}", subject))
    }
    fn issue_refresh_token(&self, subject: &str, _claims: &str) -> Token {
        Token::new(format!("refresh_{}", subject))
    }
    fn validate_access_token(&self, token: &Token) -> Result<String, ()> {
        if token.value().starts_with("access_") { Ok("claims".to_string()) } else { Err(()) }
    }
    fn validate_refresh_token(&self, token: &Token) -> Result<String, ()> {
        if token.value().starts_with("refresh_") { Ok("claims".to_string()) } else { Err(()) }
    }
}

#[test]
fn token_service_issue_access_token() {
    let service = MockTokenService;
    let token = service.issue_access_token("user123", "claims");
    assert_eq!(token.value(), "access_user123");
}

#[test]
fn token_service_validate_access_token() {
    let service = MockTokenService;
    let token = Token::new("access_user123");
    assert!(service.validate_access_token(&token).is_ok());
    let invalid_token = Token::new("invalid");
    assert!(service.validate_access_token(&invalid_token).is_err());
}
