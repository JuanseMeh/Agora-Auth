
//! Comprehensive tests for ValidateAccessToken use case.

use super::super::validate_access_token::{ValidateAccessToken, ValidateAccessTokenInput};
use crate::core::token::Token;
use crate::core::usecases::ports::TokenService;

// ============================================================================
// Mock Implementations
// ============================================================================

struct MockTokenService {
    valid_tokens: std::collections::HashSet<String>,
}

impl MockTokenService {
    fn new() -> Self {
        let mut valid_tokens = std::collections::HashSet::new();
        // Valid access tokens with proper format
        valid_tokens.insert("valid_access_token".to_string());
        valid_tokens.insert("token_with_session".to_string());
        valid_tokens.insert("expired_token".to_string());
        Self { valid_tokens }
    }
    
    fn with_expired_token() -> Self {
        let mut service = Self::new();
        service.valid_tokens.insert("expired_token".to_string());
        service
    }
}

impl TokenService for MockTokenService {
    fn issue_access_token(&self, user_id: &str, claims: &str) -> Token {
        Token::new(format!("access_{}_{}", user_id, claims.len()))
    }
    
    fn issue_refresh_token(&self, user_id: &str, _claims: &str) -> Token {
        Token::new(format!("refresh_{}", user_id))
    }
    
    fn validate_access_token(&self, token: &Token) -> Result<String, ()> {
        let token_value = token.value();
        // Use a timestamp far in the future (year 2286) - i64::MAX seconds is too big,
        // so use 10 billion seconds (year ~2286)
        let future_exp = 10_000_000_000i64;
        
        if token_value == "valid_access_token" {
            Ok(format!(r#"{{"sub":"user123","type":"access","exp":{}}}"#, future_exp))
        } else if token_value == "token_with_session" {
            Ok(format!(r#"{{"sub":"user456","sid":"session789","type":"access","exp":{}}}"#, future_exp))
        } else if token_value == "expired_token" {
            // Return a token that is already expired (year 2001)
            Ok(r#"{"sub":"user999","type":"access","exp":1000000000}"#.to_string())
        } else if token_value.starts_with("access_") {
            // Tokens issued by this mock
            Ok(format!(r#"{{"sub":"user123","type":"access","exp":{}}}"#, future_exp))
        } else {
            Err(())
        }
    }
    
    fn validate_refresh_token(&self, _token: &Token) -> Result<String, ()> {
        Err(()) // Not used in these tests
    }
}

// ============================================================================
// Test Cases
// ============================================================================

#[test]
fn test_validate_access_token_success() {
    let token_service = MockTokenService::new();
    let use_case = ValidateAccessToken::new(&token_service);
    
    let input = ValidateAccessTokenInput {
        access_token: Token::new("valid_access_token"),
    };
    
    let result = use_case.execute(input);
    assert!(result.is_ok());
    
    let output = result.unwrap();
    assert!(output.valid);
    assert_eq!(output.reason, None);
    assert_eq!(output.user_id, Some("user123".to_string()));
    assert_eq!(output.session_id, None); // No session_id in this token
}

#[test]
fn test_validate_access_token_with_session() {
    let token_service = MockTokenService::new();
    let use_case = ValidateAccessToken::new(&token_service);
    
    let input = ValidateAccessTokenInput {
        access_token: Token::new("token_with_session"),
    };
    
    let result = use_case.execute(input);
    assert!(result.is_ok());
    
    let output = result.unwrap();
    assert!(output.valid);
    assert_eq!(output.user_id, Some("user456".to_string()));
    assert_eq!(output.session_id, Some("session789".to_string()));
}

#[test]
fn test_validate_access_token_invalid_signature() {
    let token_service = MockTokenService::new();
    let use_case = ValidateAccessToken::new(&token_service);
    
    let input = ValidateAccessTokenInput {
        access_token: Token::new("invalid_token"),
    };
    
    let result = use_case.execute(input);
    assert!(result.is_ok());
    
    let output = result.unwrap();
    assert!(!output.valid);
    assert_eq!(output.reason, Some("token signature invalid".to_string()));
    assert_eq!(output.user_id, None);
    assert_eq!(output.session_id, None);
}

#[test]
fn test_validate_access_token_expired() {
    let token_service = MockTokenService::with_expired_token();
    let use_case = ValidateAccessToken::new(&token_service);
    
    let input = ValidateAccessTokenInput {
        access_token: Token::new("expired_token"),
    };
    
    let result = use_case.execute(input);
    assert!(result.is_ok());
    
    let output = result.unwrap();
    assert!(!output.valid);
    assert_eq!(output.reason, Some("token expired".to_string()));
}

#[test]
fn test_validate_access_token_output_structure() {
    let token_service = MockTokenService::new();
    let use_case = ValidateAccessToken::new(&token_service);
    
    // Test valid token output
    let input = ValidateAccessTokenInput {
        access_token: Token::new("valid_access_token"),
    };
    
    let result = use_case.execute(input).unwrap();
    assert!(result.valid);
    assert!(result.reason.is_none());
    assert!(result.user_id.is_some());
    
    // Test invalid token output
    let input = ValidateAccessTokenInput {
        access_token: Token::new("unknown_token"),
    };
    
    let result = use_case.execute(input).unwrap();
    assert!(!result.valid);
    assert!(result.reason.is_some());
    assert!(result.user_id.is_none());
}

#[test]
fn test_validate_access_token_empty_token() {
    let token_service = MockTokenService::new();
    let use_case = ValidateAccessToken::new(&token_service);
    
    let input = ValidateAccessTokenInput {
        access_token: Token::new(""),
    };
    
    let result = use_case.execute(input);
    assert!(result.is_ok());
    
    let output = result.unwrap();
    assert!(!output.valid);
    assert_eq!(output.reason, Some("token signature invalid".to_string()));
}
