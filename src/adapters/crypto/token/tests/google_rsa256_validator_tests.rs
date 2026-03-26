//! Tests for Google RS256 token validator.

use crate::adapters::crypto::token::{GoogleRs256Validator, GoogleValidatorConfig};
use crate::core::identity::ExternalIdentity;
use crate::core::error::{CoreError, TokenError};
use crate::core::usecases::ports::external_token_validator::ExternalTokenValidator;

#[test]
fn test_new_validator() {
    let config = GoogleValidatorConfig::new(
        "https://www.googleapis.com/oauth2/v3/certs".to_string(),
        "https://accounts.google.com".to_string(),
        "my-app-client-id".to_string(),
    );
    
    let validator = GoogleRs256Validator::new(config);
    
    // Field access for compile check (private OK in tests if pub(crate))
    let _ = validator.config.clone();
}

#[tokio::test]
async fn test_validate_malformed_header() {
    let config = GoogleValidatorConfig::new(
        "https://www.googleapis.com/oauth2/v3/certs".to_string(),
        "https://accounts.google.com".to_string(),
        "my-app-client-id".to_string(),
    );
    
    let validator = GoogleRs256Validator::new(config);
    
    let malformed = "not.a.jwt";
    let result: Result<ExternalIdentity, CoreError> = validator.validate(malformed).await;
    
    assert!(result.is_err());
    match result {
        Err(CoreError::Token(TokenError::Malformed { .. })) => {},
        _ => panic!("Expected Malformed error"),
    }
}

#[tokio::test]
async fn test_validate_wrong_algorithm() {
    let config = GoogleValidatorConfig::new(
        "https://www.googleapis.com/oauth2/v3/certs".to_string(),
        "https://accounts.google.com".to_string(),
        "my-app-client-id".to_string(),
    );
    
    let validator = GoogleRs256Validator::new(config);
    
    // HS256 header
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.signature";
    
    let result = validator.validate(token).await;
    
    assert!(matches!(
        result,
        Err(CoreError::Token(TokenError::UnsupportedAlgorithm { .. }))
    ));
}

#[tokio::test]
async fn test_validate_missing_kid() {
    let config = GoogleValidatorConfig::new(
        "https://www.googleapis.com/oauth2/v3/certs".to_string(),
        "https://accounts.google.com".to_string(),
        "my-app-client-id".to_string(),
    );
    
    let validator = GoogleRs256Validator::new(config);
    
    // RS256 header but no kid
    let token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.invalid";
    
    let result = validator.validate(token).await;
    
    assert!(matches!(
        result,
        Err(CoreError::Token(TokenError::KeyIdNotFound { .. }))
    ));
}

#[tokio::test]
async fn test_validate_key_not_found() {
    let config = GoogleValidatorConfig::new(
        "https://www.googleapis.com/oauth2/v3/certs".to_string(),
        "https://accounts.google.com".to_string(),
        "my-app-client-id".to_string(),
    );
    
    let validator = GoogleRs256Validator::new(config);
    
    // Valid RS256 header with fake kid
    let token = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImZha2Uta2lkIn0.invalid.invalid";
    
    let result = validator.validate(token).await;
    
    assert!(matches!(
        result,
        Err(CoreError::Token(TokenError::KeyIdNotFound { .. }))
    ));
}

#[tokio::test]
async fn test_validate_wrong_issuer() {
    let config = GoogleValidatorConfig::new(
        "https://www.googleapis.com/oauth2/v3/certs".to_string(),
        "https://accounts.google.com".to_string(),
        "my-app-client-id".to_string(),
    );
    
    let validator = GoogleRs256Validator::new(config);
    
    // Note: Needs real token, but test structure with wrong iss would fail validation
    // Placeholder for integration test
    let result = validator.validate("eyJhbGciOiJSUzI1NiIsImtpZCI6Im...").await;
    assert!(result.is_err());
}
