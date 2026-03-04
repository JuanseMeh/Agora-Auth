//! Comprehensive tests for ValidateAccessToken use case.

use futures::future::BoxFuture;
use super::super::validate_access_token::{ValidateAccessToken, ValidateAccessTokenInput};
use crate::core::token::Token;
use crate::core::usecases::ports::{TokenService, SessionRepository};
use crate::core::usecases::ports::session_repository::Session;
use crate::core::identity::UserIdentity;

// ============================================================================
// Mock Implementations
// ============================================================================

struct MockTokenService {
    valid_tokens: std::sync::RwLock<std::collections::HashSet<String>>,
    expired_tokens: std::sync::RwLock<std::collections::HashSet<String>>,
    revoked_tokens: std::sync::RwLock<std::collections::HashSet<String>>,
}

impl MockTokenService {
    fn new() -> Self {
        Self {
            valid_tokens: std::sync::RwLock::new(std::collections::HashSet::new()),
            expired_tokens: std::sync::RwLock::new(std::collections::HashSet::new()),
            revoked_tokens: std::sync::RwLock::new(std::collections::HashSet::new()),
        }
    }
    
    fn add_valid_token(&self, token: &str) {
        self.valid_tokens.write().unwrap().insert(token.to_string());
    }
    
    fn add_expired_token(&self, token: &str) {
        self.expired_tokens.write().unwrap().insert(token.to_string());
    }
}

impl TokenService for MockTokenService {
    fn issue_access_token(&self, subject: &str, _claims: &str) -> Token {
        Token::new(&format!("access_token_for_{}", subject))
    }
    
    fn issue_refresh_token(&self, subject: &str, _claims: &str) -> Token {
        Token::new(&format!("refresh_token_for_{}", subject))
    }

    fn issue_service_token(&self, subject: &str, _claims: &str) -> Token {
        Token::new(&format!("service_token_for_{}", subject))
    }
    
    fn validate_access_token(&self, token: &Token) -> Result<String, ()> {
        let token_value = token.value();
        
        if self.revoked_tokens.read().unwrap().contains(token_value) {
            return Err(());
        }
        
        if self.expired_tokens.read().unwrap().contains(token_value) {
            return Err(());
        }
        
        if self.valid_tokens.read().unwrap().contains(token_value) {
            // Return claims with proper format including type and exp
            Ok(r#"{"sub":"user123","sid":"session123","type":"access","exp":9999999999}"#.to_string())
        } else {
            Err(())
        }
    }
    
    fn validate_refresh_token(&self, token: &Token) -> Result<String, ()> {
        let token_value = token.value();
        
        if self.valid_tokens.read().unwrap().contains(token_value) {
            Ok(r#"{"sub":"user123","type":"refresh"}"#.to_string())
        } else {
            Err(())
        }
    }

    fn validate_service_token(&self, token: &Token) -> Result<String, ()> {
        if token.value().contains("service_token_for_") {
            Ok(r#"{"sub":"service123","type":"service"}"#.to_string())
        } else {
            Err(())
        }
    }
}

struct MockSessionRepo;
impl SessionRepository for MockSessionRepo {
    fn create_session(&self, _session_id: &str, _user: &UserIdentity, _refresh_token_hash: &str, _metadata: &str) -> BoxFuture<'_, ()> {
        Box::pin(async move {})
    }
    
    fn find_by_refresh_token_hash(&self, _hash: &str) -> BoxFuture<'_, Option<Session>> {
        Box::pin(async move { None })
    }
    
    fn find_by_id(&self, _session_id: &str) -> BoxFuture<'_, Option<Session>> {
        // Default: always return Some(Session) to simulate active session
        Box::pin(async move { Some(Session {}) })
    }
    
    fn revoke_session(&self, _session_id: &str) -> BoxFuture<'_, ()> {
        Box::pin(async move {})
    }
    
    fn revoke_all_for_user(&self, _user_id: &str) -> BoxFuture<'_, ()> {
        Box::pin(async move {})
    }
    
    fn delete_expired(&self) -> BoxFuture<'_, ()> {
        Box::pin(async move {})
    }
}

// ============================================================================
// Test Cases
// ============================================================================

#[tokio::test]
async fn test_validate_access_token_success() {
    let token_service = MockTokenService::new();
    let session_repo = MockSessionRepo;
    
    // Add a valid token
    token_service.add_valid_token("valid_token_123");
    
    let use_case = ValidateAccessToken::new(&token_service, &session_repo);
    
    let input = ValidateAccessTokenInput {
        access_token: Token::new("valid_token_123"),
    };
    
    let result = use_case.execute(input).await;
    assert!(result.is_ok(), "Validation should succeed for valid token");
    
    let output = result.unwrap();
    assert!(output.valid);
    assert!(output.user_id.is_some());
    assert_eq!(output.user_id.unwrap(), "user123");
}

#[tokio::test]
async fn test_validate_access_token_with_session() {
    let token_service = MockTokenService::new();
    let session_repo = MockSessionRepo;
    
    token_service.add_valid_token("token_with_session");
    
    let use_case = ValidateAccessToken::new(&token_service, &session_repo);
    
    let input = ValidateAccessTokenInput {
        access_token: Token::new("token_with_session"),
    };
    
    let result = use_case.execute(input).await;
    assert!(result.is_ok());
    
    let output = result.unwrap();
    assert!(output.valid);
    assert!(output.session_id.is_some());
    assert_eq!(output.session_id.unwrap(), "session123");
}

#[tokio::test]
async fn test_validate_access_token_invalid_signature() {
    let token_service = MockTokenService::new();
    let session_repo = MockSessionRepo;
    
    // Don't add the token to valid tokens - it will fail validation
    let use_case = ValidateAccessToken::new(&token_service, &session_repo);
    
    let input = ValidateAccessTokenInput {
        access_token: Token::new("invalid_token"),
    };
    
    let result = use_case.execute(input).await;
    assert!(result.is_ok()); // Returns Ok with valid=false, not Err
    
    let output = result.unwrap();
    assert!(!output.valid);
    assert!(output.reason.is_some());
}

#[tokio::test]
async fn test_validate_access_token_expired() {
    let token_service = MockTokenService::new();
    let session_repo = MockSessionRepo;
    
    // Add token as expired
    token_service.add_expired_token("expired_token_123");
    
    let use_case = ValidateAccessToken::new(&token_service, &session_repo);
    
    let input = ValidateAccessTokenInput {
        access_token: Token::new("expired_token_123"),
    };
    
    let result = use_case.execute(input).await;
    assert!(result.is_ok()); // Returns Ok with valid=false
    
    let output = result.unwrap();
    assert!(!output.valid);
}

#[tokio::test]
async fn test_validate_access_token_output_structure() {
    let token_service = MockTokenService::new();
    let session_repo = MockSessionRepo;
    
    token_service.add_valid_token("test_token");
    
    let use_case = ValidateAccessToken::new(&token_service, &session_repo);
    
    let input = ValidateAccessTokenInput {
        access_token: Token::new("test_token"),
    };
    
    let result = use_case.execute(input).await;
    assert!(result.is_ok());
    
    let output = result.unwrap();
    
    // Verify output structure
    assert!(output.valid);
    assert!(output.user_id.is_some());
    assert!(output.session_id.is_some());
    assert!(output.reason.is_none()); // No error reason for valid token
}

#[tokio::test]
async fn test_validate_access_token_empty_token() {
    let token_service = MockTokenService::new();
    let session_repo = MockSessionRepo;
    
    let use_case = ValidateAccessToken::new(&token_service, &session_repo);
    
    let input = ValidateAccessTokenInput {
        access_token: Token::new(""),
    };
    
    let result = use_case.execute(input).await;
    assert!(result.is_ok()); // Returns Ok with valid=false
    
    let output = result.unwrap();
    assert!(!output.valid);
    assert!(output.reason.is_some());
}
