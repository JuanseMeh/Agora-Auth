
//! Comprehensive tests for RefreshSession use case.

use super::super::refresh_session::{RefreshSession, RefreshSessionInput};
use crate::core::token::Token;
use crate::core::usecases::ports::{SessionRepository, TokenService};
use crate::core::usecases::ports::session_repository::Session as SessionType;
use crate::core::error::CoreError;

// ============================================================================
// Mock Implementations
// ============================================================================

struct MockSessionRepo {
    sessions: std::cell::RefCell<std::collections::HashMap<String, SessionData>>, // session_id -> session data
    revoked_sessions: std::cell::RefCell<std::collections::HashSet<String>>,
}

struct SessionData {
    _user_id: String,
    refresh_token_hash: String,
    revoked: bool,
}

impl MockSessionRepo {
    fn new() -> Self {
        Self {
            sessions: std::cell::RefCell::new(std::collections::HashMap::new()),
            revoked_sessions: std::cell::RefCell::new(std::collections::HashSet::new()),
        }
    }
    
    fn insert_session(&self, session_id: &str, user_id: &str, refresh_token: &str) {
        // Hash the token to store it (matches RefreshSession use case behavior)
        let refresh_token_hash = Self::hash_token(refresh_token);
        self.sessions.borrow_mut().insert(
            session_id.to_string(),
            SessionData {
                _user_id: user_id.to_string(),
                refresh_token_hash,
                revoked: false,
            },
        );
    }
    
    fn _is_revoked(&self, session_id: &str) -> bool {
        self.revoked_sessions.borrow().contains(session_id)
    }
    
    fn hash_token(token: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        token.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }
}

impl SessionRepository for MockSessionRepo {
    fn create_session(&self, _user: &crate::core::identity::UserIdentity, _refresh_token_hash: &str, _metadata: &str) {
        // Not used in refresh tests
    }
    
    fn find_by_refresh_token_hash(&self, hash: &str) -> Option<SessionType> {
        for (_session_id, data) in self.sessions.borrow().iter() {
            if data.refresh_token_hash == hash && !data.revoked {
                return Some(SessionType {});
            }
        }
        None
    }
    
    fn revoke_session(&self, session_id: &str) {
        self.revoked_sessions.borrow_mut().insert(session_id.to_string());
        if let Some(data) = self.sessions.borrow_mut().get_mut(session_id) {
            data.revoked = true;
        }
    }
    
    fn revoke_all_for_user(&self, _user_id: &str) {
        // Not used in refresh tests
    }
    
    fn delete_expired(&self) {
        // Not used in refresh tests
    }
}

struct MockTokenService {
    valid_tokens: std::collections::HashSet<String>,
    issued_access_tokens: std::cell::RefCell<u32>,
    issued_refresh_tokens: std::cell::RefCell<u32>,
}

impl MockTokenService {
    fn new() -> Self {
        let mut valid_tokens = std::collections::HashSet::new();
        valid_tokens.insert("valid_refresh_token".to_string());
        valid_tokens.insert("valid_refresh_token_2".to_string());
        valid_tokens.insert("old_refresh_token".to_string());
        valid_tokens.insert("revoked_refresh_token".to_string());
        Self {
            valid_tokens,
            issued_access_tokens: std::cell::RefCell::new(0),
            issued_refresh_tokens: std::cell::RefCell::new(0),
        }
    }
}

impl TokenService for MockTokenService {
    fn issue_access_token(&self, user_id: &str, _claims: &str) -> Token {
        *self.issued_access_tokens.borrow_mut() += 1;
        Token::new(format!("access_token_for_{}", user_id))
    }
    
    fn issue_refresh_token(&self, user_id: &str, _claims: &str) -> Token {
        *self.issued_refresh_tokens.borrow_mut() += 1;
        Token::new(format!("refresh_token_for_{}", user_id))
    }
    
    fn validate_access_token(&self, token: &Token) -> Result<String, ()> {
        if token.value().starts_with("access_token_for_") {
            Ok(r#"{"sub":"user123","type":"access","exp":9999999999}"#.to_string())
        } else {
            Err(())
        }
    }
    
    fn validate_refresh_token(&self, token: &Token) -> Result<String, ()> {
        if self.valid_tokens.contains(token.value()) {
            Ok(r#"{"sub":"user123","type":"refresh","exp":9999999999}"#.to_string())
        } else {
            Err(())
        }
    }
}

// ============================================================================
// Test Cases
// ============================================================================

#[test]
fn test_refresh_session_success() {
    let session_repo = MockSessionRepo::new();
    let token_service = MockTokenService::new();
    
    // Setup: Create a valid session
    session_repo.insert_session("session_123", "user123", "valid_refresh_token");
    
    let use_case = RefreshSession::new(
        &session_repo,
        &token_service,
        3600,  // access_token_ttl_seconds
        true,  // rotate_refresh_token
    );
    
    let input = RefreshSessionInput {
        refresh_token: Token::new("valid_refresh_token"),
    };
    
    let result = use_case.execute(input);
    assert!(result.is_ok(), "Refresh should succeed with valid token");
    
    let output = result.unwrap();
    assert!(!output.access_token.value().is_empty());
    assert!(output.refresh_token.is_some());
    assert_eq!(output.token_type, "Bearer");
    assert_eq!(output.expires_in, 3600);
    
    // Verify new tokens were issued
    assert_eq!(*token_service.issued_access_tokens.borrow(), 1);
    assert_eq!(*token_service.issued_refresh_tokens.borrow(), 1);
}

#[test]
fn test_refresh_session_invalid_token() {
    let session_repo = MockSessionRepo::new();
    let token_service = MockTokenService::new();
    
    let use_case = RefreshSession::new(
        &session_repo,
        &token_service,
        3600,
        true,
    );
    
    let input = RefreshSessionInput {
        refresh_token: Token::new("invalid_refresh_token"),
    };
    
    let result = use_case.execute(input);
    assert!(result.is_err(), "Refresh should fail with invalid token");
    
    match result.unwrap_err() {
        CoreError::Authentication(err) => {
            assert!(err.to_string().to_lowercase().contains("invalid") || 
                    err.to_string().to_lowercase().contains("token"));
        }
        _ => {} // Other error types are acceptable
    }
}

#[test]
fn test_refresh_session_rotation() {
    let session_repo = MockSessionRepo::new();
    let token_service = MockTokenService::new();
    
    // Setup: Create a valid session
    session_repo.insert_session("session_123", "user123", "old_refresh_token");
    
    let use_case = RefreshSession::new(
        &session_repo,
        &token_service,
        3600,
        true,  // Enable rotation
    );
    
    let input = RefreshSessionInput {
        refresh_token: Token::new("old_refresh_token"),
    };
    
    let result = use_case.execute(input);
    assert!(result.is_ok());
    
    let output = result.unwrap();
    let new_refresh_token = output.refresh_token.unwrap();
    
    // New token should be different from old token
    assert_ne!(new_refresh_token.value(), "old_refresh_token");
}

#[test]
fn test_refresh_session_no_rotation() {
    let session_repo = MockSessionRepo::new();
    let token_service = MockTokenService::new();
    
    // Setup: Create a valid session
    session_repo.insert_session("session_123", "user123", "valid_refresh_token");
    
    let use_case = RefreshSession::new(
        &session_repo,
        &token_service,
        3600,
        false,  // Disable rotation
    );
    
    let input = RefreshSessionInput {
        refresh_token: Token::new("valid_refresh_token"),
    };
    
    let result = use_case.execute(input);
    assert!(result.is_ok());
    
    let output = result.unwrap();
    
    // With rotation disabled, refresh_token should be None
    assert!(output.refresh_token.is_none());
    
    // Only access token should be issued
    assert_eq!(*token_service.issued_access_tokens.borrow(), 1);
    assert_eq!(*token_service.issued_refresh_tokens.borrow(), 0);
}

#[test]
fn test_refresh_session_revoked_session() {
    let session_repo = MockSessionRepo::new();
    let token_service = MockTokenService::new();
    
    // Setup: Create a session and then revoke it
    session_repo.insert_session("session_123", "user123", "revoked_refresh_token");
    session_repo.revoke_session("session_123");
    
    let use_case = RefreshSession::new(
        &session_repo,
        &token_service,
        3600,
        true,
    );
    
    let input = RefreshSessionInput {
        refresh_token: Token::new("revoked_refresh_token"),
    };
    
    let result = use_case.execute(input);
    assert!(result.is_err(), "Refresh should fail for revoked session");
}

#[test]
fn test_refresh_session_token_expiration_config() {
    let session_repo = MockSessionRepo::new();
    let token_service = MockTokenService::new();
    
    session_repo.insert_session("session_123", "user123", "valid_refresh_token");
    
    // Test with different TTL values
    let ttl_values = vec![300, 3600, 86400];
    
    for ttl in ttl_values {
        let use_case = RefreshSession::new(
            &session_repo,
            &token_service,
            ttl,
            false,
        );
        
        let input = RefreshSessionInput {
            refresh_token: Token::new("valid_refresh_token"),
        };
        
        let result = use_case.execute(input);
        assert!(result.is_ok());
        
        let output = result.unwrap();
        assert_eq!(output.expires_in, ttl, "TTL should match configured value");
    }
}
