//! Comprehensive tests for RefreshSession use case.

use futures::future::BoxFuture;
use super::super::refresh_session::{RefreshSession, RefreshSessionInput};
use crate::core::token::Token;
use crate::core::usecases::ports::{SessionRepository, TokenService};
use crate::core::usecases::ports::session_repository::Session as SessionType;

// ============================================================================
// Mock Implementations
// ============================================================================

struct MockSessionRepo {
    sessions: std::sync::RwLock<std::collections::HashMap<String, SessionData>>, // session_id -> session data
    revoked_sessions: std::sync::RwLock<std::collections::HashSet<String>>,
}

struct SessionData {
    _user_id: String,
    refresh_token_hash: String,
    revoked: bool,
}

impl MockSessionRepo {
    fn new() -> Self {
        Self {
            sessions: std::sync::RwLock::new(std::collections::HashMap::new()),
            revoked_sessions: std::sync::RwLock::new(std::collections::HashSet::new()),
        }
    }
    
    fn insert_session(&self, session_id: &str, user_id: &str, refresh_token: &str) {
        // Hash the token to store it (matches RefreshSession use case behavior)
        let refresh_token_hash = Self::hash_token(refresh_token);
        self.sessions.write().unwrap().insert(
            session_id.to_string(),
            SessionData {
                _user_id: user_id.to_string(),
                refresh_token_hash,
                revoked: false,
            },
        );
    }
    
    fn _is_revoked(&self, session_id: &str) -> bool {
        self.revoked_sessions.read().unwrap().contains(session_id)
    }
    
    fn hash_token(token: &str) -> String {
        use sha2::{Sha256, Digest};
        
        
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        let result = hasher.finalize();
        result.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

impl SessionRepository for MockSessionRepo {
    fn create_session(&self, _session_id: &str, _user: &crate::core::identity::UserIdentity, _refresh_token_hash: &str, _metadata: &str) -> BoxFuture<'_, ()> {
        // Not used in refresh tests
        Box::pin(async move {})
    }
    
    fn find_by_refresh_token_hash(&self, hash: &str) -> BoxFuture<'_, Option<SessionType>> {
        let sessions = self.sessions.read().unwrap();
        let result = sessions.values().find(|data| data.refresh_token_hash == hash && !data.revoked).map(|_| SessionType {});
        Box::pin(async move { result })
    }

    fn find_by_id(&self, _session_id: &str) -> BoxFuture<'_, Option<SessionType>> {
        Box::pin(async move { None })
    }
    
    fn revoke_session(&self, session_id: &str) -> BoxFuture<'_, ()> {
        self.revoked_sessions.write().unwrap().insert(session_id.to_string());
        Box::pin(async move {})
    }
    
    fn revoke_all_for_user(&self, _user_id: &str) -> BoxFuture<'_, ()> {
        Box::pin(async move {})
    }
    
    fn delete_expired(&self) -> BoxFuture<'_, ()> {
        Box::pin(async move {})
    }
}

struct MockTokenService {
    issued_access_tokens: std::sync::RwLock<u32>,
    issued_refresh_tokens: std::sync::RwLock<u32>,
    valid_tokens: std::sync::RwLock<std::collections::HashSet<String>>,
}

impl MockTokenService {
    fn new() -> Self {
        Self {
            issued_access_tokens: std::sync::RwLock::new(0),
            issued_refresh_tokens: std::sync::RwLock::new(0),
            valid_tokens: std::sync::RwLock::new(std::collections::HashSet::new()),
        }
    }
    
    fn add_valid_token(&self, token: &str) {
        self.valid_tokens.write().unwrap().insert(token.to_string());
    }
}

impl TokenService for MockTokenService {
    fn issue_access_token(&self, subject: &str, _claims: &str) -> Token {
        *self.issued_access_tokens.write().unwrap() += 1;
        let token = Token::new(&format!("access_token_for_{}", subject));
        self.valid_tokens.write().unwrap().insert(token.value().to_string());
        token
    }
    
    fn issue_refresh_token(&self, subject: &str, _claims: &str) -> Token {
        *self.issued_refresh_tokens.write().unwrap() += 1;
        let token = Token::new(&format!("refresh_token_for_{}", subject));
        self.valid_tokens.write().unwrap().insert(token.value().to_string());
        token
    }

    fn issue_service_token(&self, subject: &str, _claims: &str) -> Token {
        Token::new(&format!("service_token_for_{}", subject))
    }
    
    fn validate_access_token(&self, token: &Token) -> Result<String, ()> {
        if self.valid_tokens.read().unwrap().contains(token.value()) {
            // Return claims with proper format including sub field
            Ok(r#"{"sub":"user123","type":"access"}"#.to_string())
        } else {
            Err(())
        }
    }
    
    fn validate_refresh_token(&self, token: &Token) -> Result<String, ()> {
        if self.valid_tokens.read().unwrap().contains(token.value()) {
            // Return claims with proper format including sub and sid fields
            Ok(r#"{"sub":"user123","type":"refresh","sid":"session_123"}"#.to_string())
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

// ============================================================================
// Test Cases
// ============================================================================

#[tokio::test]
async fn test_refresh_session_success() {
    let session_repo = MockSessionRepo::new();
    let token_service = MockTokenService::new();
    
    // Setup: Create a valid session with a token that will be marked as valid
    token_service.add_valid_token("valid_refresh_token");
    session_repo.insert_session("session_123", "user123", "valid_refresh_token");
    
    let use_case = RefreshSession::new(
        &session_repo,
        &token_service,
        3600,
        true,  // Enable rotation
    );
    
    let input = RefreshSessionInput {
        refresh_token: Token::new("valid_refresh_token"),
    };
    
    let result = use_case.execute(input).await;
    assert!(result.is_ok(), "Refresh should succeed with valid token");
    
    let output = result.unwrap();
    
    // Verify new tokens were issued
    assert!(!output.access_token.value().is_empty());
    assert!(output.refresh_token.is_some());
    assert!(!output.refresh_token.unwrap().value().is_empty());
    
    // Verify both access and refresh tokens were issued
    assert_eq!(*token_service.issued_access_tokens.read().unwrap(), 1);
    assert_eq!(*token_service.issued_refresh_tokens.read().unwrap(), 1);
}

#[tokio::test]
async fn test_refresh_session_invalid_token() {
    let session_repo = MockSessionRepo::new();
    let token_service = MockTokenService::new();
    
    // No session setup - token won't be found
    
    let use_case = RefreshSession::new(
        &session_repo,
        &token_service,
        3600,
        true,
    );
    
    let input = RefreshSessionInput {
        refresh_token: Token::new("invalid_refresh_token"),
    };
    
    let result = use_case.execute(input).await;
    assert!(result.is_err(), "Refresh should fail with invalid token");
}

#[tokio::test]
async fn test_refresh_session_rotation() {
    let session_repo = MockSessionRepo::new();
    let token_service = MockTokenService::new();
    
    // Setup: Create a valid session
    token_service.add_valid_token("valid_refresh_token");
    session_repo.insert_session("session_123", "user123", "valid_refresh_token");
    
    let use_case = RefreshSession::new(
        &session_repo,
        &token_service,
        3600,
        true,  // Enable rotation
    );
    
    let input = RefreshSessionInput {
        refresh_token: Token::new("valid_refresh_token"),
    };
    
    let result = use_case.execute(input).await;
    assert!(result.is_ok());
    
    let output = result.unwrap();
    
    // With rotation enabled, refresh_token should be Some
    assert!(output.refresh_token.is_some());
    
    // Both access and refresh tokens should be issued
    assert_eq!(*token_service.issued_access_tokens.read().unwrap(), 1);
    assert_eq!(*token_service.issued_refresh_tokens.read().unwrap(), 1);
}

#[tokio::test]
async fn test_refresh_session_no_rotation() {
    let session_repo = MockSessionRepo::new();
    let token_service = MockTokenService::new();
    
    // Setup: Create a valid session
    token_service.add_valid_token("valid_refresh_token");
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
    
    let result = use_case.execute(input).await;
    assert!(result.is_ok());
    
    let output = result.unwrap();
    
    // With rotation disabled, refresh_token should be None
    assert!(output.refresh_token.is_none());
    
    // Only access token should be issued
    assert_eq!(*token_service.issued_access_tokens.read().unwrap(), 1);
    assert_eq!(*token_service.issued_refresh_tokens.read().unwrap(), 0);
}

#[tokio::test]
async fn test_refresh_session_revoked_session() {
    let session_repo = MockSessionRepo::new();
    let token_service = MockTokenService::new();
    
    // Setup: Create a session and then revoke it
    session_repo.insert_session("session_123", "user123", "revoked_refresh_token");
    session_repo.revoke_session("session_123").await;
    
    let use_case = RefreshSession::new(
        &session_repo,
        &token_service,
        3600,
        true,
    );
    
    let input = RefreshSessionInput {
        refresh_token: Token::new("revoked_refresh_token"),
    };
    
    let result = use_case.execute(input).await;
    assert!(result.is_err(), "Refresh should fail for revoked session");
}

#[tokio::test]
async fn test_refresh_session_token_expiration_config() {
    let session_repo = MockSessionRepo::new();
    let token_service = MockTokenService::new();
    
    token_service.add_valid_token("valid_refresh_token");
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
        
        let result = use_case.execute(input).await;
        assert!(result.is_ok());
        
        let output = result.unwrap();
        assert_eq!(output.expires_in, ttl, "TTL should match configured value");
    }
}
