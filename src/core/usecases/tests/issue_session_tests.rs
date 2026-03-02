//! Comprehensive tests for IssueSession use case.

use futures::future::BoxFuture;
use super::super::issue_session::{IssueSession, IssueSessionInput};
use crate::core::identity::UserIdentity;
use crate::core::token::Token;
use crate::core::usecases::ports::{SessionRepository, TokenService};
use crate::core::usecases::ports::session_repository::Session;

// ============================================================================
// Mock Implementations
// ============================================================================

struct MockSessionRepo {
    sessions: std::sync::RwLock<std::collections::HashMap<String, String>>, // session_id -> refresh_token_hash
}

impl MockSessionRepo {
    fn new() -> Self {
        Self {
            sessions: std::sync::RwLock::new(std::collections::HashMap::new()),
        }
    }
    
    fn get_session_count(&self) -> usize {
        self.sessions.read().unwrap().len()
    }
}

impl SessionRepository for MockSessionRepo {
    fn create_session(&self, session_id: &str, _user: &UserIdentity, refresh_token_hash: &str, _metadata: &str) -> BoxFuture<'_, ()> {
        self.sessions.write().unwrap().insert(session_id.to_string(), refresh_token_hash.to_string());
        Box::pin(async move {})
    }
    
    fn find_by_refresh_token_hash(&self, hash: &str) -> BoxFuture<'_, Option<Session>> {
        let sessions = self.sessions.read().unwrap();
        let result = sessions.values().any(|stored_hash| stored_hash == hash).then_some(Session {});
        Box::pin(async move { result })
    }

    fn find_by_id(&self, _session_id: &str) -> BoxFuture<'_, Option<Session>> {
        Box::pin(async move { Some(Session {}) })
    }
    
    fn revoke_session(&self, session_id: &str) -> BoxFuture<'_, ()> {
        self.sessions.write().unwrap().remove(session_id);
        Box::pin(async move {})
    }
    
    fn revoke_all_for_user(&self, _user_id: &str) -> BoxFuture<'_, ()> {
        // Remove all sessions for the user (simplified)
        self.sessions.write().unwrap().clear();
        Box::pin(async move {})
    }
    
    fn delete_expired(&self) -> BoxFuture<'_, ()> {
        // Delete expired sessions (simplified)
        Box::pin(async move {})
    }
}

struct MockTokenService {
    access_tokens_issued: std::sync::RwLock<u32>,
    refresh_tokens_issued: std::sync::RwLock<u32>,
}

impl MockTokenService {
    fn new() -> Self {
        Self {
            access_tokens_issued: std::sync::RwLock::new(0),
            refresh_tokens_issued: std::sync::RwLock::new(0),
        }
    }
}

impl TokenService for MockTokenService {
    fn issue_access_token(&self, subject: &str, _claims: &str) -> Token {
        *self.access_tokens_issued.write().unwrap() += 1;
        Token::new(&format!("access_token_for_{}", subject))
    }
    
    fn issue_refresh_token(&self, subject: &str, _claims: &str) -> Token {
        *self.refresh_tokens_issued.write().unwrap() += 1;
        Token::new(&format!("refresh_token_for_{}", subject))
    }

    fn issue_service_token(&self, subject: &str, _claims: &str) -> Token {
        Token::new(&format!("service_token_for_{}", subject))
    }
    
    fn validate_access_token(&self, token: &Token) -> Result<String, ()> {
        // Simple mock validation - just check if token contains expected format
        if token.value().contains("access_token_for_") {
            Ok("user123".to_string())
        } else {
            Err(())
        }
    }
    
    fn validate_refresh_token(&self, token: &Token) -> Result<String, ()> {
        // Simple mock validation
        if token.value().contains("refresh_token_for_") {
            Ok("user123".to_string())
        } else {
            Err(())
        }
    }

    fn validate_service_token(&self, token: &Token) -> Result<String, ()> {
        if token.value().contains("service_token_for_") {
            Ok("service123".to_string())
        } else {
            Err(())
        }
    }
}

// ============================================================================
// Test Cases
// ============================================================================

#[tokio::test]
async fn test_issue_session_success() {
    let session_repo = MockSessionRepo::new();
    let token_service = MockTokenService::new();
    
    let use_case = IssueSession::new(
        &session_repo,
        &token_service,
        3600, // access_token_ttl
        30,   // refresh_token_ttl_days
    );
    
    let input = IssueSessionInput {
        user: UserIdentity::new("user123"),
        ip_address: "127.0.0.1".to_string(),
        user_agent: "Test".to_string(),
    };
    
    let result = use_case.execute(input).await;
    assert!(result.is_ok(), "Session should be issued successfully");
    
    let output = result.unwrap();
    
    // Verify tokens were issued
    assert!(!output.access_token.value().is_empty());
    assert!(!output.refresh_token.value().is_empty());
    assert!(!output.session_id.is_empty());
    assert_eq!(output.expires_in, 3600);
    
    // Verify session was created
    assert_eq!(session_repo.get_session_count(), 1);
    
    // Verify token service was called
    assert_eq!(*token_service.access_tokens_issued.read().unwrap(), 1);
    assert_eq!(*token_service.refresh_tokens_issued.read().unwrap(), 1);
}

#[tokio::test]
async fn test_issue_session_different_users() {
    let session_repo = MockSessionRepo::new();
    let token_service = MockTokenService::new();
    
    let use_case = IssueSession::new(
        &session_repo,
        &token_service,
        3600,
        30,
    );
    
    // Issue sessions for different users
    let users = vec!["alice", "bob", "charlie"];
    let mut session_ids = std::collections::HashSet::new();
    
    for user_id in users {
        let input = IssueSessionInput {
            user: UserIdentity::new(user_id),
            ip_address: "127.0.0.1".to_string(),
            user_agent: "Test".to_string(),
        };
        
        let output = use_case.execute(input).await.unwrap();
        session_ids.insert(output.session_id.clone());
        
        // Each user should get tokens with their ID
        assert!(output.access_token.value().contains(user_id));
    }
    
    // All session IDs should be unique
    assert_eq!(session_ids.len(), 3);
    assert_eq!(session_repo.get_session_count(), 3);
}

#[tokio::test]
async fn test_issue_session_with_metadata() {
    let session_repo = MockSessionRepo::new();
    let token_service = MockTokenService::new();
    
    let use_case = IssueSession::new(
        &session_repo,
        &token_service,
        3600,
        30,
    );
    
    let input = IssueSessionInput {
        user: UserIdentity::new("user789"),
        ip_address: "203.0.113.1".to_string(),
        user_agent: "CustomApp/1.0".to_string(),
    };
    
    let result = use_case.execute(input).await;
    assert!(result.is_ok());
    
    // Session should be created with metadata
    assert_eq!(session_repo.get_session_count(), 1);
}

#[tokio::test]
async fn test_issue_session_token_expiration() {
    let session_repo = MockSessionRepo::new();
    let token_service = MockTokenService::new();
    
    // Test with different TTL values
    let ttl_values = vec![300, 3600, 86400]; // 5 min, 1 hour, 1 day
    
    for ttl in ttl_values {
        let use_case = IssueSession::new(
            &session_repo,
            &token_service,
            ttl,
            30,
        );
        
        let input = IssueSessionInput {
            user: UserIdentity::new(&format!("user_{}", ttl)),
            ip_address: "127.0.0.1".to_string(),
            user_agent: "Test".to_string(),
        };
        
        let output = use_case.execute(input).await.unwrap();
        assert_eq!(output.expires_in, ttl, "TTL should match configured value");
    }
}
