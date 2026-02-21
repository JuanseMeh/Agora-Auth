//! Comprehensive tests for IssueSession use case.
use super::super::issue_session::{IssueSession, IssueSessionInput};
use crate::core::identity::UserIdentity;
use crate::core::token::Token;
use crate::core::usecases::ports::{SessionRepository, TokenService};
use crate::core::usecases::ports::session_repository::Session;

// ============================================================================
// Mock Implementations
// ============================================================================

struct MockSessionRepo {
    sessions: std::cell::RefCell<std::collections::HashMap<String, String>>, // session_id -> refresh_token_hash
    session_counter: std::cell::RefCell<u32>,
}

impl MockSessionRepo {
    fn new() -> Self {
        Self {
            sessions: std::cell::RefCell::new(std::collections::HashMap::new()),
            session_counter: std::cell::RefCell::new(0),
        }
    }
    
    fn get_session_count(&self) -> usize {
        self.sessions.borrow().len()
    }
}

impl SessionRepository for MockSessionRepo {
    fn create_session(&self, user: &UserIdentity, refresh_token_hash: &str, _metadata: &str) {
        let counter = *self.session_counter.borrow();
        *self.session_counter.borrow_mut() += 1;
        let session_id = format!("session_{}_{}", user.id(), counter);
        self.sessions.borrow_mut().insert(session_id, refresh_token_hash.to_string());
    }
    
    fn find_by_refresh_token_hash(&self, hash: &str) -> Option<Session> {
        // Find session by refresh token hash
        for (_session_id, stored_hash) in self.sessions.borrow().iter() {
            if stored_hash == hash {
                return Some(Session {});
            }
        }
        None
    }
    
    fn revoke_session(&self, session_id: &str) {
        self.sessions.borrow_mut().remove(session_id);
    }
    
    fn revoke_all_for_user(&self, _user_id: &str) {
        // Remove all sessions for the user (simplified)
        self.sessions.borrow_mut().clear();
    }
    
    fn delete_expired(&self) {
        // Delete expired sessions (simplified)
    }
}

struct MockTokenService {
    access_tokens_issued: std::cell::RefCell<u32>,
    refresh_tokens_issued: std::cell::RefCell<u32>,
}

impl MockTokenService {
    fn new() -> Self {
        Self {
            access_tokens_issued: std::cell::RefCell::new(0),
            refresh_tokens_issued: std::cell::RefCell::new(0),
        }
    }
}

impl TokenService for MockTokenService {
    fn issue_access_token(&self, user_id: &str, _claims: &str) -> Token {
        *self.access_tokens_issued.borrow_mut() += 1;
        Token::new(format!("access_token_for_{}", user_id))
    }
    
    fn issue_refresh_token(&self, user_id: &str, _claims: &str) -> Token {
        *self.refresh_tokens_issued.borrow_mut() += 1;
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
        if token.value().starts_with("refresh_token_for_") {
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
fn test_issue_session_success() {
    let session_repo = MockSessionRepo::new();
    let token_service = MockTokenService::new();
    
    let use_case = IssueSession::new(
        &session_repo,
        &token_service,
        3600,  // access_token_ttl_seconds
        30,    // refresh_token_ttl_days
    );
    
    let input = IssueSessionInput {
        user: UserIdentity::new("user123"),
        ip_address: "127.0.0.1".to_string(),
        user_agent: "Mozilla/5.0".to_string(),
    };
    
    let result = use_case.execute(input);
    assert!(result.is_ok(), "Session issuance should succeed");
    
    let output = result.unwrap();
    
    // Verify output contains expected fields
    assert!(!output.access_token.value().is_empty());
    assert!(!output.refresh_token.value().is_empty());
    assert!(!output.session_id.is_empty());
    assert_eq!(output.expires_in, 3600);
    
    // Verify session was created
    assert_eq!(session_repo.get_session_count(), 1);
    
    // Verify tokens were issued
    assert_eq!(*token_service.access_tokens_issued.borrow(), 1);
    assert_eq!(*token_service.refresh_tokens_issued.borrow(), 1);
}

#[test]
fn test_issue_session_creates_unique_session_id() {
    let session_repo = MockSessionRepo::new();
    let token_service = MockTokenService::new();
    
    let use_case = IssueSession::new(
        &session_repo,
        &token_service,
        3600,
        30,
    );
    
    // Issue multiple sessions for the same user
    let input1 = IssueSessionInput {
        user: UserIdentity::new("user123"),
        ip_address: "127.0.0.1".to_string(),
        user_agent: "Device1".to_string(),
    };
    
    let input2 = IssueSessionInput {
        user: UserIdentity::new("user123"),
        ip_address: "192.168.1.1".to_string(),
        user_agent: "Device2".to_string(),
    };
    
    let output1 = use_case.execute(input1).unwrap();
    let output2 = use_case.execute(input2).unwrap();
    
    // Session IDs should be different
    assert_ne!(output1.session_id, output2.session_id);
    
    // Both sessions should exist
    assert_eq!(session_repo.get_session_count(), 2);
}

#[test]
fn test_issue_session_token_format() {
    let session_repo = MockSessionRepo::new();
    let token_service = MockTokenService::new();
    
    let use_case = IssueSession::new(
        &session_repo,
        &token_service,
        3600,
        30,
    );
    
    let input = IssueSessionInput {
        user: UserIdentity::new("user456"),
        ip_address: "10.0.0.1".to_string(),
        user_agent: "TestAgent".to_string(),
    };
    
    let output = use_case.execute(input).unwrap();
    
    // Tokens should contain user reference
    assert!(output.access_token.value().contains("user456"));
    assert!(output.refresh_token.value().contains("user456"));
}

#[test]
fn test_issue_session_different_users() {
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
        
        let output = use_case.execute(input).unwrap();
        session_ids.insert(output.session_id.clone());
        
        // Each user should get tokens with their ID
        assert!(output.access_token.value().contains(user_id));
    }
    
    // All session IDs should be unique
    assert_eq!(session_ids.len(), 3);
    assert_eq!(session_repo.get_session_count(), 3);
}

#[test]
fn test_issue_session_with_metadata() {
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
    
    let result = use_case.execute(input);
    assert!(result.is_ok());
    
    // Session should be created with metadata
    assert_eq!(session_repo.get_session_count(), 1);
}

#[test]
fn test_issue_session_token_expiration() {
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
        
        let output = use_case.execute(input).unwrap();
        assert_eq!(output.expires_in, ttl, "TTL should match configured value");
    }
}
