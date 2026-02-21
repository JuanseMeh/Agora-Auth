
//! Comprehensive tests for RevokeSession use case.

use super::super::revoke_session::{RevokeSession, RevokeSessionInput};
use crate::core::usecases::ports::SessionRepository;
use crate::core::usecases::ports::session_repository::Session as SessionType;
use crate::core::error::CoreError;

// ============================================================================
// Mock Implementations
// ============================================================================

struct MockSessionRepo {
    sessions: std::cell::RefCell<std::collections::HashMap<String, SessionData>>,
    revoked_sessions: std::cell::RefCell<std::collections::HashSet<String>>,
}

struct SessionData {
    user_id: String,
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
    
    fn insert_session(&self, session_id: &str, user_id: &str, refresh_token_hash: &str) {
        self.sessions.borrow_mut().insert(
            session_id.to_string(),
            SessionData {
                user_id: user_id.to_string(),
                refresh_token_hash: refresh_token_hash.to_string(),
                revoked: false,
            },
        );
    }
    
    fn is_revoked(&self, session_id: &str) -> bool {
        self.revoked_sessions.borrow().contains(session_id)
    }
}

impl SessionRepository for MockSessionRepo {
    fn create_session(&self, _user: &crate::core::identity::UserIdentity, _refresh_token_hash: &str, _metadata: &str) {
        // Not used in revoke tests
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
    
    fn revoke_all_for_user(&self, user_id: &str) {
        // Collect session IDs to revoke first to avoid borrow issues
        let session_ids_to_revoke: Vec<String> = {
            let sessions = self.sessions.borrow();
            sessions
                .iter()
                .filter(|(_, data)| data.user_id == user_id)
                .map(|(session_id, _)| session_id.clone())
                .collect()
        };
        
        // Now revoke each session
        for session_id in session_ids_to_revoke {
            self.revoke_session(&session_id);
        }
    }
    
    fn delete_expired(&self) {
        // Not used in revoke tests
    }
}

// ============================================================================
// Test Cases
// ============================================================================

#[test]
fn test_revoke_session_by_id_success() {
    let session_repo = MockSessionRepo::new();
    
    // Setup: Create a valid session
    session_repo.insert_session("session_123", "user123", "refresh_hash_123");
    
    let use_case = RevokeSession::new(&session_repo);
    
    let input = RevokeSessionInput {
        session_id: Some("session_123".to_string()),
        refresh_token_hash: None,
    };
    
    let result = use_case.execute(input);
    assert!(result.is_ok(), "Revoke should succeed with valid session_id");
    
    let output = result.unwrap();
    assert!(output.revoked);
    assert_eq!(output.session_id, Some("session_123".to_string()));
    
    // Verify session was actually revoked
    assert!(session_repo.is_revoked("session_123"));
}

#[test]
fn test_revoke_session_missing_input() {
    let session_repo = MockSessionRepo::new();
    let use_case = RevokeSession::new(&session_repo);
    
    // Neither session_id nor refresh_token_hash provided
    let input = RevokeSessionInput {
        session_id: None,
        refresh_token_hash: None,
    };
    
    let result = use_case.execute(input);
    assert!(result.is_err(), "Should fail when no identifier provided");
    
    match result.unwrap_err() {
        CoreError::Invariant(err) => {
            assert!(err.to_string().to_lowercase().contains("must be provided"));
        }
        _ => panic!("Expected InvariantError"),
    }
}

#[test]
fn test_revoke_session_already_revoked() {
    let session_repo = MockSessionRepo::new();
    
    // Setup: Create and revoke a session
    session_repo.insert_session("session_123", "user123", "refresh_hash_123");
    session_repo.revoke_session("session_123");
    
    let use_case = RevokeSession::new(&session_repo);
    
    let input = RevokeSessionInput {
        session_id: Some("session_123".to_string()),
        refresh_token_hash: None,
    };
    
    // Should succeed even if already revoked (idempotent)
    let result = use_case.execute(input);
    assert!(result.is_ok());
    
    let output = result.unwrap();
    assert!(output.revoked);
    assert!(session_repo.is_revoked("session_123"));
}

#[test]
fn test_revoke_session_output_structure() {
    let session_repo = MockSessionRepo::new();
    session_repo.insert_session("session_456", "user456", "refresh_hash_456");
    
    let use_case = RevokeSession::new(&session_repo);
    
    let input = RevokeSessionInput {
        session_id: Some("session_456".to_string()),
        refresh_token_hash: None,
    };
    
    let result = use_case.execute(input);
    assert!(result.is_ok());
    
    let output = result.unwrap();
    
    // Verify output structure
    assert!(output.revoked);
    assert_eq!(output.session_id, Some("session_456".to_string()));
}

#[test]
fn test_revoke_session_by_refresh_token_hash_not_implemented() {
    let session_repo = MockSessionRepo::new();
    
    // Setup: Create a session
    session_repo.insert_session("session_789", "user789", "refresh_hash_789");
    
    let use_case = RevokeSession::new(&session_repo);
    
    // Try to revoke by refresh token hash (not yet fully implemented)
    let input = RevokeSessionInput {
        session_id: None,
        refresh_token_hash: Some("refresh_hash_789".to_string()),
    };
    
    let result = use_case.execute(input);
    // Currently returns error because lookup by hash needs session_id extraction
    assert!(result.is_err());
}

#[test]
fn test_revoke_session_multiple_sessions() {
    let session_repo = MockSessionRepo::new();
    
    // Setup: Create multiple sessions for same user
    session_repo.insert_session("session_1", "user_multi", "hash_1");
    session_repo.insert_session("session_2", "user_multi", "hash_2");
    session_repo.insert_session("session_3", "user_multi", "hash_3");
    
    let use_case = RevokeSession::new(&session_repo);
    
    // Revoke each session individually
    for i in 1..=3 {
        let session_id = format!("session_{}", i);
        let input = RevokeSessionInput {
            session_id: Some(session_id.clone()),
            refresh_token_hash: None,
        };
        
        let result = use_case.execute(input);
        assert!(result.is_ok());
        
        let output = result.unwrap();
        assert!(output.revoked);
        assert_eq!(output.session_id, Some(session_id));
    }
    
    // Verify all sessions are revoked
    assert!(session_repo.is_revoked("session_1"));
    assert!(session_repo.is_revoked("session_2"));
    assert!(session_repo.is_revoked("session_3"));
}
