//! Comprehensive tests for RevokeSession use case.

use futures::future::BoxFuture;
use super::super::revoke_session::{RevokeSession, RevokeSessionInput};
use crate::core::usecases::ports::SessionRepository;
use crate::core::usecases::ports::session_repository::Session as SessionType;
use crate::core::error::CoreError;

// ============================================================================
// Mock Implementations
// ============================================================================

struct MockSessionRepo {
    sessions: std::sync::RwLock<std::collections::HashMap<String, SessionData>>, // session_id -> session data
    revoked_sessions: std::sync::RwLock<std::collections::HashSet<String>>,
}

struct SessionData {
    user_id: String,
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
    
    fn insert_session(&self, session_id: &str, user_id: &str, refresh_token_hash: &str) {
        self.sessions.write().unwrap().insert(
            session_id.to_string(),
            SessionData {
                user_id: user_id.to_string(),
                refresh_token_hash: refresh_token_hash.to_string(),
                revoked: false,
            },
        );
    }
    
    fn is_revoked(&self, session_id: &str) -> bool {
        self.revoked_sessions.read().unwrap().contains(session_id)
    }
}

impl SessionRepository for MockSessionRepo {
    fn create_session(&self, _session_id: &str, _user: &crate::core::identity::UserIdentity, _refresh_token_hash: &str, _metadata: &str) -> BoxFuture<'_, ()> {
        Box::pin(async move {})
    }
    
    fn find_by_refresh_token_hash(&self, hash: &str) -> BoxFuture<'_, Option<SessionType>> {
        let sessions = self.sessions.read().unwrap();
        let result = sessions.values().find(|data| data.refresh_token_hash == hash && !data.revoked).map(|_| SessionType {});
        Box::pin(async move { result })
    }

    fn find_by_id(&self, session_id: &str) -> BoxFuture<'_, Option<SessionType>> {
        let sessions = self.sessions.read().unwrap();
        let is_revoked = self.revoked_sessions.read().unwrap().contains(session_id);
        // Return session only if it exists and is NOT revoked
        let result = sessions.get(session_id).filter(|_data| !is_revoked).map(|_| SessionType {});
        Box::pin(async move { result })
    }
    
    fn revoke_session(&self, session_id: &str) -> BoxFuture<'_, ()> {
        self.revoked_sessions.write().unwrap().insert(session_id.to_string());
        Box::pin(async move {})
    }
    
    fn revoke_all_for_user(&self, user_id: &str) -> BoxFuture<'_, ()> {
        let sessions = self.sessions.read().unwrap();
        let session_ids: Vec<String> = sessions
            .iter()
            .filter(|(_, data)| data.user_id == user_id)
            .map(|(id, _)| id.clone())
            .collect();
        
        drop(sessions); // Release read lock before acquiring write lock
        
        let mut revoked = self.revoked_sessions.write().unwrap();
        for id in session_ids {
            revoked.insert(id);
        }
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
async fn test_revoke_session_by_id_success() {
    let session_repo = MockSessionRepo::new();
    
    // Setup: Create a session
    session_repo.insert_session("session_123", "user123", "hash_123");
    
    let use_case = RevokeSession::new(&session_repo);
    
    let input = RevokeSessionInput {
        session_id: Some("session_123".to_string()),
        refresh_token_hash: None,
    };
    
    let result = use_case.execute(input).await;
    assert!(result.is_ok(), "Revoke should succeed");
    
    let output = result.unwrap();
    assert!(output.revoked);
    assert_eq!(output.session_id, Some("session_123".to_string()));
}

#[tokio::test]
async fn test_revoke_session_missing_input() {
    let session_repo = MockSessionRepo::new();
    
    let use_case = RevokeSession::new(&session_repo);
    
    // Neither session_id nor refresh_token_hash provided
    let input = RevokeSessionInput {
        session_id: None,
        refresh_token_hash: None,
    };
    
    let result = use_case.execute(input).await;
    assert!(result.is_err(), "Should fail with missing input");
    
    match result.unwrap_err() {
        CoreError::Invariant(_) => {} // Expected
        _ => panic!("Expected InvariantError"),
    }
}

#[tokio::test]
async fn test_revoke_session_already_revoked() {
    let session_repo = MockSessionRepo::new();
    
    // Setup: Create and revoke a session
    session_repo.insert_session("session_123", "user123", "hash_123");
    session_repo.revoke_session("session_123").await;
    
    let use_case = RevokeSession::new(&session_repo);
    
    let input = RevokeSessionInput {
        session_id: Some("session_123".to_string()),
        refresh_token_hash: None,
    };
    
    // Should fail because session is already revoked (new validation behavior)
    let result = use_case.execute(input).await;
    assert!(result.is_err());
    
    // Verify the error is "session revoked or expired"
    match result.unwrap_err() {
        CoreError::Authentication(auth_err) => {
            assert_eq!(auth_err.to_string(), "User not found: session revoked or expired");
        }
        _ => panic!("Expected AuthenticationError"),
    }
}

#[tokio::test]
async fn test_revoke_session_output_structure() {
    let session_repo = MockSessionRepo::new();
    
    session_repo.insert_session("session_123", "user123", "hash_123");
    
    let use_case = RevokeSession::new(&session_repo);
    
    let input = RevokeSessionInput {
        session_id: Some("session_123".to_string()),
        refresh_token_hash: None,
    };
    
    let result = use_case.execute(input).await;
    assert!(result.is_ok());
    
    let output = result.unwrap();
    assert!(output.revoked);
    assert!(output.session_id.is_some());
}

#[tokio::test]
async fn test_revoke_session_by_refresh_token_hash_not_implemented() {
    let session_repo = MockSessionRepo::new();
    
    // Setup: Create a session
    session_repo.insert_session("session_123", "user123", "refresh_hash_123");
    
    let use_case = RevokeSession::new(&session_repo);
    
    // Try to revoke by refresh token hash
    let input = RevokeSessionInput {
        session_id: None,
        refresh_token_hash: Some("refresh_hash_123".to_string()),
    };
    
    // This should fail because lookup by refresh token hash is not fully implemented
    let result = use_case.execute(input).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_revoke_session_multiple_sessions() {
    let session_repo = MockSessionRepo::new();
    
    // Setup: Create multiple sessions for the same user
    session_repo.insert_session("session_1", "user123", "hash_1");
    session_repo.insert_session("session_2", "user123", "hash_2");
    session_repo.insert_session("session_3", "user456", "hash_3"); // Different user
    
    let use_case = RevokeSession::new(&session_repo);
    
    // Revoke first session
    let input = RevokeSessionInput {
        session_id: Some("session_1".to_string()),
        refresh_token_hash: None,
    };
    
    let result = use_case.execute(input).await;
    assert!(result.is_ok());
    
    // Verify only session_1 was revoked
    assert!(session_repo.is_revoked("session_1"));
    assert!(!session_repo.is_revoked("session_2"));
    assert!(!session_repo.is_revoked("session_3"));
}
