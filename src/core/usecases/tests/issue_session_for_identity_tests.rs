//! Tests for IssueSessionForIdentity use case.

use futures::future::BoxFuture;

use crate::core::error::CoreError;
use crate::core::identity::UserIdentity;
use crate::core::token::Token;
use crate::core::usecases::issue_session_for_identity::{
    IssueSessionForIdentity, IssueSessionForIdentityInput,
};
use crate::core::usecases::ports::{IdentityRepository, SessionRepository, TokenService};
use crate::core::usecases::ports::session_repository::Session;

// ============================================================================
// Mock Implementations
// ============================================================================

/// Mock IdentityRepository for testing
struct MockIdentityRepository {
    /// Map of user_id -> UserIdentity
    identities: std::sync::RwLock<std::collections::HashMap<String, UserIdentity>>,
}

impl MockIdentityRepository {
    fn new() -> Self {
        let mut identities = std::collections::HashMap::new();
        // Add a valid user
        identities.insert(
            "user123".to_string(),
            UserIdentity::new("user123"),
        );
        identities.insert(
            "user456".to_string(),
            UserIdentity::new("user456"),
        );
        Self {
            identities: std::sync::RwLock::new(identities),
        }
    }
}

impl IdentityRepository for MockIdentityRepository {
    fn find_by_identifier(&self, _identifier: &str) -> BoxFuture<'_, Option<UserIdentity>> {
        Box::pin(async { None })
    }

    fn find_by_id(&self, id: &str) -> BoxFuture<'_, Option<UserIdentity>> {
        let id = id.to_string();
        let identities = self.identities.read().unwrap().clone();
        Box::pin(async move { identities.get(&id).cloned() })
    }

    fn create(
        &self,
        _user_id: &uuid::Uuid,
        _identifier: &str,
        _password_hash: &str,
        _salt: &str,
        _algorithm: &str,
        _iterations: u32,
    ) -> BoxFuture<'_, Result<(), String>> {
        Box::pin(async { Ok(()) })
    }
}

/// Mock SessionRepository for testing
struct MockSessionRepository {
    sessions: std::sync::RwLock<std::collections::HashMap<String, String>>,
}

impl MockSessionRepository {
    fn new() -> Self {
        Self {
            sessions: std::sync::RwLock::new(std::collections::HashMap::new()),
        }
    }

    fn get_session_count(&self) -> usize {
        self.sessions.read().unwrap().len()
    }
}

impl SessionRepository for MockSessionRepository {
    fn create_session(
        &self,
        session_id: &str,
        _user: &UserIdentity,
        refresh_token_hash: &str,
        _metadata: &str,
    ) -> BoxFuture<'_, ()> {
        self.sessions
            .write()
            .unwrap()
            .insert(session_id.to_string(), refresh_token_hash.to_string());
        Box::pin(async move {})
    }

    fn find_by_refresh_token_hash(&self, _hash: &str) -> BoxFuture<'_, Option<Session>> {
        Box::pin(async { None })
    }

    fn find_by_id(&self, _session_id: &str) -> BoxFuture<'_, Option<Session>> {
        Box::pin(async { None })
    }

    fn revoke_session(&self, session_id: &str) -> BoxFuture<'_, ()> {
        self.sessions.write().unwrap().remove(session_id);
        Box::pin(async move {})
    }

    fn revoke_all_for_user(&self, _user_id: &str) -> BoxFuture<'_, ()> {
        self.sessions.write().unwrap().clear();
        Box::pin(async move {})
    }

    fn delete_expired(&self) -> BoxFuture<'_, ()> {
        Box::pin(async move {})
    }
}

/// Mock TokenService for testing
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
        if token.value().contains("access_token_for_") {
            Ok("user123".to_string())
        } else {
            Err(())
        }
    }

    fn validate_refresh_token(&self, token: &Token) -> Result<String, ()> {
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
async fn test_issue_session_for_identity_success() {
    let identity_repo = MockIdentityRepository::new();
    let session_repo = MockSessionRepository::new();
    let token_service = MockTokenService::new();

    let use_case = IssueSessionForIdentity::new(
        &identity_repo,
        &session_repo,
        &token_service,
        3600,  // access_token_ttl_seconds
        30,    // refresh_token_ttl_days
    );

    let input = IssueSessionForIdentityInput {
        user_id: "user123".to_string(),
        issued_by_service_id: Some("test_service".to_string()),
    };

    let result = use_case.execute(input).await;
    assert!(result.is_ok(), "Session should be issued successfully");

    let output = result.unwrap();
    assert!(!output.access_token.is_empty());
    assert!(!output.refresh_token.is_empty());
    assert!(!output.session_id.is_empty());
    assert_eq!(output.expires_in, 3600);

    // Verify session was created
    assert_eq!(session_repo.get_session_count(), 1);

    // Verify token service was called
    assert_eq!(*token_service.access_tokens_issued.read().unwrap(), 1);
    assert_eq!(*token_service.refresh_tokens_issued.read().unwrap(), 1);
}

#[tokio::test]
async fn test_issue_session_for_identity_user_not_found() {
    let identity_repo = MockIdentityRepository::new();
    let session_repo = MockSessionRepository::new();
    let token_service = MockTokenService::new();

    let use_case = IssueSessionForIdentity::new(
        &identity_repo,
        &session_repo,
        &token_service,
        3600,
        30,
    );

    let input = IssueSessionForIdentityInput {
        user_id: "nonexistent_user".to_string(),
        issued_by_service_id: None,
    };

    let result = use_case.execute(input).await;
    assert!(result.is_err());

    let err = result.unwrap_err();
    match err {
        CoreError::Authentication(auth_err) => {
            // Check that it's a UserNotFound variant
            assert!(matches!(
                auth_err,
                crate::core::error::AuthenticationError::UserNotFound { .. }
            ));
        }
        _ => panic!("Expected Authentication error"),
    }
}

#[tokio::test]
async fn test_issue_session_for_identity_without_service_id() {
    let identity_repo = MockIdentityRepository::new();
    let session_repo = MockSessionRepository::new();
    let token_service = MockTokenService::new();

    let use_case = IssueSessionForIdentity::new(
        &identity_repo,
        &session_repo,
        &token_service,
        3600,
        30,
    );

    let input = IssueSessionForIdentityInput {
        user_id: "user456".to_string(),
        issued_by_service_id: None,
    };

    let result = use_case.execute(input).await;
    assert!(result.is_ok(), "Session should be issued without service ID");

    let output = result.unwrap();
    assert!(!output.access_token.is_empty());
    assert!(!output.refresh_token.is_empty());

    // Session should still be created
    assert_eq!(session_repo.get_session_count(), 1);
}

#[tokio::test]
async fn test_issue_session_for_identity_different_users() {
    let identity_repo = MockIdentityRepository::new();
    let session_repo = MockSessionRepository::new();
    let token_service = MockTokenService::new();

    let use_case = IssueSessionForIdentity::new(
        &identity_repo,
        &session_repo,
        &token_service,
        3600,
        30,
    );

    // Issue sessions for different users
    let users = vec!["user123", "user456"];
    let mut session_ids = std::collections::HashSet::new();

    for user_id in users {
        let input = IssueSessionForIdentityInput {
            user_id: user_id.to_string(),
            issued_by_service_id: None,
        };

        let output = use_case.execute(input).await.unwrap();
        session_ids.insert(output.session_id.clone());

        // Each user should get tokens with their ID
        assert!(output.access_token.contains(user_id));
    }

    // All session IDs should be unique
    assert_eq!(session_ids.len(), 2);
    assert_eq!(session_repo.get_session_count(), 2);
}

#[tokio::test]
async fn test_issue_session_for_identity_token_expiration() {
    let identity_repo = MockIdentityRepository::new();
    let session_repo = MockSessionRepository::new();
    let token_service = MockTokenService::new();

    // Test with different TTL values
    let ttl_values = vec![300, 3600, 86400]; // 5 min, 1 hour, 1 day

    for ttl in ttl_values {
        let use_case = IssueSessionForIdentity::new(
            &identity_repo,
            &session_repo,
            &token_service,
            ttl,
            30,
        );

        let input = IssueSessionForIdentityInput {
            user_id: "user123".to_string(),
            issued_by_service_id: None,
        };

        let output = use_case.execute(input).await.unwrap();
        assert_eq!(output.expires_in, ttl, "TTL should match configured value");
    }
}

