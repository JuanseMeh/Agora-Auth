//! Tests for logout handler

use axum::{
    body::Body,
    http::{Request, StatusCode},
    routing::post,
    Router,
};
use tower::ServiceExt;
use std::sync::Arc;

use crate::adapters::http::{
    dto::public::{LogoutRequest},
    state::AppState,
};

// ============================================================================
// Simple Integration Tests
// ============================================================================

#[tokio::test]
async fn test_logout_missing_both_session_and_token() {
    // Create a minimal state for testing
    let state = AppState::new(
        Arc::new(MockIdentityRepo),
        Arc::new(MockCredentialRepo),
        Arc::new(MockSessionRepo),
        Arc::new(MockPasswordHasher),
        Arc::new(MockTokenService),
        Arc::new(MockServiceRegistry),
        3600,  // access_token_ttl_seconds
        30,    // refresh_token_ttl_days
        true,  // rotate_refresh_tokens
    );
    
    let app = Router::new()
        .route("/auth/logout", post(crate::adapters::http::handlers::logout))
        .with_state(state);
    
    let request_body = LogoutRequest {
        session_id: None,
        refresh_token: None,
    };
    
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/logout")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&request_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    
    // Should return 400 Bad Request when neither session_id nor refresh_token provided
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_logout_invalid_json() {
    let state = AppState::new(
        Arc::new(MockIdentityRepo),
        Arc::new(MockCredentialRepo),
        Arc::new(MockSessionRepo),
        Arc::new(MockPasswordHasher),
        Arc::new(MockTokenService),
        Arc::new(MockServiceRegistry),
        3600,
        30,
        true,
    );
    
    let app = Router::new()
        .route("/auth/logout", post(crate::adapters::http::handlers::logout))
        .with_state(state);
    
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/logout")
                .header("content-type", "application/json")
                .body(Body::from("invalid json"))
                .unwrap(),
        )
        .await
        .unwrap();
    
    // Should return 400 Bad Request for invalid JSON (Axum returns 400 for JSON parse errors)
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// ============================================================================
// Mock Implementations
// ============================================================================

use crate::core::usecases::ports::{
    IdentityRepository, CredentialRepository, PasswordHasher, TokenService, 
    SessionRepository, ServiceRegistry
};
use crate::core::identity::{UserIdentity, WorkspaceIdentity};
use crate::core::credentials::StoredCredential;
use crate::core::token::Token;
use crate::core::usecases::ports::session_repository::Session;

struct MockIdentityRepo;
impl IdentityRepository for MockIdentityRepo {
    fn find_by_identifier(&self, _id: &str) -> Option<UserIdentity> { None }
    fn find_by_id(&self, _id: &str) -> Option<UserIdentity> { None }
    fn find_workspace_by_id(&self, _id: &str) -> Option<WorkspaceIdentity> { None }
    fn create(
        &self,
        _user_id: &uuid::Uuid,
        _identifier: &str,
        _password_hash: &str,
        _salt: &str,
        _algorithm: &str,
        _iterations: u32,
    ) -> Result<(), String> {
        Ok(())
    }
}

struct MockCredentialRepo;
impl CredentialRepository for MockCredentialRepo {
    fn get_by_user_id(&self, _user_id: &str) -> Option<StoredCredential> { None }
    fn update_failed_attempts(&self, _user_id: &str, _attempts: u32) {}
    fn lock_until(&self, _user_id: &str, _until: &str) {}
    fn update_password(&self, _user_id: &str, _new_credential: StoredCredential) {}
    fn initialize_credential_state(&self, _user_id: &str) -> Result<(), String> { Ok(()) }
}

struct MockPasswordHasher;
impl PasswordHasher for MockPasswordHasher {
    fn hash(&self, raw: &str) -> StoredCredential {
        StoredCredential::from_hash(format!("hashed_{}", raw))
    }
    fn verify(&self, raw: &str, stored: &StoredCredential) -> bool {
        stored.as_hash_str() == format!("hashed_{}", raw)
    }
}

struct MockTokenService;
impl TokenService for MockTokenService {
    fn issue_access_token(&self, _subject: &str, _claims: &str) -> Token {
        Token::new("access_token_123".to_string())
    }
    
    fn issue_refresh_token(&self, _subject: &str, _claims: &str) -> Token {
        Token::new("refresh_token_123".to_string())
    }
    
    fn validate_access_token(&self, token: &Token) -> Result<String, ()> {
        if token.value() == "valid_access_token" {
            Ok("claims".to_string())
        } else {
            Err(())
        }
    }
    
    fn validate_refresh_token(&self, token: &Token) -> Result<String, ()> {
        if token.value() == "valid_refresh_token" {
            Ok("claims".to_string())
        } else {
            Err(())
        }
    }
}

struct MockSessionRepo;
impl SessionRepository for MockSessionRepo {
    fn create_session(&self, _user: &UserIdentity, _refresh_token_hash: &str, _metadata: &str) {}
    
    fn find_by_refresh_token_hash(&self, _hash: &str) -> Option<Session> {
        None
    }
    
    fn revoke_session(&self, _session_id: &str) {}
    
    fn revoke_all_for_user(&self, _user_id: &str) {}
    
    fn delete_expired(&self) {}
}

struct MockServiceRegistry;
impl ServiceRegistry for MockServiceRegistry {
    fn validate_api_key(&self, key: &str) -> Option<String> {
        if key == "valid_api_key" {
            Some("test_service".to_string())
        } else {
            None
        }
    }
    
    fn is_service_active(&self, _service_id: &str) -> bool {
        true
    }
}
