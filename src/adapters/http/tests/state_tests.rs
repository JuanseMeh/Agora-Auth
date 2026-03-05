//! Tests for AppState

use std::sync::Arc;
use futures::future::BoxFuture;
use crate::adapters::http::state::AppState;
use crate::core::usecases::ports::{
    IdentityRepository, CredentialRepository, SessionRepository, TokenService, PasswordHasher, ServiceRegistry,
};
use crate::core::identity::UserIdentity;
use crate::core::credentials::StoredCredential;
use crate::core::token::Token;

// ============================================================================
// Mock Implementations
// ============================================================================

struct MockIdentityRepo;
struct MockCredentialRepo;
struct MockSessionRepo;
struct MockTokenService;
struct MockPasswordHasher;
struct MockServiceRegistry;

impl IdentityRepository for MockIdentityRepo {
    fn find_by_identifier(&self, _identifier: &str) -> BoxFuture<'_, Option<UserIdentity>> {
        Box::pin(async move { None })
    }
    
    fn find_by_id(&self, _id: &str) -> BoxFuture<'_, Option<UserIdentity>> {
        Box::pin(async move { None })
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
        Box::pin(async move { Ok(()) })
    }
}

impl CredentialRepository for MockCredentialRepo {
    fn get_by_user_id(&self, _user_id: &str) -> BoxFuture<'_, Option<StoredCredential>> {
        Box::pin(async move { None })
    }
    
    fn update_failed_attempts(&self, _user_id: &str, _attempts: u32) -> BoxFuture<'_, ()> {
        Box::pin(async move {})
    }
    
    fn lock_until(&self, _user_id: &str, _until: &str) -> BoxFuture<'_, ()> {
        Box::pin(async move {})
    }
    
    fn update_password(&self, _user_id: &str, _new_credential: StoredCredential) -> BoxFuture<'_, ()> {
        Box::pin(async move {})
    }
    
    fn initialize_credential_state(&self, _user_id: &str) -> BoxFuture<'_, Result<(), String>> {
        Box::pin(async move { Ok(()) })
    }
}

impl SessionRepository for MockSessionRepo {
    fn create_session(&self, _session_id: &str, _user: &crate::core::identity::UserIdentity, _refresh_token_hash: &str, _metadata: &str) -> BoxFuture<'_, ()> {
        Box::pin(async move {})
    }
    
    fn find_by_refresh_token_hash(&self, _hash: &str) -> BoxFuture<'_, Option<crate::core::usecases::ports::session_repository::Session>> {
        Box::pin(async move { None })
    }

    fn find_by_id(&self, _session_id: &str) -> BoxFuture<'_, Option<crate::core::usecases::ports::session_repository::Session>> {
        Box::pin(async move { None })
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

impl TokenService for MockTokenService {
    fn issue_access_token(&self, user_id: &str, _claims: &str) -> Token {
        Token::new(format!("access_{}", user_id))
    }
    
    fn issue_refresh_token(&self, user_id: &str, _claims: &str) -> Token {
        Token::new(format!("refresh_{}", user_id))
    }

    fn issue_service_token(&self, subject: &str, _claims: &str) -> Token {
        Token::new(format!("service_{}", subject))
    }
    
    fn validate_access_token(&self, _token: &Token) -> Result<String, ()> {
        Ok(r#"{"sub":"user123","type":"access"}"#.to_string())
    }
    
    fn validate_refresh_token(&self, _token: &Token) -> Result<String, ()> {
        Ok(r#"{"sub":"user123","type":"refresh"}"#.to_string())
    }

    fn validate_service_token(&self, _token: &Token) -> Result<String, ()> {
        Ok(r#"{"sub":"service123","type":"service"}"#.to_string())
    }
}

impl PasswordHasher for MockPasswordHasher {
    fn hash(&self, raw: &str) -> StoredCredential {
        StoredCredential::from_hash(format!("hashed_{}", raw))
    }
    
    fn verify(&self, raw: &str, stored: &StoredCredential) -> bool {
        stored.as_hash_str() == format!("hashed_{}", raw)
    }
}

impl ServiceRegistry for MockServiceRegistry {
    fn validate_api_key(&self, _api_key: &str) -> Option<String> {
        Some("test-service".to_string())
    }
    
    fn is_service_active(&self, _service_name: &str) -> bool {
        true
    }
    
    fn validate_credentials(
        &self, 
        _service_id: &str, 
        _service_secret: &str,
        _password_hasher: Arc<dyn PasswordHasher + Send + Sync>,
    ) -> Option<String> {
        None
    }
}

// ============================================================================
// Test Cases
// ============================================================================

#[test]
fn test_app_state_creation() {
    let state = AppState::new(
        Arc::new(MockIdentityRepo),
        Arc::new(MockCredentialRepo),
        Arc::new(MockSessionRepo),
        Arc::new(MockPasswordHasher),
        Arc::new(MockTokenService),
        Arc::new(MockServiceRegistry),
        3600,      // access_token_ttl_seconds
        7,         // refresh_token_ttl_days
        true,      // rotate_refresh_tokens
        3600,      // service_token_ttl_seconds
    );
    
    // Verify the state was created successfully
    assert_eq!(state.access_token_ttl_seconds, 3600);
    assert_eq!(state.refresh_token_ttl_days, 7);
    assert!(state.rotate_refresh_tokens);
    assert_eq!(state.service_token_ttl_seconds, 3600);
}

#[test]
fn test_app_state_clone() {
    let state = AppState::new(
        Arc::new(MockIdentityRepo),
        Arc::new(MockCredentialRepo),
        Arc::new(MockSessionRepo),
        Arc::new(MockPasswordHasher),
        Arc::new(MockTokenService),
        Arc::new(MockServiceRegistry),
        3600,
        7,
        true,
        3600,
    );
    
    // Clone should work since all fields are Arc or Copy types
    let cloned = state.clone();
    
    assert_eq!(cloned.access_token_ttl_seconds, state.access_token_ttl_seconds);
    assert_eq!(cloned.refresh_token_ttl_days, state.refresh_token_ttl_days);
    assert_eq!(cloned.rotate_refresh_tokens, state.rotate_refresh_tokens);
    assert_eq!(cloned.service_token_ttl_seconds, state.service_token_ttl_seconds);
}

#[test]
fn test_app_state_default_token_ttls() {
    // Test with different TTL configurations
    let short_lived = AppState::new(
        Arc::new(MockIdentityRepo),
        Arc::new(MockCredentialRepo),
        Arc::new(MockSessionRepo),
        Arc::new(MockPasswordHasher),
        Arc::new(MockTokenService),
        Arc::new(MockServiceRegistry),
        900,   // 15 minutes
        1,     // 1 day
        false,
        1800,  // 30 minutes
    );
    
    assert_eq!(short_lived.access_token_ttl_seconds, 900);
    assert_eq!(short_lived.refresh_token_ttl_days, 1);
    assert!(!short_lived.rotate_refresh_tokens);
    assert_eq!(short_lived.service_token_ttl_seconds, 1800);
}

#[test]
fn test_app_state_long_lived_tokens() {
    // Test with long-lived tokens (e.g., for mobile apps)
    let long_lived = AppState::new(
        Arc::new(MockIdentityRepo),
        Arc::new(MockCredentialRepo),
        Arc::new(MockSessionRepo),
        Arc::new(MockPasswordHasher),
        Arc::new(MockTokenService),
        Arc::new(MockServiceRegistry),
        86400, // 1 day
        30,    // 30 days
        true,
        7200,  // 2 hours
    );
    
    assert_eq!(long_lived.access_token_ttl_seconds, 86400);
    assert_eq!(long_lived.refresh_token_ttl_days, 30);
    assert!(long_lived.rotate_refresh_tokens);
    assert_eq!(long_lived.service_token_ttl_seconds, 7200);
}
