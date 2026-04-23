//! Tests for AppState

use std::sync::Arc;
use futures::future::BoxFuture;
use crate::adapters::http::state::AppState;
use crate::core::usecases::ports::{
    IdentityRepository, CredentialRepository, SessionRepository, TokenService, PasswordHasher, ServiceRegistry,
    ExternalTokenValidator, ExchangeAuthorizationCode, ExternalIdentityRepository, UserServiceClient,
};

use crate::core::identity::{UserIdentity, ExternalIdentity};
use crate::core::error::CoreError;
use uuid::Uuid;
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
    fn create_session(&self, _session_id: &str, _user: &crate::core::identity::UserIdentity, _refresh_token_hash: &str, _metadata: &str) -> BoxFuture<'_, Result<(), CoreError>> {
        Box::pin(async move { Ok(()) })
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

struct MockExternalTokenValidator;
struct MockExchangeAuthorizationCode;
struct MockExternalIdentityRepository;

impl ExternalTokenValidator for MockExternalTokenValidator {
    fn validate(&self, _token: &str) -> BoxFuture<'static, Result<ExternalIdentity, CoreError>> {
        Box::pin(async {
            Ok(ExternalIdentity {
                provider: "google".to_string(),
                provider_user_id: "test123".to_string(),
                email: Some("test@example.com".to_string()),
                name: None,
                family_name: None,
                picture: None,
            })
        })
    }
}


#[derive(Clone)]
struct MockUserServiceClient;

impl UserServiceClient for MockUserServiceClient {
    fn register_google_user(
        &self,
        _request: crate::core::usecases::ports::user_service_client::RegisterGoogleUserRequest,
    ) -> BoxFuture<'static, Result<Uuid, CoreError>> {
        Box::pin(async {
            Ok(Uuid::parse_str("550e8400-e29b-41d4-a716-446655440001").unwrap())
        })
    }
}

impl ExchangeAuthorizationCode for MockExchangeAuthorizationCode {
    fn exchange(&self, _code: &str, _state: Option<&str>) -> BoxFuture<'static, Result<ExternalIdentity, CoreError>> {
        Box::pin(async {
            Ok(ExternalIdentity {
                provider: "google".to_string(),
                provider_user_id: "test123".to_string(),
                email: Some("test@example.com".to_string()),
                name: None,
                family_name: None,
                picture: None,
            })
        })
    }
}

impl ExternalIdentityRepository for MockExternalIdentityRepository {
    fn find_by_provider_user(
        &self,
        _provider: &str,
        _provider_user_id: &str,
    ) -> BoxFuture<'_, Result<Option<Uuid>, anyhow::Error>> {
        Box::pin(async { Ok(None) })
    }

    fn upsert(
        &self,
        _provider: &str,
        _provider_user_id: &str,
        _user_id: Uuid,
        _email: Option<&str>,
    ) -> BoxFuture<'_, Result<Uuid, anyhow::Error>> {
        Box::pin(async { Ok(Uuid::nil()) })
    }

    fn delete(&self, _provider: &str, _provider_user_id: &str) -> BoxFuture<'_, Result<(), anyhow::Error>> {
        Box::pin(async { Ok(()) })
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
        Arc::new(MockExternalTokenValidator),
        Arc::new(MockExchangeAuthorizationCode),
        Arc::new(MockExternalIdentityRepository),
        Arc::new(MockUserServiceClient),
        3600u64,
        7u64,
        true,
        3600u64,
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
        Arc::new(MockExternalTokenValidator),
        Arc::new(MockExchangeAuthorizationCode),
        Arc::new(MockExternalIdentityRepository),
        Arc::new(MockUserServiceClient),
        3600u64,
        7u64,
        true,
        3600u64,
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
        Arc::new(MockExternalTokenValidator),
        Arc::new(MockExchangeAuthorizationCode),
        Arc::new(MockExternalIdentityRepository),
        Arc::new(MockUserServiceClient),
        900u64,
        1u64,
        false,
        1800u64,
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
        Arc::new(MockExternalTokenValidator),
        Arc::new(MockExchangeAuthorizationCode),
        Arc::new(MockExternalIdentityRepository),
        Arc::new(MockUserServiceClient),
        86400u64,
        30u64,
        true,
        7200u64,
    );
    
    assert_eq!(long_lived.access_token_ttl_seconds, 86400);
    assert_eq!(long_lived.refresh_token_ttl_days, 30);
    assert!(long_lived.rotate_refresh_tokens);
    assert_eq!(long_lived.service_token_ttl_seconds, 7200);
}
