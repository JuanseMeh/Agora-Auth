//! Tests for Google OAuth handler integration

use axum::{
    body::Body,
    http::{Request, StatusCode},
    routing::post,
    Router,
};
use tower::ServiceExt;
use std::sync::Arc;
use futures::future::BoxFuture;
use crate::core::usecases::ports::{
    CredentialRepository, 
    PasswordHasher, 
    ServiceRegistry, 
    ExternalTokenValidator, 
    UserServiceClient
};
use crate::core::credentials::StoredCredential;

use uuid::Uuid;

use crate::adapters::http::{
    dto::public::google_oauth::{GoogleCodeExchangeRequest, GoogleCodeExchangeResponse},
    state::AppState,
};
use crate::adapters::http::handlers::public::google_oauth::exchange_google_code;

use crate::core::identity::ExternalIdentity;
use crate::core::error::{CoreError, AuthenticationError};


// ============================================================================
// Mock Implementations
// ============================================================================

use crate::core::usecases::ports::{ExchangeAuthorizationCode, ExternalIdentityRepository, IdentityRepository, SessionRepository, TokenService};
use crate::core::identity::UserIdentity;

// Mock for GoogleCodeExchanger (ExchangeAuthorizationCode)
#[derive(Clone)]
struct MockCodeExchanger;
impl ExchangeAuthorizationCode for MockCodeExchanger {
    fn exchange(&self, code: &str, state_opt: Option<&str>) -> BoxFuture<'static, Result<ExternalIdentity, CoreError>> {
        let code = code.to_owned();
        let _state = state_opt.map(|s| s.to_owned());
        Box::pin(async move {
            if code == "invalid_code" {
                return Err(CoreError::Authentication(AuthenticationError::InvalidExternalToken {
                    reason: "Invalid code".to_string(),
                }));
            }
            let provider = "google".to_string();
            let provider_user_id = "google_sub_123".to_string();
            let email = Some("test@example.com".to_string());
            let name = None;
            let family_name = None;
            let picture = None;
            Ok(ExternalIdentity::new(provider, provider_user_id, email, name, family_name, picture).unwrap())
        })
    }
}

// Missing mocks for test_app_state
#[derive(Clone)]
struct MockCredentialRepo;
impl CredentialRepository for MockCredentialRepo {
    fn get_by_user_id(&self, _user_id: &str) -> BoxFuture<'static, Option<StoredCredential>> {
        Box::pin(async move { None })
    }
    fn update_failed_attempts(&self, _user_id: &str, _attempts: u32) -> BoxFuture<'static, ()> {
        Box::pin(async move {})
    }
    fn lock_until(&self, _user_id: &str, _until: &str) -> BoxFuture<'static, ()> {
        Box::pin(async move {})
    }
    fn update_password(&self, _user_id: &str, _new_credential: StoredCredential) -> BoxFuture<'static, ()> {
        Box::pin(async move {})
    }
    fn initialize_credential_state(&self, _user_id: &str) -> BoxFuture<'static, Result<(), String>> {
        Box::pin(async move { Ok(()) })
    }
}

#[derive(Clone)]
struct MockPasswordHasherImpl;
impl PasswordHasher for MockPasswordHasherImpl {
    fn hash(&self, raw: &str) -> StoredCredential {
        StoredCredential::from_hash(format!("mock_hashed_{}", raw))
    }
    fn verify(&self, raw: &str, stored: &StoredCredential) -> bool {
        stored.as_hash_str() == format!("mock_hashed_{}", raw)
    }
}

#[derive(Clone)]
struct MockServiceRegistryImpl;
impl ServiceRegistry for MockServiceRegistryImpl {
    fn validate_api_key(&self, _api_key: &str) -> Option<String> {
        Some("test-service".to_string())
    }
    fn is_service_active(&self, _service_name: &str) -> bool {
        true
    }
    fn validate_credentials(&self, _service_id: &str, _service_secret: &str, _password_hasher: Arc<dyn PasswordHasher + Send + Sync>) -> Option<String> {
        None
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

#[derive(Clone)]
struct MockGoogleTokenValidator;
impl ExternalTokenValidator for MockGoogleTokenValidator {
    fn validate(&self, _token: &str) -> BoxFuture<'static, Result<ExternalIdentity, CoreError>> {
        let provider = "google".to_string();
        let provider_user_id = "mock_google_user".to_string();
        let email = Some("mock@example.com".to_string());
        let name = None;
        let family_name = None;
        let picture = None;
        Box::pin(async move {
            Ok(ExternalIdentity::new(provider, provider_user_id, email, name, family_name, picture).unwrap())
        })
    }
}

/// Test helper to create AppState with provided OAuth mocks + defaults
fn test_app_state(
    google_code_exchanger: Arc<dyn ExchangeAuthorizationCode + Send + Sync>,
    external_identity_repo: Arc<dyn ExternalIdentityRepository + Send + Sync>,
    identity_repo: Arc<dyn IdentityRepository + Send + Sync>,
    session_repo: Arc<dyn SessionRepository + Send + Sync>,
    token_service: Arc<dyn TokenService + Send + Sync>,
    user_service_client: Arc<dyn UserServiceClient + Send + Sync>,
) -> AppState {
    AppState::new(
        identity_repo,
        Arc::new(MockCredentialRepo),
        session_repo,
        Arc::new(MockPasswordHasherImpl),
        token_service,
        Arc::new(MockServiceRegistryImpl),
        Arc::new(MockGoogleTokenValidator),
        google_code_exchanger,
        external_identity_repo,
        user_service_client,
        3600, // access_token_ttl_seconds
        7,    // refresh_token_ttl_days
        true, // rotate_refresh_tokens
        3600, // service_token_ttl_seconds
    )
}





// Mock for ExternalIdentityRepo
#[derive(Clone)]
struct MockExternalIdentityRepo;
impl ExternalIdentityRepository for MockExternalIdentityRepo {
    fn find_by_provider_user(&self, provider: &str, provider_user_id: &str) -> BoxFuture<'static, Result<Option<Uuid>, anyhow::Error>> {
        let provider = provider.to_owned();
        let provider_user_id = provider_user_id.to_owned();
        Box::pin(async move {
            if provider == "google" && provider_user_id == "google_sub_123" {
                Ok(Some(Uuid::parse_str("550e8400-e29b-41d4-a716-446655440001").unwrap()))
            } else {
                Ok(None)
            }
        })
    }
    fn upsert(&self, provider: &str, provider_user_id: &str, user_id: Uuid, email: Option<&str>) -> BoxFuture<'static, Result<Uuid, anyhow::Error>> {
        let _provider = provider.to_owned();
        let _provider_user_id = provider_user_id.to_owned();
        let _email = email.map(|e| e.to_owned());
        Box::pin(async move { Ok(user_id) })
    }
    fn delete(&self, provider: &str, provider_user_id: &str) -> BoxFuture<'static, Result<(), anyhow::Error>> {
        let _provider = provider.to_owned();
        let _provider_user_id = provider_user_id.to_owned();
        Box::pin(async move { Ok(()) })
    }
}





// Mock for IdentityRepo
#[derive(Clone)]
struct MockIdentityRepo;
impl IdentityRepository for MockIdentityRepo {
    fn find_by_identifier(&self, id: &str) -> BoxFuture<'static, Option<UserIdentity>> {
        let _id = id.to_owned();
        Box::pin(async move { None })
    }
    fn find_by_id(&self, id: &str) -> BoxFuture<'static, Option<UserIdentity>> {
        let _id = id.to_owned();
        Box::pin(async move {
            Some(UserIdentity::new(Uuid::parse_str("550e8400-e29b-41d4-a716-446655440001").unwrap()))
        })
    }
    fn create(&self, _user_id: &Uuid, identifier: &str, password_hash: &str, salt: &str, algorithm: &str, _iterations: u32) -> BoxFuture<'static, Result<(), String>> {
        let _identifier = identifier.to_owned();
        let _password_hash = password_hash.to_owned();
        let _salt = salt.to_owned();
        let _algorithm = algorithm.to_owned();
        Box::pin(async move { Ok(()) })
    }
}



// Mock SessionRepo & TokenService (simplified for issue_usecase)
#[derive(Clone)]
struct MockSessionRepo;
impl SessionRepository for MockSessionRepo {
    fn create_session(&self, session_id: &str, _user: &UserIdentity, refresh_token_hash: &str, metadata: &str) -> BoxFuture<'static, ()> {
        let _session_id = session_id.to_owned();
        let _refresh_token_hash = refresh_token_hash.to_owned();
        let _metadata = metadata.to_owned();
        Box::pin(async move {})
    }
    fn find_by_refresh_token_hash(&self, _hash: &str) -> BoxFuture<'_, Option<crate::core::usecases::ports::session_repository::Session>> {
        Box::pin(async { None })
    }
    fn find_by_id(&self, _session_id: &str) -> BoxFuture<'_, Option<crate::core::usecases::ports::session_repository::Session>> {
        Box::pin(async { None })
    }
    fn revoke_session(&self, _session_id: &str) -> BoxFuture<'_, ()> {
        Box::pin(async {})
    }
    fn revoke_all_for_user(&self, _user_id: &str) -> BoxFuture<'_, ()> {
        Box::pin(async {})
    }
fn delete_expired(&self) -> BoxFuture<'_, ()> {
        Box::pin(async {})
    }
}

struct MockTokenService;
impl TokenService for MockTokenService {
    fn issue_access_token(&self, _subject: &str, _claims: &str) -> crate::core::token::Token {
        crate::core::token::Token::new("mock_access".to_string())
    }
    fn issue_refresh_token(&self, _subject: &str, _claims: &str) -> crate::core::token::Token {
        crate::core::token::Token::new("mock_refresh".to_string())
    }
    fn issue_service_token(&self, _subject: &str, _claims: &str) -> crate::core::token::Token {
        crate::core::token::Token::new("mock_service".to_string())
    }
    fn validate_access_token(&self, _token: &crate::core::token::Token) -> Result<String, ()> {
        Ok("valid".to_string())
    }
    fn validate_refresh_token(&self, _token: &crate::core::token::Token) -> Result<String, ()> {
        Ok("valid".to_string())
    }
    fn validate_service_token(&self, _token: &crate::core::token::Token) -> Result<String, ()> {
        Ok("valid".to_string())
    }
}


// ============================================================================
// Integration Tests
// ============================================================================

#[tokio::test]
async fn test_exchange_google_code_happy_path() {
    let app_state = test_app_state(
        Arc::new(MockCodeExchanger) as Arc<dyn ExchangeAuthorizationCode + Send + Sync>,
        Arc::new(MockExternalIdentityRepo) as Arc<dyn ExternalIdentityRepository + Send + Sync>,
        Arc::new(MockIdentityRepo) as Arc<dyn IdentityRepository + Send + Sync>,
        Arc::new(MockSessionRepo) as Arc<dyn SessionRepository + Send + Sync>,
        Arc::new(MockTokenService) as Arc<dyn TokenService + Send + Sync>,
        Arc::new(MockUserServiceClient) as Arc<dyn UserServiceClient + Send + Sync>,
    );

    let app = Router::new()
        .route("/auth/google/callback", post(exchange_google_code))
        .with_state(app_state);

    let request_body = GoogleCodeExchangeRequest {
        code: "valid_code".to_string(),
        state: Some("csrf_state".to_string()),
    };

    let req = Request::builder()
        .method("POST")
        .uri("/auth/google/callback")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&request_body).unwrap()))
        .unwrap();

    let response = app
        .oneshot(req)
        .await
        .unwrap();


    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024).await.unwrap();
    let resp: GoogleCodeExchangeResponse = serde_json::from_slice(&body).unwrap();
    assert!(!resp.access_token.is_empty());
    assert_eq!(resp.token_type, "Bearer".to_string());
}

#[tokio::test]
async fn test_exchange_google_code_invalid_request() {
    let state = test_app_state(
        Arc::new(MockCodeExchanger) as Arc<dyn ExchangeAuthorizationCode + Send + Sync>,
        Arc::new(MockExternalIdentityRepo) as Arc<dyn ExternalIdentityRepository + Send + Sync>,
        Arc::new(MockIdentityRepo) as Arc<dyn IdentityRepository + Send + Sync>,
        Arc::new(MockSessionRepo) as Arc<dyn SessionRepository + Send + Sync>,
        Arc::new(MockTokenService) as Arc<dyn TokenService + Send + Sync>,
        Arc::new(MockUserServiceClient) as Arc<dyn UserServiceClient + Send + Sync>,
    );


    let app = Router::new()
        .route("/auth/google/callback", post(exchange_google_code))
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/google/callback")
                .header("content-type", "application/json")
                .body(Body::from("{}".to_string()))  // empty code
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);  // ValidationError
}

#[tokio::test]
async fn test_exchange_google_code_exchange_fail() {
    let state = test_app_state(
        Arc::new(MockCodeExchanger) as Arc<dyn ExchangeAuthorizationCode + Send + Sync>,
        Arc::new(MockExternalIdentityRepo) as Arc<dyn ExternalIdentityRepository + Send + Sync>,
        Arc::new(MockIdentityRepo) as Arc<dyn IdentityRepository + Send + Sync>,
        Arc::new(MockSessionRepo) as Arc<dyn SessionRepository + Send + Sync>,
        Arc::new(MockTokenService) as Arc<dyn TokenService + Send + Sync>,
        Arc::new(MockUserServiceClient) as Arc<dyn UserServiceClient + Send + Sync>,
    );


    let app = Router::new()
        .route("/auth/google/callback", post(exchange_google_code))
        .with_state(state);

    let request_body = GoogleCodeExchangeRequest {
        code: "invalid_code".to_string(),
        state: None,
    };

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/google/callback")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&request_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[derive(Clone)]
struct MockNoLinkExchanger;
impl ExchangeAuthorizationCode for MockNoLinkExchanger {
    fn exchange(&self, code: &str, state_opt: Option<&str>) -> BoxFuture<'static, Result<ExternalIdentity, CoreError>> {
        let _code = code.to_owned();
        let _state = state_opt.map(|s| s.to_owned());
        Box::pin(async move {
            Ok(ExternalIdentity::new("google".to_string(), "no_link_sub".to_string(), None, None, None, None).unwrap())
        })
    }
}



#[tokio::test]
async fn test_exchange_google_code_no_linked_user() {
    let app_state = test_app_state(
        Arc::new(MockNoLinkExchanger) as Arc<dyn ExchangeAuthorizationCode + Send + Sync>,
        Arc::new(MockExternalIdentityRepo) as Arc<dyn ExternalIdentityRepository + Send + Sync>,
        Arc::new(MockIdentityRepo) as Arc<dyn IdentityRepository + Send + Sync>,
        Arc::new(MockSessionRepo) as Arc<dyn SessionRepository + Send + Sync>,
        Arc::new(MockTokenService) as Arc<dyn TokenService + Send + Sync>,
        Arc::new(MockUserServiceClient) as Arc<dyn UserServiceClient + Send + Sync>,
    );

    let app = Router::new()
        .route("/auth/google/callback", post(exchange_google_code))
        .with_state(app_state);

    let request_body = GoogleCodeExchangeRequest {
        code: "no_link_code".to_string(),
        state: None,
    };

    let req = Request::builder()
        .method("POST")
        .uri("/auth/google/callback")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&request_body).unwrap()))
        .unwrap();

    let response = app
        .oneshot(req)
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

