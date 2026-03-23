// HTTP server shared state

use std::sync::Arc;
use crate::core::usecases::ports::{
    CredentialRepository, 
    ExchangeAuthorizationCode,
    ExternalIdentityRepository,
    ExternalTokenValidator,
    IdentityRepository, 
    PasswordHasher, 
    SessionRepository, 
    ServiceRegistry, 
    TokenService,
};

/// Application state shared across all HTTP handlers
///
/// Contains only application-level services and utilities.
/// Does NOT contain:
/// - Database connections (injected into services)
/// - Repositories (injected into services)
/// - Infrastructure primitives
#[derive(Clone)]
pub struct AppState {
    /// Repository for identity operations
    pub identity_repo: Arc<dyn IdentityRepository + Send + Sync>,
    /// Repository for credential operations
    pub credential_repo: Arc<dyn CredentialRepository + Send + Sync>,
    /// Repository for session operations
    pub session_repo: Arc<dyn SessionRepository + Send + Sync>,
    /// Password hasher service
    pub password_hasher: Arc<dyn PasswordHasher + Send + Sync>,
    /// Token service for issuing and validating tokens
    pub token_service: Arc<dyn TokenService + Send + Sync>,
    /// Service registry for validating API keys
    pub service_registry: Arc<dyn ServiceRegistry + Send + Sync>,
    /// Access token TTL in seconds
    pub access_token_ttl_seconds: u64,
    /// Refresh token TTL in days
    pub refresh_token_ttl_days: u64,
    /// Whether to rotate refresh tokens
    pub rotate_refresh_tokens: bool,
    /// Service token TTL in seconds
    pub service_token_ttl_seconds: u64,
    /// Google OAuth token validator
    pub google_token_validator: Arc<dyn ExternalTokenValidator + Send + Sync>,
    /// Google OAuth code exchanger
    pub google_code_exchanger: Arc<dyn ExchangeAuthorizationCode + Send + Sync>,
    /// External identity repository for OAuth linking
    pub external_identity_repo: Arc<dyn ExternalIdentityRepository + Send + Sync>,
}

impl AppState {
    /// Create a new application state with all required dependencies
    pub fn new(
        identity_repo: Arc<dyn IdentityRepository + Send + Sync>,
        credential_repo: Arc<dyn CredentialRepository + Send + Sync>,
        session_repo: Arc<dyn SessionRepository + Send + Sync>,
        password_hasher: Arc<dyn PasswordHasher + Send + Sync>,
        token_service: Arc<dyn TokenService + Send + Sync>,
        service_registry: Arc<dyn ServiceRegistry + Send + Sync>,
        google_token_validator: Arc<dyn ExternalTokenValidator + Send + Sync>,
        google_code_exchanger: Arc<dyn ExchangeAuthorizationCode + Send + Sync>,
        external_identity_repo: Arc<dyn ExternalIdentityRepository + Send + Sync>,
        access_token_ttl_seconds: u64,
        refresh_token_ttl_days: u64,
        rotate_refresh_tokens: bool,
        service_token_ttl_seconds: u64,
    ) -> Self {
        Self {
            identity_repo,
            credential_repo,
            session_repo,
            password_hasher,
            token_service,
            service_registry,
            google_token_validator,
            google_code_exchanger,
            external_identity_repo,
            access_token_ttl_seconds,
            refresh_token_ttl_days,
            rotate_refresh_tokens,
            service_token_ttl_seconds,
        }
    }
}
