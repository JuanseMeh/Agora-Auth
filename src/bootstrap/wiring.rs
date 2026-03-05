//! Dependency injection and component initialization.
//!
//! This module wires together all adapters, repositories, and services
//! following the dependency graph defined in the bootstrap README.

use std::sync::Arc;

use crate::adapters::crypto::password::Argon2PasswordHasher;
use crate::adapters::crypto::token::{EddsaTokenService, HmacTokenService};
use crate::adapters::http::state::AppState;
use crate::adapters::persistence::database::{Database, PoolConfig};
use crate::adapters::persistence::repositories::{
    CredentialRepositorySql, IdentityRepositorySql, SessionRepositorySql,
};
use crate::core::usecases::ports::{PasswordHasher, ServiceRegistry, TokenService};

use crate::adapters::crypto::token::EddsaKey;
use super::config::{AuthConfig, TokenAlgorithm};

/// Container for all initialized application components.
///
/// This struct holds ownership of all long-lived services and adapters.
/// It is constructed once during bootstrap and passed to the HTTP layer.
pub struct AppComponents {
    /// Database connection pool and executor
    pub database: Database,
    /// HTTP application state (for Axum)
    pub app_state: AppState,
}

/// Initialize all application components.
///
/// This function follows the strict initialization order:
/// 1. Database pool
/// 2. Repositories
/// 3. Crypto adapters
/// 4. Domain policies
/// 5. Application services
/// 6. HTTP state
///
/// # Errors
/// Returns an error if any infrastructure component fails to initialize.
pub async fn initialize_components(config: &AuthConfig) -> anyhow::Result<AppComponents> {
    // Step 1: Initialize database pool
    tracing::info!("Initializing database pool...");
    let database = initialize_database(config).await?;
    
    // Step 2: Build repositories (depend on database)
    tracing::info!("Building repositories...");
    let identity_repo = IdentityRepositorySql::new(database.clone());
    let credential_repo = CredentialRepositorySql::new(database.clone());
    let session_repo = SessionRepositorySql::new(database.clone());
    
    // Step 3: Initialize crypto adapters
    tracing::info!("Initializing crypto adapters...");
    let password_hasher = initialize_password_hasher(config)?;
    let token_service = initialize_token_service(config)?;
    
    // Step 4: Build service registry for internal auth
    tracing::info!("Building service registry...");
    let service_registry = build_service_registry(config);
    
    // Step 5: Build HTTP application state
    tracing::info!("Building HTTP state...");
    let app_state = build_app_state(
        config,
        Arc::new(identity_repo),
        Arc::new(credential_repo),
        Arc::new(session_repo),
        Arc::new(password_hasher),
        token_service, // Already Arc< dyn TokenService>
        service_registry,
    );
    
    tracing::info!("Component initialization complete");
    
    Ok(AppComponents {
        database,
        app_state,
    })
}

/// Initialize database connection pool.
async fn initialize_database(config: &AuthConfig) -> anyhow::Result<Database> {
    let pool_config = PoolConfig {
        max_connections: config.database.max_connections,
        idle_timeout: std::time::Duration::from_secs(600),
        max_lifetime: std::time::Duration::from_secs(1800),
    };
    
    let database = Database::new(&config.database.url, pool_config).await
        .map_err(|e| anyhow::anyhow!("Failed to initialize database: {}", e))?;
    
    tracing::info!(
        "Database pool initialized (max_connections={})",
        config.database.max_connections
    );
    
    Ok(database)
}

/// Initialize password hasher with configured parameters.
fn initialize_password_hasher(config: &AuthConfig) -> anyhow::Result<Argon2PasswordHasher> {
    let hasher = Argon2PasswordHasher::new(
        config.crypto.password_hash_memory_cost,
        config.crypto.password_hash_iterations,
        config.crypto.password_hash_parallelism,
        16, // salt length in bytes
    ).map_err(|e| anyhow::anyhow!("Failed to initialize password hasher: {:?}", e))?;
    
    tracing::info!(
        "Password hasher initialized (memory_cost={}KB, iterations={})",
        config.crypto.password_hash_memory_cost,
        config.crypto.password_hash_iterations
    );
    
    Ok(hasher)
}

/// Initialize token service with signing key (supports both EdDSA and HMAC).
fn initialize_token_service(config: &AuthConfig) -> anyhow::Result<Arc<dyn TokenService>> {
    use base64::Engine;
    
    match config.crypto.token_algorithm {
        TokenAlgorithm::EdDSA => {
            // EdDSA mode: requires EdDSA keys
            let private_key_b64 = config.crypto.eddsa_private_key.as_ref()
                .ok_or_else(|| anyhow::anyhow!("EdDSA private key not configured (AUTH_EDDSA_PRIVATE_KEY)"))?;
            let public_key_b64 = config.crypto.eddsa_public_key.as_ref()
                .ok_or_else(|| anyhow::anyhow!("EdDSA public key not configured (AUTH_EDDSA_PUBLIC_KEY)"))?;
            
            let eddsa_key = EddsaKey::from_base64_pair(private_key_b64, public_key_b64)
                .map_err(|e| anyhow::anyhow!("Failed to load EdDSA key: {}", e))?;
            
            let mut token_service = EddsaTokenService::from_key(&eddsa_key)
                .map_err(|e| anyhow::anyhow!("Failed to initialize EdDSA token service: {:?}", e))?;
            
            // Configure service token key if EdDSA service keys are provided
            if let (Some(service_private), Some(service_public)) = (
                config.service_auth.eddsa_service_private_key.as_ref(),
                config.service_auth.eddsa_service_public_key.as_ref()
            ) {
                let service_key = EddsaKey::from_base64_pair(service_private, service_public)
                    .map_err(|e| anyhow::anyhow!("Failed to load EdDSA service key: {}", e))?;
                token_service = token_service.with_service_token_key(&service_key.as_bytes())
                    .map_err(|e| anyhow::anyhow!("Failed to set EdDSA service token key: {:?}", e))?;
            }
            
            tracing::info!(
                "Token service initialized (EdDSA, access_ttl={}m, refresh_ttl={}d)",
                config.crypto.access_token_ttl_mins,
                config.crypto.refresh_token_ttl_days
            );
            
            Ok(Arc::new(token_service))
        }
        TokenAlgorithm::Hmac => {
            // HMAC mode: legacy symmetric key
            let signing_key = base64::engine::general_purpose::STANDARD
                .decode(&config.crypto.token_signing_key)
                .map_err(|e| anyhow::anyhow!("Failed to decode token signing key: {}", e))?;
            
            let mut token_service = HmacTokenService::from_secret_key(&signing_key)
                .map_err(|e| anyhow::anyhow!("Failed to initialize HMAC token service: {:?}", e))?;
            
            // Decode service token signing key (separate key for service-to-service auth)
            let service_signing_key = base64::engine::general_purpose::STANDARD
                .decode(&config.service_auth.service_token_signing_key)
                .map_err(|e| anyhow::anyhow!("Failed to decode service token signing key: {}", e))?;
            
            token_service = token_service
                .with_service_token_key(&service_signing_key)
                .map_err(|e| anyhow::anyhow!("Failed to set service token key: {:?}", e))?;
            
            tracing::info!(
                "Token service initialized (HMAC, access_ttl={}m, refresh_ttl={}d)",
                config.crypto.access_token_ttl_mins,
                config.crypto.refresh_token_ttl_days
            );
            
            Ok(Arc::new(token_service))
        }
    }
}

/// Build service registry for internal service authentication.
fn build_service_registry(config: &AuthConfig) -> Arc<dyn ServiceRegistry + Send + Sync> {
    let mut registry = SimpleServiceRegistry::new(config.service_auth.valid_service_keys.clone());
    
// Add service credentials from config
    for (service_id, hashed_secret) in &config.service_auth.service_credentials {
        let prefix_len = 20.min(hashed_secret.len());
        tracing::debug!(
            "[BOOTSTRAP] Loading service credential for service_id: {}, hash_prefix: {}",
            service_id,
            &hashed_secret[..prefix_len]
        );
        registry.add_credentials(service_id, hashed_secret);
    }
    
    tracing::info!(
        "[BOOTSTRAP] Service registry initialized with {} credentials",
        config.service_auth.service_credentials.len()
    );
    
    Arc::new(registry)
}

/// Build HTTP application state for Axum.
fn build_app_state(
    config: &AuthConfig,
    identity_repo: Arc<dyn crate::core::usecases::ports::IdentityRepository + Send + Sync>,
    credential_repo: Arc<dyn crate::core::usecases::ports::CredentialRepository + Send + Sync>,
    session_repo: Arc<dyn crate::core::usecases::ports::SessionRepository + Send + Sync>,
    password_hasher: Arc<dyn crate::core::usecases::ports::PasswordHasher + Send + Sync>,
    token_service: Arc<dyn crate::core::usecases::ports::TokenService + Send + Sync>,
    service_registry: Arc<dyn ServiceRegistry + Send + Sync>,
) -> AppState {
    AppState::new(
        identity_repo,
        credential_repo,
        session_repo,
        password_hasher,
        token_service,
        service_registry,
        config.crypto.access_token_ttl_mins * 60, // Convert to seconds
        config.crypto.refresh_token_ttl_days,
        true, // rotate_refresh_tokens
        config.service_auth.service_token_ttl_mins * 60, // Convert to seconds
    )
}

/// Simple in-memory service registry implementation.
#[derive(Clone)]
struct SimpleServiceRegistry {
    valid_keys: std::collections::HashMap<String, String>,
    credentials: std::collections::HashMap<String, String>,
}

impl SimpleServiceRegistry {
    fn new(valid_keys: Vec<String>) -> Self {
        // Map each key to a generic service name
        let mut key_map = std::collections::HashMap::new();
        for (idx, key) in valid_keys.iter().enumerate() {
            key_map.insert(key.clone(), format!("service-{}", idx));
        }
        Self { 
            valid_keys: key_map,
            credentials: std::collections::HashMap::new(),
        }
    }
    
    /// Add service credentials (service_id, hashed_secret)
    fn add_credentials(&mut self, service_id: &str, hashed_secret: &str) {
        self.credentials.insert(service_id.to_string(), hashed_secret.to_string());
    }
}

impl ServiceRegistry for SimpleServiceRegistry {
    fn validate_api_key(&self, api_key: &str) -> Option<String> {
        self.valid_keys.get(api_key).cloned()
    }
    
    fn is_service_active(&self, _service_name: &str) -> bool {
        // All services are considered active in this simple implementation
        true
    }
    
    fn validate_credentials(
        &self, 
        service_id: &str, 
        service_secret: &str,
        password_hasher: Arc<dyn PasswordHasher + Send + Sync>,
    ) -> Option<String> {
        use crate::core::credentials::StoredCredential;
        
        if let Some(stored_hash) = self.credentials.get(service_id) {
            let stored_credential = StoredCredential::from_hash(stored_hash.as_str());
            if password_hasher.verify(service_secret, &stored_credential) {
                return Some(service_id.to_string());
            }
        }
        None
    }
}
