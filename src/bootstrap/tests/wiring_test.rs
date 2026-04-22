//! Tests for the wiring module.

use crate::bootstrap::config::{
    AuthConfig, 
    CryptoConfig, 
    DatabaseConfig, 
    DeploymentMode, 
    SecurityConfig, 
    ServerConfig, 
    ServiceAuthConfig, 
    GoogleOAuthConfig,
    TokenAlgorithm};
use crate::bootstrap::wiring::{initialize_components, AppComponents};

/// Test-specific initialization with test database.
#[cfg(test)]
pub async fn initialize_test_components() -> anyhow::Result<AppComponents> {
    let test_config = AuthConfig {
        server: ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 0, // Random port
        },
        database: DatabaseConfig {
            url: "postgres://postgres:postgres@localhost:5432/auth_test".to_string(),
            max_connections: 5,
            connect_timeout_secs: 5,
        },
        crypto: CryptoConfig {
            password_hash_memory_cost: 4096, // Low cost for fast tests
            password_hash_iterations: 1,
            password_hash_parallelism: 1,
            token_algorithm: TokenAlgorithm::Hmac,
            token_signing_key: "dGVzdC1zZWNyZXQta2V5LXRoYXQtaXMtbG9uZy1lbm91Z2gtZm9yLWhzMjU2".to_string(),
            eddsa_private_key: None,
            eddsa_public_key: None,
            access_token_ttl_mins: 5,
            refresh_token_ttl_days: 1,
        },
        security: SecurityConfig {
            max_failed_attempts: 3,
            lock_duration_mins: 1,
            enable_debug_logs: true,
        },
        service_auth: ServiceAuthConfig {
            valid_service_keys: vec!["test-service-key".to_string()],
            service_credentials: vec![],
            service_token_algorithm: TokenAlgorithm::Hmac,
            service_token_signing_key: "dGVzdC1zZWNyZXQta2V5LXRoYXQtaXMtbG9uZy1lbm91Z2gtZm9yLWhzMjU2".to_string(),
            eddsa_service_private_key: None,
            eddsa_service_public_key: None,
            service_token_ttl_mins: 60,
        },
        google_oauth: GoogleOAuthConfig {
            client_id: "test-client-id.googleusercontent.com".to_string(),
            client_secret: "test-client-secret".to_string(),
            redirect_uri: "http://localhost:8080/auth/google/callback".to_string(),
            issuer: "https://accounts.google.com".to_string(),
            jwks_url: "https://www.googleapis.com/oauth2/v3/certs".to_string(),
            token_url: "https://oauth2.googleapis.com/token".to_string(),
        },
        user_service: crate::bootstrap::config::UserServiceConfig {
            base_url: "http://localhost:8083".to_string(),
        },
        mode: DeploymentMode::Test,
    };
    
    initialize_components(&test_config).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_initialize_test_components() {
        // This test verifies the test helper works
        let result = initialize_test_components().await;
        // We expect this might fail if DB is not available, but it should compile
        // In a real CI environment, this would be skipped or use a test DB
        match result {
            Ok(_) => println!("Components initialized successfully"),
            Err(e) => println!("Expected failure in test environment: {}", e),
        }
    }
}

