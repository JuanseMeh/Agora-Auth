//! Tests for the server module.

use crate::bootstrap::config::{AuthConfig, CryptoConfig, DatabaseConfig, DeploymentMode, SecurityConfig, ServerConfig, ServiceAuthConfig, TokenAlgorithm};
use crate::bootstrap::server::health_check;

/// Create a test configuration for server tests.
fn create_test_config() -> AuthConfig {
    AuthConfig {
        server: ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 0,
        },
        database: DatabaseConfig {
            url: "postgres://postgres:postgres@localhost:5432/auth_test".to_string(),
            max_connections: 5,
            connect_timeout_secs: 5,
        },
        crypto: CryptoConfig {
            password_hash_memory_cost: 4096,
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
        mode: DeploymentMode::Test,
    }
}

#[tokio::test]
async fn test_health_check_returns_ok() {
    let response = health_check().await;
    
    assert_eq!(response.status(), axum::http::StatusCode::OK);
}

#[tokio::test]
async fn test_health_check_response_body() {
    let response = health_check().await;
    
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    
    assert!(body_str.contains("healthy") || body_str.contains("ok") || body_str.contains("status"));
}

#[test]
fn test_server_config_creation() {
    let config = create_test_config();
    
    assert_eq!(config.server.host, "127.0.0.1");
    assert_eq!(config.server.port, 0);
}

#[test]
fn test_deployment_mode_in_config() {
    let config = create_test_config();
    assert_eq!(config.mode, DeploymentMode::Test);
}

#[test]
fn test_security_config_in_test_mode() {
    let config = create_test_config();
    
    // Test mode should have relaxed security for fast tests
    assert_eq!(config.crypto.password_hash_memory_cost, 4096);
    assert_eq!(config.crypto.password_hash_iterations, 1);
    assert!(config.security.enable_debug_logs);
}

#[test]
fn test_service_keys_parsed() {
    let config = create_test_config();
    assert_eq!(config.service_auth.valid_service_keys.len(), 1);
    assert_eq!(config.service_auth.valid_service_keys[0], "test-service-key");
}

#[test]
fn test_token_ttl_config() {
    let config = create_test_config();
    
    // Access token should be shorter than refresh token
    let access_ttl_mins = config.crypto.access_token_ttl_mins;
    let refresh_ttl_mins = config.crypto.refresh_token_ttl_days * 24 * 60;
    
    assert!(access_ttl_mins < refresh_ttl_mins);
    assert_eq!(access_ttl_mins, 5);
    assert_eq!(refresh_ttl_mins, 1440); // 1 day in minutes
}

#[test]
fn test_lockout_config() {
    let config = create_test_config();
    
    assert_eq!(config.security.max_failed_attempts, 3);
    assert_eq!(config.security.lock_duration_mins, 1);
}

/// Test that server configuration can be cloned (needed for Arc sharing)
#[test]
fn test_config_clone() {
    let config = create_test_config();
    let cloned = config.clone();
    
    assert_eq!(config.server.host, cloned.server.host);
    assert_eq!(config.server.port, cloned.server.port);
    assert_eq!(config.mode, cloned.mode);
}

/// Test that the signing key is valid base64 and has correct length
#[test]
fn test_signing_key_validation() {
    let config = create_test_config();
    
    use base64::Engine;
    let key_bytes = base64::engine::general_purpose::STANDARD
        .decode(&config.crypto.token_signing_key)
        .expect("Signing key should be valid base64");
    
    assert!(key_bytes.len() >= 32, "Signing key must be at least 32 bytes");
}
