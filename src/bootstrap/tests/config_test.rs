//! Tests for configuration management.

use crate::bootstrap::config::{AuthConfig, CryptoConfig, DatabaseConfig, DeploymentMode, SecurityConfig, ServerConfig, ServiceAuthConfig, TokenAlgorithm};

#[test]
fn test_deployment_mode_display() {
    assert_eq!(DeploymentMode::Development.to_string(), "development");
    assert_eq!(DeploymentMode::Production.to_string(), "production");
    assert_eq!(DeploymentMode::Test.to_string(), "test");
}

#[test]
fn test_deployment_mode_equality() {
    assert_eq!(DeploymentMode::Development, DeploymentMode::Development);
    assert_eq!(DeploymentMode::Production, DeploymentMode::Production);
    assert_eq!(DeploymentMode::Test, DeploymentMode::Test);
    
    assert_ne!(DeploymentMode::Development, DeploymentMode::Production);
    assert_ne!(DeploymentMode::Development, DeploymentMode::Test);
    assert_ne!(DeploymentMode::Production, DeploymentMode::Test);
}

#[test]
fn test_deployment_mode_clone() {
    let mode = DeploymentMode::Production;
    let cloned = mode.clone();
    assert_eq!(mode, cloned);
}

#[test]
fn test_server_config_default() {
    let config = ServerConfig {
        host: "0.0.0.0".to_string(),
        port: 8080,
    };
    assert_eq!(config.host, "0.0.0.0");
    assert_eq!(config.port, 8080);
}

#[test]
fn test_database_config_default() {
    let config = DatabaseConfig {
        url: "postgres://localhost/auth".to_string(),
        max_connections: 10,
        connect_timeout_secs: 30,
    };
    assert_eq!(config.url, "postgres://localhost/auth");
    assert_eq!(config.max_connections, 10);
    assert_eq!(config.connect_timeout_secs, 30);
}

#[test]
fn test_crypto_config_default() {
    let config = CryptoConfig {
        password_hash_memory_cost: 65536,
        password_hash_iterations: 3,
        password_hash_parallelism: 4,
        token_algorithm: TokenAlgorithm::Hmac,
        token_signing_key: "dGVzdC1rZXktdGhhdC1pcy1sb25nLWVub3VnaC1mb3ItaHMyNTY=".to_string(),
        eddsa_private_key: None,
        eddsa_public_key: None,
        access_token_ttl_mins: 15,
        refresh_token_ttl_days: 7,
    };
    assert_eq!(config.password_hash_memory_cost, 65536);
    assert_eq!(config.password_hash_iterations, 3);
    assert_eq!(config.password_hash_parallelism, 4);
    assert_eq!(config.token_algorithm, TokenAlgorithm::Hmac);
    assert_eq!(config.access_token_ttl_mins, 15);
    assert_eq!(config.refresh_token_ttl_days, 7);
}

#[test]
fn test_security_config_default() {
    let config = SecurityConfig {
        max_failed_attempts: 5,
        lock_duration_mins: 30,
        enable_debug_logs: false,
    };
    assert_eq!(config.max_failed_attempts, 5);
    assert_eq!(config.lock_duration_mins, 30);
    assert!(!config.enable_debug_logs);
}

#[test]
fn test_service_auth_config() {
    let config = ServiceAuthConfig {
        valid_service_keys: vec!["key1".to_string(), "key2".to_string()],
        service_credentials: vec![],
        service_token_algorithm: TokenAlgorithm::Hmac,
        service_token_signing_key: "dGVzdC1rZXktdGhhdC1pcy1sb25nLWVuZ3VnaC1mb3ItaHMyNTY=".to_string(),
        eddsa_service_private_key: None,
        eddsa_service_public_key: None,
        service_token_ttl_mins: 60,
    };
    assert_eq!(config.valid_service_keys.len(), 2);
    assert_eq!(config.valid_service_keys[0], "key1");
    assert_eq!(config.valid_service_keys[1], "key2");
    assert_eq!(config.service_token_algorithm, TokenAlgorithm::Hmac);
}

#[test]
fn test_auth_config_validation_valid() {
    let config = AuthConfig {
        server: ServerConfig {
            host: "0.0.0.0".to_string(),
            port: 8080,
        },
        database: DatabaseConfig {
            url: "postgres://localhost/auth".to_string(),
            max_connections: 10,
            connect_timeout_secs: 30,
        },
        crypto: CryptoConfig {
            password_hash_memory_cost: 65536,
            password_hash_iterations: 3,
            password_hash_parallelism: 4,
            token_algorithm: TokenAlgorithm::Hmac,
            token_signing_key: "dGVzdC1rZXktdGhhdC1pcy1sb25nLWVuZ3VnaC1mb3ItaHMyNTY=".to_string(),
            eddsa_private_key: None,
            eddsa_public_key: None,
            access_token_ttl_mins: 15,
            refresh_token_ttl_days: 7,
        },
        security: SecurityConfig {
            max_failed_attempts: 5,
            lock_duration_mins: 30,
            enable_debug_logs: false,
        },
        service_auth: ServiceAuthConfig {
            valid_service_keys: vec!["service-key".to_string()],
            service_credentials: vec![],
            service_token_algorithm: TokenAlgorithm::Hmac,
            service_token_signing_key: "dGVzdC1rZXktdGhhdC1pcy1sb25nLWVuZ3VnaC1mb3ItaHMyNTY=".to_string(),
            eddsa_service_private_key: None,
            eddsa_service_public_key: None,
            service_token_ttl_mins: 60,
        },
        mode: DeploymentMode::Production,
    };
    
    // Should pass validation
    assert!(config.validate().is_ok());
}

#[test]
fn test_auth_config_validation_invalid_ttl() {
    let config = AuthConfig {
        server: ServerConfig {
            host: "0.0.0.0".to_string(),
            port: 8080,
        },
        database: DatabaseConfig {
            url: "postgres://localhost/auth".to_string(),
            max_connections: 10,
            connect_timeout_secs: 30,
        },
        crypto: CryptoConfig {
            password_hash_memory_cost: 65536,
            password_hash_iterations: 3,
            password_hash_parallelism: 4,
            token_algorithm: TokenAlgorithm::Hmac,
            token_signing_key: "dGVzdC1rZXktdGhhdC1pcy1sb25nLWVuZ3VnaC1mb3ItaHMyNTY=".to_string(),
            eddsa_private_key: None,
            eddsa_public_key: None,
            access_token_ttl_mins: 10080, // 7 days - longer than refresh token
            refresh_token_ttl_days: 7,
        },
        security: SecurityConfig {
            max_failed_attempts: 5,
            lock_duration_mins: 30,
            enable_debug_logs: false,
        },
        service_auth: ServiceAuthConfig {
            valid_service_keys: vec!["service-key".to_string()],
            service_credentials: vec![],
            service_token_algorithm: TokenAlgorithm::Hmac,
            service_token_signing_key: "dGVzdC1rZXktdGhhdC1pcy1sb25nLWVuZ3VnaC1mb3ItaHMyNTY=".to_string(),
            eddsa_service_private_key: None,
            eddsa_service_public_key: None,
            service_token_ttl_mins: 60,
        },
        mode: DeploymentMode::Production,
    };
    
    // Should fail validation - access token TTL must be less than refresh token TTL
    let result = config.validate();
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(err_msg.contains("Access token TTL"));
}

#[test]
fn test_auth_config_validation_short_signing_key() {
    let config = AuthConfig {
        server: ServerConfig {
            host: "0.0.0.0".to_string(),
            port: 8080,
        },
        database: DatabaseConfig {
            url: "postgres://localhost/auth".to_string(),
            max_connections: 10,
            connect_timeout_secs: 30,
        },
        crypto: CryptoConfig {
            password_hash_memory_cost: 65536,
            password_hash_iterations: 3,
            password_hash_parallelism: 4,
            token_algorithm: TokenAlgorithm::Hmac,
            token_signing_key: "c2hvcnQta2V5".to_string(), // "short-key" - too short
            eddsa_private_key: None,
            eddsa_public_key: None,
            access_token_ttl_mins: 15,
            refresh_token_ttl_days: 7,
        },
        security: SecurityConfig {
            max_failed_attempts: 5,
            lock_duration_mins: 30,
            enable_debug_logs: false,
        },
        service_auth: ServiceAuthConfig {
            valid_service_keys: vec!["service-key".to_string()],
            service_credentials: vec![],
            service_token_algorithm: TokenAlgorithm::Hmac,
            service_token_signing_key: "dGVzdC1rZXktdGhhdC1pcy1sb25nLWVuZ3VnaC1mb3ItaHMyNTY=".to_string(),
            eddsa_service_private_key: None,
            eddsa_service_public_key: None,
            service_token_ttl_mins: 60,
        },
        mode: DeploymentMode::Production,
    };
    
    // Should fail validation - signing key too short
    let result = config.validate();
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(err_msg.contains("signing key"));
}

#[test]
fn test_auth_config_validation_zero_max_attempts() {
    let config = AuthConfig {
        server: ServerConfig {
            host: "0.0.0.0".to_string(),
            port: 8080,
        },
        database: DatabaseConfig {
            url: "postgres://localhost/auth".to_string(),
            max_connections: 10,
            connect_timeout_secs: 30,
        },
        crypto: CryptoConfig {
            password_hash_memory_cost: 65536,
            password_hash_iterations: 3,
            password_hash_parallelism: 4,
            token_algorithm: TokenAlgorithm::Hmac,
            token_signing_key: "dGVzdC1rZXktdGhhdC1pcy1sb25nLWVuZ3VnaC1mb3ItaHMyNTY=".to_string(),
            eddsa_private_key: None,
            eddsa_public_key: None,
            access_token_ttl_mins: 15,
            refresh_token_ttl_days: 7,
        },
        security: SecurityConfig {
            max_failed_attempts: 0, // Invalid - must be > 0
            lock_duration_mins: 30,
            enable_debug_logs: false,
        },
        service_auth: ServiceAuthConfig {
            valid_service_keys: vec!["service-key".to_string()],
            service_credentials: vec![],
            service_token_algorithm: TokenAlgorithm::Hmac,
            service_token_signing_key: "dGVzdC1rZXktdGhhdC1pcy1sb25nLWVuZ3VnaC1mb3ItaHMyNTY=".to_string(),
            eddsa_service_private_key: None,
            eddsa_service_public_key: None,
            service_token_ttl_mins: 60,
        },
        mode: DeploymentMode::Production,
    };
    
    // Should fail validation
    let result = config.validate();
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(err_msg.contains("Max failed attempts"));
}

#[test]
fn test_auth_config_validation_production_requirements() {
    let config = AuthConfig {
        server: ServerConfig {
            host: "0.0.0.0".to_string(),
            port: 8080,
        },
        database: DatabaseConfig {
            url: "postgres://localhost/auth".to_string(),
            max_connections: 10,
            connect_timeout_secs: 30,
        },
        crypto: CryptoConfig {
            password_hash_memory_cost: 4096, // Too low for production
            password_hash_iterations: 2,      // Too low for production
            password_hash_parallelism: 4,
            token_algorithm: TokenAlgorithm::Hmac,
            token_signing_key: "dGVzdC1rZXktdGhhdC1pcy1sb25nLWVuZ3VnaC1mb3ItaHMyNTY=".to_string(),
            eddsa_private_key: None,
            eddsa_public_key: None,
            access_token_ttl_mins: 15,
            refresh_token_ttl_days: 7,
        },
        security: SecurityConfig {
            max_failed_attempts: 5,
            lock_duration_mins: 30,
            enable_debug_logs: false,
        },
        service_auth: ServiceAuthConfig {
            valid_service_keys: vec!["service-key".to_string()],
            service_credentials: vec![],
            service_token_algorithm: TokenAlgorithm::Hmac,
            service_token_signing_key: "dGVzdC1rZXktdGhhdC1pcy1sb25nLWVuZ3VnaC1mb3ItaHMyNTY=".to_string(),
            eddsa_service_private_key: None,
            eddsa_service_public_key: None,
            service_token_ttl_mins: 60,
        },
        mode: DeploymentMode::Production,
    };
    
    // Should fail validation - production requires higher security params
    let result = config.validate();
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(err_msg.contains("Production mode requires"));
}

#[test]
fn test_auth_config_validation_development_allows_lower_security() {
    let config = AuthConfig {
        server: ServerConfig {
            host: "0.0.0.0".to_string(),
            port: 8080,
        },
        database: DatabaseConfig {
            url: "postgres://localhost/auth".to_string(),
            max_connections: 10,
            connect_timeout_secs: 30,
        },
        crypto: CryptoConfig {
            password_hash_memory_cost: 4096, // Lower is OK for development
            password_hash_iterations: 2,      // Lower is OK for development
            password_hash_parallelism: 4,
            token_algorithm: TokenAlgorithm::Hmac,
            token_signing_key: "dGVzdC1rZXktdGhhdC1pcy1sb25nLWVuZ3VnaC1mb3ItaHMyNTY=".to_string(),
            eddsa_private_key: None,
            eddsa_public_key: None,
            access_token_ttl_mins: 15,
            refresh_token_ttl_days: 7,
        },
        security: SecurityConfig {
            max_failed_attempts: 5,
            lock_duration_mins: 30,
            enable_debug_logs: true,
        },
        service_auth: ServiceAuthConfig {
            valid_service_keys: vec!["service-key".to_string()],
            service_credentials: vec![],
            service_token_algorithm: TokenAlgorithm::Hmac,
            service_token_signing_key: "dGVzdC1rZXktdGhhdC1pcy1sb25nLWVuZ3VnaC1mb3ItaHMyNTY=".to_string(),
            eddsa_service_private_key: None,
            eddsa_service_public_key: None,
            service_token_ttl_mins: 60,
        },
        mode: DeploymentMode::Development,
    };
    
    // Should pass validation in development mode
    assert!(config.validate().is_ok());
}

#[test]
fn test_auth_config_validation_empty_service_keys() {
    let config = AuthConfig {
        server: ServerConfig {
            host: "0.0.0.0".to_string(),
            port: 8080,
        },
        database: DatabaseConfig {
            url: "postgres://localhost/auth".to_string(),
            max_connections: 10,
            connect_timeout_secs: 30,
        },
        crypto: CryptoConfig {
            password_hash_memory_cost: 65536,
            password_hash_iterations: 3,
            password_hash_parallelism: 4,
            token_algorithm: TokenAlgorithm::Hmac,
            token_signing_key: "dGVzdC1rZXktdGhhdC1pcy1sb25nLWVuZ3VnaC1mb3ItaHMyNTY=".to_string(),
            eddsa_private_key: None,
            eddsa_public_key: None,
            access_token_ttl_mins: 15,
            refresh_token_ttl_days: 7,
        },
        security: SecurityConfig {
            max_failed_attempts: 5,
            lock_duration_mins: 30,
            enable_debug_logs: false,
        },
        service_auth: ServiceAuthConfig {
            valid_service_keys: vec![], // Empty - should fail
            service_credentials: vec![],
            service_token_algorithm: TokenAlgorithm::Hmac,
            service_token_signing_key: "dGVzdC1rZXktdGhhdC1pcy1sb25nLWVuZ3VnaC1mb3ItaHMyNTY=".to_string(),
            eddsa_service_private_key: None,
            eddsa_service_public_key: None,
            service_token_ttl_mins: 60,
        },
        mode: DeploymentMode::Production,
    };
    
    // Should fail validation
    let result = config.validate();
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(err_msg.contains("service API key"));
}

#[test]
fn test_token_algorithm_display() {
    assert_eq!(format!("{}", TokenAlgorithm::EdDSA), "EdDSA");
    assert_eq!(format!("{}", TokenAlgorithm::Hmac), "Hmac");
}

