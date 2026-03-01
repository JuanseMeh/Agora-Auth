//! Configuration management for the authentication service.
//!
//! This module handles environment variable parsing, validation, and
//! structured configuration for all service components.

use std::env;

/// Centralized configuration for the authentication service.
///
/// All environment variables are parsed and validated at startup.
/// No environment access occurs outside this module.
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// Server binding configuration
    pub server: ServerConfig,
    /// Database connection settings
    pub database: DatabaseConfig,
    /// Cryptographic parameters and keys
    pub crypto: CryptoConfig,
    /// Security policies and limits
    pub security: SecurityConfig,
    /// Service-to-service authentication
    pub service_auth: ServiceAuthConfig,
    /// Operational mode (development, production, test)
    pub mode: DeploymentMode,
}

/// Server binding configuration
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Host address to bind (e.g., "0.0.0.0")
    pub host: String,
    /// Port to listen on
    pub port: u16,
}

/// Database connection configuration
#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    /// PostgreSQL connection URL
    pub url: String,
    /// Maximum connections in the pool
    pub max_connections: u32,
    /// Connection timeout in seconds
    pub connect_timeout_secs: u64,
}

/// Cryptographic configuration
#[derive(Debug, Clone)]
pub struct CryptoConfig {
    /// Argon2 memory cost (KB)
    pub password_hash_memory_cost: u32,
    /// Argon2 iterations
    pub password_hash_iterations: u32,
    /// Argon2 parallelism factor
    pub password_hash_parallelism: u32,
    /// JWT signing key (HS256 symmetric key)
    pub token_signing_key: String,
    /// Access token TTL in minutes
    pub access_token_ttl_mins: u64,
    /// Refresh token TTL in days
    pub refresh_token_ttl_days: u64,
}

/// Security policy configuration
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    /// Maximum failed authentication attempts before lockout
    pub max_failed_attempts: u32,
    /// Account lockout duration in minutes
    pub lock_duration_mins: u64,
    /// Enable debug logging (security-sensitive)
    pub enable_debug_logs: bool,
}

/// Service-to-service authentication configuration
#[derive(Debug, Clone)]
pub struct ServiceAuthConfig {
    /// Comma-separated list of valid service API keys (legacy)
    pub valid_service_keys: Vec<String>,
    /// Service credentials: map of service_id -> hashed secret
    /// Format: service_id:hashed_secret (comma-separated)
    pub service_credentials: Vec<(String, String)>,
    /// Service token signing key (base64 encoded)
    pub service_token_signing_key: String,
    /// Service token TTL in minutes
    pub service_token_ttl_mins: u64,
}

/// Deployment mode determines operational characteristics
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeploymentMode {
    /// Development: lower security, verbose logging
    Development,
    /// Production: strict security, structured logging
    Production,
    /// Test: deterministic, in-memory options
    Test,
}

impl AuthConfig {
    /// Load configuration from environment variables.
    ///
    /// # Errors
    /// Returns an error if required variables are missing or invalid.
    pub fn from_env() -> anyhow::Result<Self> {
        let mode = Self::parse_mode()?;
        
        let config = AuthConfig {
            server: ServerConfig {
                host: Self::get_env("AUTH_SERVER_HOST", "0.0.0.0"),
                port: Self::parse_port()?,
            },
            database: DatabaseConfig {
                url: Self::require_env("AUTH_DATABASE_URL")?,
                max_connections: Self::parse_u32("AUTH_DB_MAX_CONNECTIONS", 10)?,
                connect_timeout_secs: Self::parse_u64("AUTH_DB_CONNECT_TIMEOUT_SECS", 30)?,
            },
            crypto: CryptoConfig {
                password_hash_memory_cost: Self::parse_u32("AUTH_HASH_MEMORY_COST", 
                    if mode == DeploymentMode::Development { 4096 } else { 65536 })?,
                password_hash_iterations: Self::parse_u32("AUTH_HASH_ITERATIONS", 
                    if mode == DeploymentMode::Development { 2 } else { 3 })?,
                password_hash_parallelism: Self::parse_u32("AUTH_HASH_PARALLELISM", 1)?,
                token_signing_key: Self::require_env("AUTH_TOKEN_SIGNING_KEY")?,
                access_token_ttl_mins: Self::parse_u64("AUTH_ACCESS_TOKEN_TTL_MINS", 15)?,
                refresh_token_ttl_days: Self::parse_u64("AUTH_REFRESH_TOKEN_TTL_DAYS", 7)?,
            },
            security: SecurityConfig {
                max_failed_attempts: Self::parse_u32("AUTH_MAX_FAILED_ATTEMPTS", 5)?,
                lock_duration_mins: Self::parse_u64("AUTH_LOCK_DURATION_MINS", 30)?,
                enable_debug_logs: Self::parse_bool("AUTH_ENABLE_DEBUG_LOGS", 
                    mode == DeploymentMode::Development),
            },
            service_auth: ServiceAuthConfig {
                valid_service_keys: Self::parse_service_keys()?,
                service_credentials: Self::parse_service_credentials()?,
                service_token_signing_key: Self::require_env("AUTH_SERVICE_TOKEN_SIGNING_KEY")?,
                service_token_ttl_mins: Self::parse_u64("AUTH_SERVICE_TOKEN_TTL_MINS", 60)?,
            },
            mode,
        };

        config.validate()?;
        Ok(config)
    }

    /// Validate security-critical configuration parameters.
    ///
    /// Fails fast on invalid security settings.
    /// Public for testing purposes.
    pub fn validate(&self) -> anyhow::Result<()> {
        // Validate token TTL relationship
        let access_ttl_mins = self.crypto.access_token_ttl_mins;
        let refresh_ttl_mins = self.crypto.refresh_token_ttl_days * 24 * 60;
        
        anyhow::ensure!(
            access_ttl_mins < refresh_ttl_mins,
            "Access token TTL ({access_ttl_mins} mins) must be less than refresh token TTL ({refresh_ttl_mins} mins)",
        );

        // Validate lockout parameters
        anyhow::ensure!(
            self.security.max_failed_attempts > 0,
            "Max failed attempts must be greater than 0"
        );
        
        anyhow::ensure!(
            self.security.lock_duration_mins > 0,
            "Lock duration must be greater than 0 minutes"
        );

        // Validate signing key entropy (minimum 32 bytes for HS256)
        use base64::Engine;
        let key_bytes = base64::engine::general_purpose::STANDARD
            .decode(&self.crypto.token_signing_key)
            .map_err(|_| anyhow::anyhow!("Token signing key must be valid base64"))?;
        
        anyhow::ensure!(
            key_bytes.len() >= 32,
            "Token signing key must be at least 32 bytes (256 bits), got {} bytes. \
             Generate with: openssl rand -base64 32",
            key_bytes.len()
        );

        // Validate service keys are present
        anyhow::ensure!(
            !self.service_auth.valid_service_keys.is_empty(),
            "At least one service API key must be configured"
        );

        // Validate service token signing key
        let service_key_bytes = base64::engine::general_purpose::STANDARD
            .decode(&self.service_auth.service_token_signing_key)
            .map_err(|_| anyhow::anyhow!("Service token signing key must be valid base64"))?;
        
        anyhow::ensure!(
            service_key_bytes.len() >= 32,
            "Service token signing key must be at least 32 bytes (256 bits), got {} bytes",
            service_key_bytes.len()
        );

        // Validate hash parameters for production
        if self.mode == DeploymentMode::Production {
            anyhow::ensure!(
                self.crypto.password_hash_memory_cost >= 65536,
                "Production mode requires password_hash_memory_cost >= 65536 KB"
            );
            anyhow::ensure!(
                self.crypto.password_hash_iterations >= 3,
                "Production mode requires password_hash_iterations >= 3"
            );
        }

        Ok(())
    }

    // Helper methods for environment parsing

    fn get_env(key: &str, default: &str) -> String {
        env::var(key).unwrap_or_else(|_| default.to_string())
    }

    fn require_env(key: &str) -> anyhow::Result<String> {
        env::var(key).map_err(|_| anyhow::anyhow!(
            "Required environment variable {} is not set", key
        ))
    }

    fn parse_mode() -> anyhow::Result<DeploymentMode> {
        let mode_str = Self::get_env("AUTH_MODE", "development").to_lowercase();
        match mode_str.as_str() {
            "development" | "dev" => Ok(DeploymentMode::Development),
            "production" | "prod" => Ok(DeploymentMode::Production),
            "test" => Ok(DeploymentMode::Test),
            _ => Err(anyhow::anyhow!(
                "Invalid AUTH_MODE: {}. Must be 'development', 'production', or 'test'",
                mode_str
            )),
        }
    }

    fn parse_port() -> anyhow::Result<u16> {
        let port_str = Self::get_env("AUTH_SERVER_PORT", "8080");
        port_str.parse().map_err(|_| {
            anyhow::anyhow!("AUTH_SERVER_PORT must be a valid port number (1-65535)")
        })
    }

    fn parse_u32(key: &str, default: u32) -> anyhow::Result<u32> {
        let val = Self::get_env(key, &default.to_string());
        val.parse().map_err(|_| {
            anyhow::anyhow!("{} must be a valid positive integer", key)
        })
    }

    fn parse_u64(key: &str, default: u64) -> anyhow::Result<u64> {
        let val = Self::get_env(key, &default.to_string());
        val.parse().map_err(|_| {
            anyhow::anyhow!("{} must be a valid positive integer", key)
        })
    }

    fn parse_bool(key: &str, default: bool) -> bool {
        let val = Self::get_env(key, &default.to_string()).to_lowercase();
        matches!(val.as_str(), "true" | "1" | "yes" | "on")
    }

    fn parse_service_keys() -> anyhow::Result<Vec<String>> {
        let keys_str = Self::require_env("AUTH_SERVICE_KEYS")?;
        let keys: Vec<String> = keys_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        
        anyhow::ensure!(!keys.is_empty(), "AUTH_SERVICE_KEYS cannot be empty");
        Ok(keys)
    }

    /// Parse service credentials from environment.
    /// Format: service_id:secret (comma-separated)
    /// Note: The secret should already be hashed, or can be raw (will be hashed on first use)
    fn parse_service_credentials() -> anyhow::Result<Vec<(String, String)>> {
        let creds_str = Self::get_env("AUTH_SERVICE_CREDENTIALS", "");
        if creds_str.is_empty() {
            return Ok(Vec::new());
        }
        
        let credentials: Vec<(String, String)> = creds_str
            .split(',')
            .filter(|s| !s.trim().is_empty())
            .map(|s| {
                let parts: Vec<&str> = s.split(':').collect();
                if parts.len() >= 2 {
                    Ok((parts[0].trim().to_string(), parts[1].trim().to_string()))
                } else {
                    Err(anyhow::anyhow!("Invalid service credential format: {}", s))
                }
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        
        Ok(credentials)
    }
}

impl std::fmt::Display for DeploymentMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeploymentMode::Development => write!(f, "development"),
            DeploymentMode::Production => write!(f, "production"),
            DeploymentMode::Test => write!(f, "test"),
        }
    }
}
