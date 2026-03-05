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
    /// JWT signing algorithm: "eddsa" or "hmac"
    pub token_algorithm: TokenAlgorithm,
    /// JWT signing key for HMAC (HS256 symmetric key)
    pub token_signing_key: String,
    /// EdDSA private key (base64 encoded, 32 bytes)
    pub eddsa_private_key: Option<String>,
    /// EdDSA public key (base64 encoded, 32 bytes)
    pub eddsa_public_key: Option<String>,
    /// Access token TTL in minutes
    pub access_token_ttl_mins: u64,
    /// Refresh token TTL in days
    pub refresh_token_ttl_days: u64,
}

/// JWT signing algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenAlgorithm {
    /// EdDSA (Ed25519) - asymmetric
    EdDSA,
    /// HMAC-SHA256 - symmetric
    Hmac,
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
    /// Service token signing algorithm
    pub service_token_algorithm: TokenAlgorithm,
    /// Service token signing key for HMAC (base64 encoded)
    pub service_token_signing_key: String,
    /// EdDSA service token private key (base64 encoded, 32 bytes)
    pub eddsa_service_private_key: Option<String>,
    /// EdDSA service token public key (base64 encoded, 32 bytes)
    pub eddsa_service_public_key: Option<String>,
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
                token_algorithm: Self::parse_token_algorithm()?,
                token_signing_key: Self::require_env("AUTH_TOKEN_SIGNING_KEY")?,
                eddsa_private_key: Self::get_env("AUTH_EDDSA_PRIVATE_KEY", "").into(),
                eddsa_public_key: Self::get_env("AUTH_EDDSA_PUBLIC_KEY", "").into(),
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
                service_token_algorithm: Self::parse_service_token_algorithm()?,
                service_token_signing_key: Self::require_env("AUTH_SERVICE_TOKEN_SIGNING_KEY")?,
                eddsa_service_private_key: Self::get_env("AUTH_EDDSA_SERVICE_PRIVATE_KEY", "").into(),
                eddsa_service_public_key: Self::get_env("AUTH_EDDSA_SERVICE_PUBLIC_KEY", "").into(),
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

    fn parse_token_algorithm() -> anyhow::Result<TokenAlgorithm> {
        let alg_str = Self::get_env("AUTH_TOKEN_ALGORITHM", "hmac").to_lowercase();
        match alg_str.as_str() {
            "eddsa" | "ed25519" => Ok(TokenAlgorithm::EdDSA),
            "hmac" | "hs256" | "hs384" | "hs512" => Ok(TokenAlgorithm::Hmac),
            _ => Err(anyhow::anyhow!(
                "Invalid AUTH_TOKEN_ALGORITHM: {}. Must be 'eddsa' or 'hmac'",
                alg_str
            )),
        }
    }

    fn parse_service_token_algorithm() -> anyhow::Result<TokenAlgorithm> {
        let alg_str = Self::get_env("AUTH_SERVICE_TOKEN_ALGORITHM", "hmac").to_lowercase();
        match alg_str.as_str() {
            "eddsa" | "ed25519" => Ok(TokenAlgorithm::EdDSA),
            "hmac" | "hs256" | "hs384" | "hs512" => Ok(TokenAlgorithm::Hmac),
            _ => Err(anyhow::anyhow!(
                "Invalid AUTH_SERVICE_TOKEN_ALGORITHM: {}. Must be 'eddsa' or 'hmac'",
                alg_str
            )),
        }
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
    /// Format: service_id:secret (comma-separated, but secret can contain commas if using PHC format)
    /// Note: The secret should be an Argon2 hash in PHC format: $argon2id$v=19$m=65536,t=3,p=4$...
    /// Note: In .env files, use $$ to escape $ (e.g., $$argon2id$$v=19$$m=65536,t=3,p=4$$...)
    fn parse_service_credentials() -> anyhow::Result<Vec<(String, String)>> {
        let creds_str = Self::get_env("AUTH_SERVICE_CREDENTIALS", "");
        if creds_str.is_empty() {
            return Ok(Vec::new());
        }
        
        // Note: The value should be quoted in .env to prevent $ variable expansion
        // e.g., AUTH_SERVICE_CREDENTIALS="user_service:$argon2id$..."
        
        // Log the actual raw value from env
        tracing::info!("[CONFIG] Parsed service credentials raw (first 60 chars): '{}'", &creds_str[..60.min(creds_str.len())]);
        
        // Parse credentials - handle PHC format which contains commas
        // Format: service_id:$argon2id$...,service_id2:$argon2id$...
        // We split on comma only when it's not inside the PHC hash
        let mut credentials: Vec<(String, String)> = Vec::new();
        let mut current_cred = String::new();
        let mut in_phc_hash = false;
        
        for ch in creds_str.chars() {
            if ch == ',' && !in_phc_hash {
                // Split here - we're at a credential separator
                if !current_cred.trim().is_empty() {
                    let parts: Vec<&str> = current_cred.splitn(2, ':').collect();
                    if parts.len() == 2 {
                        credentials.push((parts[0].trim().to_string(), parts[1].trim().to_string()));
                    }
                }
                current_cred = String::new();
            } else {
                current_cred.push(ch);
                
                // Detect start of PHC hash format (argon2id or argon2)
                // Once we see $argon2 or $argon2id, we're in the hash portion
                // and should not split on commas until we see the closing $$
                if current_cred.ends_with("$argon2id$") || current_cred.ends_with("$argon2$") {
                    in_phc_hash = true;
                }
            }
        }
        
        // Don't forget the last credential
        if !current_cred.trim().is_empty() {
            let parts: Vec<&str> = current_cred.splitn(2, ':').collect();
            if parts.len() == 2 {
                credentials.push((parts[0].trim().to_string(), parts[1].trim().to_string()));
            }
        }
        
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

impl std::fmt::Display for TokenAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenAlgorithm::EdDSA => write!(f, "EdDSA"),
            TokenAlgorithm::Hmac => write!(f, "Hmac"),
        }
    }
}
