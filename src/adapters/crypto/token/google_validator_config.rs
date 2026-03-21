//! Google OAuth validator configuration.
//!
//! Contains Google-specific configuration for RS256 token validation.

use serde::Deserialize;

/// Configuration for Google RS256 token validator.
#[derive(Debug, Clone, Deserialize)]
pub struct GoogleValidatorConfig {
    /// Google JWKS URL for public keys.
    pub jwks_url: String,
    
    /// Expected token issuer.
    pub issuer: String,
    
    /// Expected audience (matches client_id).
    pub audience: String,
}

impl GoogleValidatorConfig {
    /// Create a new config.
    pub fn new(jwks_url: String, issuer: String, audience: String) -> Self {
        Self { 
            jwks_url, 
            issuer, 
            audience 
        }
    }
}

