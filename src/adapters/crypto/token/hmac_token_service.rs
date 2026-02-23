//! HMAC-SHA256 token service implementation.
//!
//! This module provides a concrete implementation of the `TokenService` port
//! using HMAC-SHA256 signatures via the jsonwebtoken library.
//!
//! # Design Principles
//!
//! - **Pure cryptographic**: No session awareness, no revocation checks
//! - **Deterministic errors**: All failures map to specific error types
//! - **No secret leakage**: Keys are never logged or exposed in errors
//! - **Algorithm enforcement**: Only HS256 is supported

use crate::adapters::crypto::error::JwtError;
use crate::adapters::crypto::token::HmacKey;
use crate::core::token::{Token, TokenClaims};
use crate::core::usecases::ports::TokenService;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

/// JWT claims structure for serialization.
///
/// This internal struct maps our domain TokenClaims to the format
/// expected by the jsonwebtoken library.
#[derive(Debug, Serialize, Deserialize)]
struct JwtClaims {
    /// Subject (user identifier)
    sub: String,
    /// Custom claims data (JSON string)
    custom_claims: String,
    /// Issued at timestamp (Unix timestamp)
    iat: i64,
    /// Expiration timestamp (Unix timestamp)
    exp: i64,
    /// Optional not-before timestamp
    nbf: Option<i64>,
    /// Optional scopes
    scope: Option<String>,
}

/// HMAC-SHA256-based token service implementation.
///
/// This service issues and validates JWT tokens signed with HMAC-SHA256.
/// It implements the `TokenService` port from the core domain.
#[derive(Debug, Clone)]
pub struct HmacTokenService {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    algorithm: Algorithm,
    issuer: Option<String>,
    audience: Option<String>,
}

impl HmacTokenService {
    /// Create a new HMAC token service from a key.
    ///
    /// # Arguments
    ///
    /// * `key` - An HmacKey containing the symmetric key
    ///
    /// # Errors
    ///
    /// Returns `JwtError::InvalidKey` if the key is not valid.
    pub fn from_key(key: &HmacKey) -> Result<Self, JwtError> {
        Ok(Self {
            encoding_key: key.encoding_key().clone(),
            decoding_key: key.decoding_key().clone(),
            algorithm: Algorithm::HS256,
            issuer: None,
            audience: None,
        })
    }

    /// Create a new HMAC token service with the given raw key bytes.
    ///
    /// This is a convenience method that creates a key internally.
    /// For production use, prefer `from_key` with a properly managed key.
    ///
    /// # Arguments
    ///
    /// * `key` - 32-byte HMAC-SHA256 key
    ///
    /// # Errors
    ///
    /// Returns `JwtError::InvalidKey` if the key is not valid HMAC material.
    pub fn from_secret_key(key: &[u8]) -> Result<Self, JwtError> {
        let hmac_key = HmacKey::from_bytes(key)
            .map_err(|e| JwtError::invalid_key(e))?;
        
        Self::from_key(&hmac_key)
    }

    /// Set the expected issuer for token validation.
    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// Set the expected audience for token validation.
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    /// Create a validation configuration for decoding tokens.
    fn create_validation(&self) -> Validation {
        let mut validation = Validation::new(self.algorithm);

        if let Some(ref issuer) = self.issuer {
            validation.set_issuer(&[issuer.clone()]);
        }

        if let Some(ref audience) = self.audience {
            validation.set_audience(&[audience.clone()]);
        }

        validation
    }

    /// Encode claims into a JWT token.
    pub fn encode_token(&self, claims: &TokenClaims) -> Result<String, JwtError> {
        // Parse timestamps
        let exp = chrono::DateTime::parse_from_rfc3339(&claims.expires_at)
            .map_err(|e| JwtError::encoding(format!("Invalid expiration timestamp: {}", e)))?
            .timestamp();

        let iat = chrono::DateTime::parse_from_rfc3339(&claims.issued_at)
            .map_err(|e| JwtError::encoding(format!("Invalid issued-at timestamp: {}", e)))?
            .timestamp();

        let nbf = claims.not_before.as_ref().map(|nbf| {
            chrono::DateTime::parse_from_rfc3339(nbf)
                .map(|dt| dt.timestamp())
                .ok()
        }).flatten();

        // Serialize custom claims (identity info)
        let custom_claims = serde_json::to_string(&claims.identity)
            .map_err(|e| JwtError::encoding(format!("Failed to serialize claims: {}", e)))?;

        // Build scope string if present
        let scope = claims.scopes.as_ref().map(|scopes| scopes.join(" "));

        let jwt_claims = JwtClaims {
            sub: claims.identity.user_id.clone().unwrap_or_default(),
            custom_claims,
            iat,
            exp,
            nbf,
            scope,
        };

        let header = Header::new(self.algorithm);

        encode(&header, &jwt_claims, &self.encoding_key)
            .map_err(|e| JwtError::encoding(format!("Token encoding failed: {}", e)))
    }

    /// Decode and validate a JWT token.
    fn decode_token(&self, token: &str) -> Result<JwtClaims, JwtError> {
        let validation = self.create_validation();

        let token_data = decode::<JwtClaims>(token, &self.decoding_key, &validation)
            .map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                    JwtError::expired("Token has expired")
                }
                jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                    JwtError::signature_invalid("Invalid signature")
                }
                jsonwebtoken::errors::ErrorKind::InvalidIssuer => {
                    JwtError::algorithm_mismatch("Invalid issuer")
                }
                jsonwebtoken::errors::ErrorKind::InvalidAudience => {
                    JwtError::algorithm_mismatch("Invalid audience")
                }
                jsonwebtoken::errors::ErrorKind::InvalidAlgorithm => {
                    JwtError::algorithm_mismatch("Algorithm mismatch")
                }
                _ => JwtError::decoding(format!("Token decoding failed: {}", e)),
            })?;

        Ok(token_data.claims)
    }
}

impl TokenService for HmacTokenService {
    fn issue_access_token(&self, _subject: &str, claims: &str) -> Token {
        // Parse the claims JSON to extract identity information
        let identity: crate::core::identity::IdentityClaims = 
            serde_json::from_str(claims).unwrap_or_default();

        let now = chrono::Utc::now();
        let expires = now + chrono::Duration::hours(1); // 1 hour for access tokens

        let token_claims = TokenClaims {
            identity,
            issued_at: now.to_rfc3339(),
            expires_at: expires.to_rfc3339(),
            not_before: None,
            scopes: None,
        };

        match self.encode_token(&token_claims) {
            Ok(token_value) => Token::new(token_value),
            Err(_) => Token::new(""), // Return empty token on error (should not happen)
        }
    }

    fn issue_refresh_token(&self, _subject: &str, claims: &str) -> Token {
        // Parse the claims JSON to extract identity information
        let identity: crate::core::identity::IdentityClaims = 
            serde_json::from_str(claims).unwrap_or_default();

        let now = chrono::Utc::now();
        let expires = now + chrono::Duration::days(7); // 7 days for refresh tokens

        let token_claims = TokenClaims {
            identity,
            issued_at: now.to_rfc3339(),
            expires_at: expires.to_rfc3339(),
            not_before: None,
            scopes: None,
        };

        match self.encode_token(&token_claims) {
            Ok(token_value) => Token::new(token_value),
            Err(_) => Token::new(""), // Return empty token on error (should not happen)
        }
    }

    fn validate_access_token(&self, token: &Token) -> Result<String, ()> {
        let token_str = token.value();
        
        if token_str.is_empty() {
            return Err(());
        }

        match self.decode_token(token_str) {
            Ok(claims) => {
                // Return the custom claims as JSON string
                Ok(claims.custom_claims)
            }
            Err(_) => Err(()),
        }
    }

    fn validate_refresh_token(&self, token: &Token) -> Result<String, ()> {
        // Same validation logic as access tokens
        // In a real implementation, you might have different validation rules
        self.validate_access_token(token)
    }
}
