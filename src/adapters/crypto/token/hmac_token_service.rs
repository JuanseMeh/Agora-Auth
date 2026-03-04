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
    /// Token type: "access" or "refresh"
    #[serde(rename = "type")]
    token_type: Option<String>,
    /// Optional session ID
    #[serde(rename = "sid")]
    session_id: Option<String>,
}

/// HMAC-SHA256-based token service implementation.
///
/// This service issues and validates JWT tokens signed with HMAC-SHA256.
/// It implements the `TokenService` port from the core domain.
#[derive(Debug, Clone)]
pub struct HmacTokenService {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    service_encoding_key: Option<EncodingKey>,
    service_decoding_key: Option<DecodingKey>,
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
            service_encoding_key: None,
            service_decoding_key: None,
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

    /// Set the service token key for signing/validating service-to-service tokens.
    ///
    /// # Arguments
    ///
    /// * `key` - 32-byte HMAC-SHA256 key for service tokens
    ///
    /// # Errors
    ///
    /// Returns `JwtError::InvalidKey` if the key is not valid HMAC material.
    pub fn with_service_token_key(mut self, key: &[u8]) -> Result<Self, JwtError> {
        let hmac_key = HmacKey::from_bytes(key)
            .map_err(|e| JwtError::invalid_key(e))?;
        
        self.service_encoding_key = Some(hmac_key.encoding_key().clone());
        self.service_decoding_key = Some(hmac_key.decoding_key().clone());
        
        Ok(self)
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
            token_type: claims.token_type.clone(),
            session_id: None, // Will be set in issue_access_token/issue_refresh_token
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
        // The claims JSON has format: {"sub":"user_id","type":"access","exp":123456,"sid":"session_id"}
        let claims_json: serde_json::Value = serde_json::from_str(claims).unwrap_or_default();
        
        let user_id = claims_json.get("sub")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        
        let session_id = claims_json.get("sid")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        
        let identity = crate::core::identity::IdentityClaims {
            user_id,
            workspace_id: None, // Not included in claims
        };

        let now = chrono::Utc::now();
        let expires = now + chrono::Duration::hours(1); // 1 hour for access tokens

        let token_claims = TokenClaims {
            identity,
            issued_at: now.to_rfc3339(),
            expires_at: expires.to_rfc3339(),
            not_before: None,
            scopes: None,
            token_type: Some("access".to_string()),
        };

        // Encode token with session_id
        let exp = chrono::DateTime::parse_from_rfc3339(&token_claims.expires_at)
            .map(|dt| dt.timestamp())
            .unwrap_or_else(|_| (now + chrono::Duration::hours(1)).timestamp());
        
        let iat = chrono::DateTime::parse_from_rfc3339(&token_claims.issued_at)
            .map(|dt| dt.timestamp())
            .unwrap_or_else(|_| now.timestamp());

        let custom_claims = serde_json::to_string(&token_claims.identity).unwrap_or_default();
        
        let jwt_claims = JwtClaims {
            sub: token_claims.identity.user_id.clone().unwrap_or_default(),
            custom_claims,
            iat,
            exp,
            nbf: None,
            scope: None,
            token_type: token_claims.token_type.clone(),
            session_id,
        };

        let header = Header::new(self.algorithm);
        
        match encode(&header, &jwt_claims, &self.encoding_key) {
            Ok(token_value) => Token::new(token_value),
            Err(_) => Token::new(""), // Return empty token on error (should not happen)
        }
    }

    fn issue_refresh_token(&self, _subject: &str, claims: &str) -> Token {
        // Parse the claims JSON to extract identity information
        // The claims JSON has format: {"sub":"user_id","type":"refresh","exp":123456,"sid":"session_id"}
        let claims_json: serde_json::Value = serde_json::from_str(claims).unwrap_or_default();
        
        let user_id = claims_json.get("sub")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        
        let session_id = claims_json.get("sid")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        
        let identity = crate::core::identity::IdentityClaims {
            user_id,
            workspace_id: None, // Not included in claims
        };

        let now = chrono::Utc::now();
        let expires = now + chrono::Duration::days(7); // 7 days for refresh tokens

        let token_claims = TokenClaims {
            identity,
            issued_at: now.to_rfc3339(),
            expires_at: expires.to_rfc3339(),
            not_before: None,
            scopes: None,
            token_type: Some("refresh".to_string()),
        };

        // Encode token with session_id
        let exp = chrono::DateTime::parse_from_rfc3339(&token_claims.expires_at)
            .map(|dt| dt.timestamp())
            .unwrap_or_else(|_| (now + chrono::Duration::days(7)).timestamp());
        
        let iat = chrono::DateTime::parse_from_rfc3339(&token_claims.issued_at)
            .map(|dt| dt.timestamp())
            .unwrap_or_else(|_| now.timestamp());

        let custom_claims = serde_json::to_string(&token_claims.identity).unwrap_or_default();
        
        let jwt_claims = JwtClaims {
            sub: token_claims.identity.user_id.clone().unwrap_or_default(),
            custom_claims,
            iat,
            exp,
            nbf: None,
            scope: None,
            token_type: token_claims.token_type.clone(),
            session_id,
        };

        let header = Header::new(self.algorithm);
        
        match encode(&header, &jwt_claims, &self.encoding_key) {
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
                // Build claims JSON including token type and timestamps
                let mut claims_map: serde_json::Map<String, serde_json::Value> = 
                    serde_json::from_str(&claims.custom_claims).unwrap_or_default();
                
                // Add token type if present
                if let Some(token_type) = claims.token_type {
                    claims_map.insert("type".to_string(), serde_json::Value::String(token_type));
                }
                
                // Add user_id from sub if present (sub is the canonical source)
                if !claims.sub.is_empty() {
                    claims_map.insert("sub".to_string(), serde_json::Value::String(claims.sub));
                }
                
                // Add expiration timestamp (required for validation)
                claims_map.insert("exp".to_string(), serde_json::Value::Number(claims.exp.into()));
                
                // Add issued-at timestamp
                claims_map.insert("iat".to_string(), serde_json::Value::Number(claims.iat.into()));
                
                // Add session_id if present
                if let Some(session_id) = claims.session_id {
                    claims_map.insert("sid".to_string(), serde_json::Value::String(session_id));
                }
                
                let claims_json = serde_json::to_string(&claims_map).unwrap_or_default();
                Ok(claims_json)
            }
            Err(_) => Err(()),
        }
    }

    fn validate_refresh_token(&self, token: &Token) -> Result<String, ()> {
        let token_str = token.value();
        
        if token_str.is_empty() {
            return Err(());
        }

        match self.decode_token(token_str) {
            Ok(claims) => {
                // Validate that this is actually a refresh token
                let token_type = claims.token_type.as_deref();
                if token_type != Some("refresh") {
                    // Token is valid but not a refresh token
                    return Err(());
                }
                
                // Build claims JSON including token type and timestamps
                let mut claims_map: serde_json::Map<String, serde_json::Value> = 
                    serde_json::from_str(&claims.custom_claims).unwrap_or_default();
                
                // Add token type
                claims_map.insert("type".to_string(), serde_json::Value::String("refresh".to_string()));
                
                // Add user_id from sub if present (sub is the canonical source)
                if !claims.sub.is_empty() {
                    claims_map.insert("sub".to_string(), serde_json::Value::String(claims.sub));
                }
                
                // Add expiration timestamp (required for validation)
                claims_map.insert("exp".to_string(), serde_json::Value::Number(claims.exp.into()));
                
                // Add issued-at timestamp
                claims_map.insert("iat".to_string(), serde_json::Value::Number(claims.iat.into()));
                
                // Add session_id if present
                if let Some(session_id) = claims.session_id {
                    claims_map.insert("sid".to_string(), serde_json::Value::String(session_id));
                }
                
                let claims_json = serde_json::to_string(&claims_map).unwrap_or_default();
                Ok(claims_json)
            }
            Err(_) => Err(()),
        }
    }

    fn issue_service_token(&self, subject: &str, claims: &str) -> Token {
        // Use service token key if configured, otherwise fall back to main key
        let encoding_key = self.service_encoding_key.as_ref()
            .unwrap_or(&self.encoding_key);
        
        // Parse the claims JSON to extract identity information
        // Service token claims format: {"sub":"service_id","type":"service","exp":123456,"iss":"auth_service","aud":"auth_service"}
        let claims_json: serde_json::Value = serde_json::from_str(claims).unwrap_or_default();
        
        let service_id = claims_json.get("sub")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| subject.to_string());
        
        let identity = crate::core::identity::IdentityClaims {
            user_id: Some(service_id.clone()),
            workspace_id: None,
        };

        let now = chrono::Utc::now();
        let expires = now + chrono::Duration::hours(1); // 1 hour default for service tokens

        let token_claims = TokenClaims {
            identity,
            issued_at: now.to_rfc3339(),
            expires_at: expires.to_rfc3339(),
            not_before: None,
            scopes: None,
            token_type: Some("service".to_string()),
        };

        // Encode token
        let exp = chrono::DateTime::parse_from_rfc3339(&token_claims.expires_at)
            .map(|dt| dt.timestamp())
            .unwrap_or_else(|_| (now + chrono::Duration::hours(1)).timestamp());
        
        let iat = chrono::DateTime::parse_from_rfc3339(&token_claims.issued_at)
            .map(|dt| dt.timestamp())
            .unwrap_or_else(|_| now.timestamp());

        let custom_claims = serde_json::to_string(&token_claims.identity).unwrap_or_default();
        
        // Extract iss and aud from claims JSON
        let _issuer = claims_json.get("iss")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "auth_service".to_string());
        
        let _audience = claims_json.get("aud")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "auth_service".to_string());

        let jwt_claims = JwtClaims {
            sub: service_id,
            custom_claims,
            iat,
            exp,
            nbf: None,
            scope: None,
            token_type: token_claims.token_type.clone(),
            session_id: None,
        };

        let header = Header::new(self.algorithm);
        
        match encode(&header, &jwt_claims, encoding_key) {
            Ok(token_value) => Token::new(token_value),
            Err(_) => Token::new(""),
        }
    }

    fn validate_service_token(&self, token: &Token) -> Result<String, ()> {
        let token_str = token.value();
        
        if token_str.is_empty() {
            return Err(());
        }

        // Use service token key if configured, otherwise fall back to main key
        let decoding_key = self.service_decoding_key.as_ref()
            .unwrap_or(&self.decoding_key);
        
        let mut validation = self.create_validation();
        // Don't validate audience/issuer for service tokens by default to allow flexibility
        validation.validate_aud = false;
        
        match decode::<JwtClaims>(token_str, decoding_key, &validation) {
            Ok(token_data) => {
                let claims = token_data.claims;
                
                // Validate that this is actually a service token
                let token_type = claims.token_type.as_deref();
                if token_type != Some("service") {
                    // Token is valid but not a service token
                    return Err(());
                }
                
                // Build claims JSON including token type and timestamps
                let mut claims_map: serde_json::Map<String, serde_json::Value> = 
                    serde_json::from_str(&claims.custom_claims).unwrap_or_default();
                
                // Add token type
                claims_map.insert("type".to_string(), serde_json::Value::String("service".to_string()));
                
                // Add service_id from sub
                if !claims.sub.is_empty() {
                    claims_map.insert("sub".to_string(), serde_json::Value::String(claims.sub));
                }
                
                // Add expiration timestamp
                claims_map.insert("exp".to_string(), serde_json::Value::Number(claims.exp.into()));
                
                // Add issued-at timestamp
                claims_map.insert("iat".to_string(), serde_json::Value::Number(claims.iat.into()));
                
                let claims_json = serde_json::to_string(&claims_map).unwrap_or_default();
                Ok(claims_json)
            }
            Err(_) => Err(()),
        }
    }
}
