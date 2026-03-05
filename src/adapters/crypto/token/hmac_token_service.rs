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
//! - **JWT Standard Compliant**: Uses i64 timestamps, flattened claims

use crate::adapters::crypto::error::JwtError;
use crate::adapters::crypto::token::HmacKey;
use crate::core::token::{Token, TokenClaims};
use crate::core::usecases::ports::TokenService;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

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
    pub fn from_secret_key(key: &[u8]) -> Result<Self, JwtError> {
        let hmac_key = HmacKey::from_bytes(key)
            .map_err(|e| JwtError::invalid_key(e))?;
        
        Self::from_key(&hmac_key)
    }

    /// Set the service token key for signing/validating service-to-service tokens.
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

    /// Encode TokenClaims into a JWT token.
    pub fn encode_token(&self, claims: &TokenClaims) -> Result<String, JwtError> {
        // Create a serialization struct that matches JWT format
        #[derive(Serialize)]
        struct JwtClaims<'a> {
            sub: &'a str,
            sid: Option<&'a str>,
            aud: Option<Vec<&'a str>>,
            iat: i64,
            exp: i64,
            nbf: Option<i64>,
            scope: Option<Vec<&'a str>>,
            #[serde(rename = "token_type")]
            token_type: &'a str,
        }

        let audience = claims.aud.as_ref().map(|aud| {
            aud.iter().map(|s| s.as_str()).collect::<Vec<&str>>()
        });

        let scope = if claims.scope.is_empty() {
            None
        } else {
            Some(claims.scope.iter().map(|s| s.as_str()).collect::<Vec<&str>>())
        };

        let jwt_claims = JwtClaims {
            sub: &claims.sub,
            sid: claims.sid.as_deref(),
            aud: audience,
            iat: claims.iat,
            exp: claims.exp,
            nbf: claims.nbf,
            scope,
            token_type: &claims.token_type,
        };

        let header = Header::new(self.algorithm);

        encode(&header, &jwt_claims, &self.encoding_key)
            .map_err(|e| JwtError::encoding(format!("Token encoding failed: {}", e)))
    }

    /// Decode and validate a JWT token.
    fn decode_token(&self, token: &str) -> Result<TokenClaims, JwtError> {
        let validation = self.create_validation();

        // First decode to get raw claims, then map to our struct
        #[derive(Deserialize)]
        struct RawJwtClaims {
            sub: String,
            #[serde(rename = "sid")]
            session_id: Option<String>,
            aud: Option<Vec<String>>,
            iat: i64,
            exp: i64,
            nbf: Option<i64>,
            scope: Option<Vec<String>>,
            #[serde(rename = "token_type")]
            token_type: String,
        }

        let token_data = decode::<RawJwtClaims>(token, &self.decoding_key, &validation)
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

        let raw = token_data.claims;

        // Scope is now an array
        let scope = raw.scope.unwrap_or_default();

        Ok(TokenClaims {
            sub: raw.sub,
            sid: raw.session_id,
            aud: raw.aud,
            iat: raw.iat,
            exp: raw.exp,
            nbf: raw.nbf,
            scope,
            token_type: raw.token_type,
        })
    }
}

impl TokenService for HmacTokenService {
    fn issue_access_token(&self, _subject: &str, claims: &str) -> Token {
        // Parse the claims JSON to extract identity information
        // The claims JSON has format: {"sub":"user_id","type":"access","exp":123456,"sid":"session_id"}
        let claims_json: serde_json::Value = serde_json::from_str(claims).unwrap_or_default();
        
        let user_id = claims_json.get("sub")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        
        let session_id = claims_json.get("sid")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let now = chrono::Utc::now();
        let expires = now + chrono::Duration::hours(1); // 1 hour for access tokens

        let token_claims = TokenClaims::new(
            user_id,
            now.timestamp(),
            expires.timestamp(),
            "access".to_string(),
        )
        .with_sid(session_id.unwrap_or_default());

        match self.encode_token(&token_claims) {
            Ok(token_value) => Token::new(token_value),
            Err(_) => Token::new(""),
        }
    }

    fn issue_refresh_token(&self, _subject: &str, claims: &str) -> Token {
        // Parse the claims JSON to extract identity information
        let claims_json: serde_json::Value = serde_json::from_str(claims).unwrap_or_default();
        
        let user_id = claims_json.get("sub")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        
        let session_id = claims_json.get("sid")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let now = chrono::Utc::now();
        let expires = now + chrono::Duration::days(7); // 7 days for refresh tokens

        let token_claims = TokenClaims::new(
            user_id,
            now.timestamp(),
            expires.timestamp(),
            "refresh".to_string(),
        )
        .with_sid(session_id.unwrap_or_default());

        match self.encode_token(&token_claims) {
            Ok(token_value) => Token::new(token_value),
            Err(_) => Token::new(""),
        }
    }

    fn validate_access_token(&self, token: &Token) -> Result<String, ()> {
        let token_str = token.value();
        
        if token_str.is_empty() {
            return Err(());
        }

        match self.decode_token(token_str) {
            Ok(claims) => {
                // Build claims JSON for return
                let mut claims_map = serde_json::Map::new();
                
                claims_map.insert("sub".to_string(), serde_json::Value::String(claims.sub));
                claims_map.insert("type".to_string(), serde_json::Value::String(claims.token_type));
                claims_map.insert("exp".to_string(), serde_json::Value::Number(claims.exp.into()));
                claims_map.insert("iat".to_string(), serde_json::Value::Number(claims.iat.into()));
                
                if let Some(sid) = claims.sid {
                    claims_map.insert("sid".to_string(), serde_json::Value::String(sid));
                }
                
                if let Some(aud) = claims.aud {
                    claims_map.insert("aud".to_string(), serde_json::Value::Array(
                        aud.into_iter().map(serde_json::Value::String).collect()
                    ));
                }
                
                if !claims.scope.is_empty() {
                    claims_map.insert("scope".to_string(), serde_json::Value::Array(
                        claims.scope.into_iter().map(serde_json::Value::String).collect()
                    ));
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
                if claims.token_type != "refresh" {
                    return Err(());
                }
                
                // Build claims JSON for return
                let mut claims_map = serde_json::Map::new();
                
                claims_map.insert("sub".to_string(), serde_json::Value::String(claims.sub));
                claims_map.insert("type".to_string(), serde_json::Value::String("refresh".to_string()));
                claims_map.insert("exp".to_string(), serde_json::Value::Number(claims.exp.into()));
                claims_map.insert("iat".to_string(), serde_json::Value::Number(claims.iat.into()));
                
                if let Some(sid) = claims.sid {
                    claims_map.insert("sid".to_string(), serde_json::Value::String(sid));
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
        
        // Parse the claims JSON
        let claims_json: serde_json::Value = serde_json::from_str(claims).unwrap_or_default();
        
        let service_id = claims_json.get("sub")
            .and_then(|v| v.as_str())
            .unwrap_or(subject)
            .to_string();

        let now = chrono::Utc::now();
        let expires = now + chrono::Duration::hours(1);

        let mut token_claims = TokenClaims::new(
            service_id,
            now.timestamp(),
            expires.timestamp(),
            "service".to_string(),
        );

        // Add audience if provided
        if let Some(aud_value) = claims_json.get("aud") {
            if let Some(aud_str) = aud_value.as_str() {
                token_claims = token_claims.with_audience(vec![aud_str.to_string()]);
            }
        }

        // Encode with service key
        #[derive(Serialize)]
        struct JwtClaims<'a> {
            sub: &'a str,
            sid: Option<&'a str>,
            aud: Option<Vec<&'a str>>,
            iat: i64,
            exp: i64,
            nbf: Option<i64>,
            scope: Option<Vec<&'a str>>,
            #[serde(rename = "token_type")]
            token_type: &'a str,
        }

        let audience = token_claims.aud.as_ref().map(|aud| {
            aud.iter().map(|s| s.as_str()).collect()
        });

        // Service tokens have no scope by default
        let _scope: Option<Vec<&str>> = None;

        let jwt_claims = JwtClaims {
            sub: &token_claims.sub,
            sid: token_claims.sid.as_deref(),
            aud: audience,
            iat: token_claims.iat,
            exp: token_claims.exp,
            nbf: token_claims.nbf,
            scope: None,
            token_type: &token_claims.token_type,
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

        #[derive(Deserialize)]
        struct RawJwtClaims {
            sub: String,
            #[serde(rename = "sid")]
            _session_id: Option<String>,
            _aud: Option<Vec<String>>,
            iat: i64,
            exp: i64,
            _nbf: Option<i64>,
            _scope: Option<String>,
            #[serde(rename = "token_type")]
            token_type: String,
        }

        match decode::<RawJwtClaims>(token_str, decoding_key, &validation) {
            Ok(token_data) => {
                let claims = token_data.claims;
                
                // Validate that this is actually a service token
                if claims.token_type != "service" {
                    return Err(());
                }
                
                // Build claims JSON for return
                let mut claims_map = serde_json::Map::new();
                
                claims_map.insert("sub".to_string(), serde_json::Value::String(claims.sub));
                claims_map.insert("type".to_string(), serde_json::Value::String("service".to_string()));
                claims_map.insert("exp".to_string(), serde_json::Value::Number(claims.exp.into()));
                claims_map.insert("iat".to_string(), serde_json::Value::Number(claims.iat.into()));
                
                let claims_json = serde_json::to_string(&claims_map).unwrap_or_default();
                Ok(claims_json)
            }
            Err(_) => Err(()),
        }
    }
}
