//! Google RS256 token validator.
//!
//! Validates Google ID tokens using JWKS.

use std::sync::Arc;
use tokio::sync::Mutex;
use futures::future::BoxFuture;
use jsonwebtoken::{decode_header, decode, Algorithm, DecodingKey, Validation};
use pkcs1::EncodeRsaPublicKey;
use crate::core::error::TokenError;

use crate::core::identity::ExternalIdentity;
use crate::core::usecases::ports::external_token_validator::ExternalTokenValidator;
use crate::core::error::CoreError;
use crate::adapters::crypto::token::google_validator_config::GoogleValidatorConfig;
use crate::adapters::crypto::token::jwks_provider::JwksProvider;

/// Google RS256 token validator.
#[derive(Debug, Clone)]
pub struct GoogleRs256Validator {
    pub config: GoogleValidatorConfig,
    pub jwks_provider: Arc<Mutex<JwksProvider>>,
}

#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
struct GoogleClaims {
    iss: String,
    aud: String,
    sub: String,
    exp: usize,
    email: Option<String>,
    name: Option<String>,
    family_name: Option<String>,
    picture: Option<String>,
}

impl GoogleRs256Validator {
    /// Create new validator from config.
    pub fn new(config: GoogleValidatorConfig) -> Self {
        let jwks_provider = Arc::new(Mutex::new(JwksProvider::new(config.jwks_url.clone())));
        Self {
            config,
            jwks_provider,
        }
    }
}

impl ExternalTokenValidator for GoogleRs256Validator {
    fn validate(&self, token: &str) -> BoxFuture<'static, Result<ExternalIdentity, CoreError>> {
        let token = token.to_string(); //  take ownership so 'static is satisfied
        let config = self.config.clone();
        let jwks_provider = Arc::clone(&self.jwks_provider);
        Box::pin(async move {
            // Decode header
            let header = decode_header(&token)
                .map_err(|e| CoreError::Token(TokenError::Malformed { reason: format!("Invalid header: {}", e) }))?;

            //  Cleaner algorithm check
            if header.alg != Algorithm::RS256 {
                return Err(CoreError::Token(TokenError::UnsupportedAlgorithm {
                    algorithm: format!("{:?}", header.alg),
                }));
            }

            let kid = header.kid
                .ok_or_else(|| CoreError::Token(TokenError::KeyIdNotFound { kid: "missing".to_string() }))?;

            //  Drop the lock as soon as we have the key — don't hold it across await
            let rsa_key = {
                let provider = jwks_provider.lock().await;
                provider.get_key(&kid).await
                    .ok_or_else(|| CoreError::Token(TokenError::KeyIdNotFound { kid }))?
            };

            //  PKCS#1 DER — matches what from_rsa_der expects
            let der = rsa_key.to_pkcs1_der()
                .map_err(|e| CoreError::Token(TokenError::Malformed { reason: format!("Key DER: {}", e) }))?;

            //  from_rsa_der returns DecodingKey directly, no Result
            let decoding_key = DecodingKey::from_rsa_der(der.as_bytes());

            // Setup validation
            let mut validation = Validation::new(Algorithm::RS256);
            validation.set_issuer(&[&config.issuer]);
            validation.set_audience(&[&config.audience]);
            validation.validate_exp = true;

            // Decode & validate
            let token_data = decode::<GoogleClaims>(&token, &decoding_key, &validation)
                .map_err(|e| {
                    if *e.kind() == jsonwebtoken::errors::ErrorKind::ExpiredSignature {
                        CoreError::Token(TokenError::Expired { expired_at: "JWT exp".to_string() })
                    } else {
                        CoreError::Token(TokenError::SignatureInvalid { reason: e.to_string() })
                    }
                })?;

            // Map to domain identity
            ExternalIdentity::new(
                "google".to_string(),
                token_data.claims.sub.clone(),
                token_data.claims.email.clone(),
                token_data.claims.name.clone(),
                token_data.claims.family_name.clone(),
                token_data.claims.picture.clone(),
            )
            .map_err(|e| CoreError::Token(TokenError::InvalidClaims { reason: e.to_string() }))
        })
    }
}