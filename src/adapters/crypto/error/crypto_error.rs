/// Crypto adapter error types.

/*
This module defines errors specific to the crypto adapter layer.

These errors represent failures in cryptographic operations,
independent of business logic. They are NOT domain errors.

Design Principles:
 - **Isolation**: Crypto errors never leak cryptographic details upward
 - **Mapping**: All library errors are caught and mapped to CryptoError
 - **No panic**: All crypto operations return Results
 - **Deterministic**: Same input always produces same error type

Errors are organized by concern:
 - `Password`: Password hashing and verification errors
 - `Token`: JWT token encoding and decoding errors
*/

use crate::adapters::crypto::error::{
    JwtError, PasswordError,
};
use crate::core::error::{
    CredentialError, 
    CoreError, 
    TokenError
};

/// Error type for crypto adapter operations.
///
/// Variants are organized by concern:
/// - `Password`: Password hashing and verification errors
/// - `Token`: JWT token encoding and decoding errors
#[derive(Debug, Clone)]
pub enum CryptoError {
    /// Password hashing or verification error
    Password(PasswordError),
    /// JWT token encoding or decoding error
    Token(JwtError),
}

impl CryptoError {
    /// Create a password error
    pub fn password(error: PasswordError) -> Self {
        CryptoError::Password(error)
    }

    /// Create a token error
    pub fn token(error: JwtError) -> Self {
        CryptoError::Token(error)
    }

    /// Returns true if this is a password error
    pub fn is_password(&self) -> bool {
        matches!(self, CryptoError::Password(_))
    }

    /// Returns true if this is a token error
    pub fn is_token(&self) -> bool {
        matches!(self, CryptoError::Token(_))
    }
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::Password(e) => write!(f, "{}", e),
            CryptoError::Token(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for CryptoError {}

// From<argon2::password_hash::Error> implementations

impl From<argon2::password_hash::Error> for CryptoError {
    fn from(err: argon2::password_hash::Error) -> Self {
        // Categorize the argon2 error
        let crypto_err = match err {
            // Hashing failed - password too long or too short
            argon2::password_hash::Error::Password => {
                PasswordError::hashing("password too long or too short")
            }
            // Salt is invalid
            argon2::password_hash::Error::SaltInvalid(_) => {
                PasswordError::invalid_hash("invalid salt")
            }
            // Version is unsupported
            argon2::password_hash::Error::Version => {
                PasswordError::invalid_hash("unsupported argon2 version")
            }
            // Output buffer too small
            argon2::password_hash::Error::OutputSize { .. } => {
                PasswordError::hashing("output buffer size mismatch")
            }
            // Algorithm mismatch
            argon2::password_hash::Error::Algorithm => {
                PasswordError::invalid_hash("algorithm mismatch")
            }
            // Base64 encoding error
            argon2::password_hash::Error::B64Encoding(_) => {
                PasswordError::invalid_hash("base64 encoding error")
            }
            // Other errors
            _ => {
                PasswordError::hashing(err.to_string())
            }
        };
        CryptoError::Password(crypto_err)
    }
}

impl From<argon2::password_hash::Error> for CoreError {
    fn from(err: argon2::password_hash::Error) -> Self {
        let crypto_err: CryptoError = err.into();
        match crypto_err {
            CryptoError::Password(password_err) => {
                CoreError::Credential(CredentialError::verification_failed(password_err.to_string()))
            }
            CryptoError::Token(_) => {
                // This should never happen for argon2 errors
                CoreError::Credential(CredentialError::verification_failed(
                    "unexpected error type".to_string(),
                ))
            }
        }
    }
}

// From<jsonwebtoken::errors::Error> implementations

impl From<jsonwebtoken::errors::Error> for CryptoError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        // Categorize the jsonwebtoken error
        let jwt_err = match err.kind() {
            // Token is malformed
            jsonwebtoken::errors::ErrorKind::InvalidToken => {
                JwtError::invalid_token("token is malformed")
            }
            // Token signature is invalid
            jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                JwtError::decoding("invalid signature")
            }
            // Token has expired
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                JwtError::decoding("token has expired")
            }
            // Token is not yet valid
            jsonwebtoken::errors::ErrorKind::InvalidIssuer => {
                JwtError::invalid_token("invalid issuer")
            }
            // Token audience mismatch
            jsonwebtoken::errors::ErrorKind::InvalidAudience => {
                JwtError::invalid_token("invalid audience")
            }
            // Algorithm mismatch
            jsonwebtoken::errors::ErrorKind::InvalidAlgorithm => {
                JwtError::invalid_token("invalid algorithm")
            }
            // Invalid subject
            jsonwebtoken::errors::ErrorKind::InvalidSubject => {
                JwtError::invalid_token("invalid subject")
            }
            // Missing algorithm
            jsonwebtoken::errors::ErrorKind::MissingAlgorithm => {
                JwtError::invalid_token("missing algorithm")
            }
            // Invalid key format
            jsonwebtoken::errors::ErrorKind::InvalidKeyFormat => {
                JwtError::encoding("invalid key format")
            }
            // Invalid ECDSA key
            jsonwebtoken::errors::ErrorKind::InvalidEcdsaKey => {
                JwtError::encoding("invalid ECDSA key")
            }
            // Invalid RSA key
            jsonwebtoken::errors::ErrorKind::InvalidRsaKey(_) => {
                JwtError::encoding("invalid RSA key")
            }
            // Invalid algorithm name
            jsonwebtoken::errors::ErrorKind::InvalidAlgorithmName => {
                JwtError::invalid_token("invalid algorithm name")
            }
            // Immature signature (not yet valid)
            jsonwebtoken::errors::ErrorKind::ImmatureSignature => {
                JwtError::decoding("token not yet valid")
            }
            // Missing required claim
            jsonwebtoken::errors::ErrorKind::MissingRequiredClaim(_) => {
                JwtError::invalid_token("missing required claim")
            }
            // Other errors (Json, Utf8, Base64, Crypto)
            _ => {
                JwtError::decoding(err.to_string())
            }
        };
        CryptoError::Token(jwt_err)
    }
}

impl From<jsonwebtoken::errors::Error> for CoreError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        let crypto_err: CryptoError = err.into();
        match crypto_err {
            CryptoError::Token(jwt_err) => {
                let token_err: TokenError = jwt_err.into();
                CoreError::Token(token_err)
            }
            CryptoError::Password(_) => {
                // This should never happen for jsonwebtoken errors
                CoreError::Token(TokenError::malformed("unexpected error type"))
            }
        }
    }
}

// From<JwtError> to TokenError conversions

impl From<JwtError> for TokenError {
    fn from(err: JwtError) -> Self {
        match err {
            JwtError::Encoding { reason } => {
                TokenError::malformed(format!("encoding failed: {}", reason))
            }
            JwtError::Decoding { reason } => {
                TokenError::malformed(format!("decoding failed: {}", reason))
            }
            JwtError::InvalidToken { reason } => {
                TokenError::malformed(reason)
            }
        }
    }
}

// From<PasswordError> to CredentialError conversions

impl From<PasswordError> for CredentialError {
    fn from(err: PasswordError) -> Self {
        match err {
            PasswordError::Hashing { reason } => {
                CredentialError::verification_failed(format!("hashing failed: {}", reason))
            }
            PasswordError::VerificationFailed { reason } => {
                CredentialError::verification_failed(reason)
            }
            PasswordError::InvalidHash { reason } => {
                CredentialError::invalid_format("password_hash", reason)
            }
        }
    }
}
