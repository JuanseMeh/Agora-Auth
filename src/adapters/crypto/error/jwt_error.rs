/// Errors specific to JWT token operations.

/*
This module defines errors specific to the JWT token adapter.

These errors represent failures in JWT token operations,
independent of business logic. They are NOT domain errors.

Design Principles:
 - **Isolation**: JWT errors never leak key material or token details upward
 - **Mapping**: All jsonwebtoken errors are caught and mapped to JwtError
 - **No panic**: All token operations return Results
 - **Deterministic**: Same input always produces same error type
*/

/// Error type for JWT token operations.
///
/// Variants are organized by concern:
/// - `Encoding`: Token encoding/signing failures
/// - `Decoding`: Token decoding/verification failures
/// - `InvalidToken`: Malformed or invalid token
/// - `InvalidKey`: Key format or content is invalid
/// - `Expired`: Token has expired
/// - `SignatureInvalid`: Signature verification failed
/// - `AlgorithmMismatch`: Algorithm does not match expected
#[derive(Debug, Clone)]
pub enum JwtError {
    /// Token encoding/signing failed
    Encoding {
        reason: String,
    },
    /// Token decoding/verification failed
    Decoding {
        reason: String,
    },
    /// Token is malformed or invalid
    InvalidToken {
        reason: String,
    },
    /// Key format or content is invalid
    InvalidKey {
        reason: String,
    },
    /// Token has expired
    Expired {
        reason: String,
    },
    /// Signature verification failed
    SignatureInvalid {
        reason: String,
    },
    /// Algorithm does not match expected
    AlgorithmMismatch {
        reason: String,
    },
}

impl JwtError {
    /// Create an encoding error
    pub fn encoding(reason: impl Into<String>) -> Self {
        Self::Encoding {
            reason: reason.into(),
        }
    }

    /// Create a decoding error
    pub fn decoding(reason: impl Into<String>) -> Self {
        Self::Decoding {
            reason: reason.into(),
        }
    }

    /// Create an invalid token error
    pub fn invalid_token(reason: impl Into<String>) -> Self {
        Self::InvalidToken {
            reason: reason.into(),
        }
    }

    /// Create an invalid key error
    pub fn invalid_key(reason: impl Into<String>) -> Self {
        Self::InvalidKey {
            reason: reason.into(),
        }
    }

    /// Create an expired token error
    pub fn expired(reason: impl Into<String>) -> Self {
        Self::Expired {
            reason: reason.into(),
        }
    }

    /// Create a signature invalid error
    pub fn signature_invalid(reason: impl Into<String>) -> Self {
        Self::SignatureInvalid {
            reason: reason.into(),
        }
    }

    /// Create an algorithm mismatch error
    pub fn algorithm_mismatch(reason: impl Into<String>) -> Self {
        Self::AlgorithmMismatch {
            reason: reason.into(),
        }
    }
}

impl std::fmt::Display for JwtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Encoding { reason } => write!(f, "Token encoding failed: {}", reason),
            Self::Decoding { reason } => write!(f, "Token decoding failed: {}", reason),
            Self::InvalidToken { reason } => write!(f, "Invalid token: {}", reason),
            Self::InvalidKey { reason } => write!(f, "Invalid key: {}", reason),
            Self::Expired { reason } => write!(f, "Token expired: {}", reason),
            Self::SignatureInvalid { reason } => write!(f, "Invalid signature: {}", reason),
            Self::AlgorithmMismatch { reason } => write!(f, "Algorithm mismatch: {}", reason),
        }
    }
}

impl std::error::Error for JwtError {}
