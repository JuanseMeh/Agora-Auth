/// Token validation semantics and outcomes.
///
/// `TokenValidationResult` describes the possible outcomes of token verification.
/// It separates the *detection* of validation failures (which happen in adapters)
/// from the *semantics* of validity (which are defined here in the core).
///
/// # Responsibility
///
/// Core defines:
/// - Valid
/// - Expired
/// - Malformed
/// - Signature invalid
/// - Audience mismatch
/// - Issuer mismatch
/// - Revoked
///
/// Adapters implement:
/// - How to detect each condition (signature checking, key resolution, revocation lookup)
/// - Which conditions are fatal vs. recoverable
/// - How to translate errors to HTTP responses
///
/// # Design Principles
///
/// - **Outcome-focused**: Describes "what happened" not "what to do about it"
/// - **No crypto**: No cryptographic operations or key material
/// - **No transport**: No HTTP status codes or header manipulation
/// - **Immutable**: Validation results are immutable value objects
/// - **Deterministic**: Given the same inputs, always produces the same result

use crate::core::error::TokenError;

/// The result of token validation.
///
/// This type encapsulates the outcome of verifying a token. Successful validation
/// is represented by `Valid`; various failure modes are represented by the error variant.
pub type TokenValidationResult = Result<(), TokenValidationFailure>;

/// Categories of token validation failures.
///
/// Each variant represents a distinct semantic category of failure, independent
/// of how the failure was detected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenValidationFailure {
    /// The token is malformed or corrupted and cannot be parsed or decoded.
    Malformed(String),

    /// The token signature or HMAC verification failed.
    SignatureInvalid(String),

    /// The token claims contain invalid or inconsistent data.
    InvalidClaims(String),

    /// The token has expired based on its expiration time.
    Expired {
        /// RFC3339 timestamp of when the token expired
        expired_at: String,
    },

    /// The token is not yet valid (before its issued-at or not-before time).
    NotYetValid {
        /// RFC3339 timestamp from which the token becomes valid
        valid_from: String,
    },

    /// The token issuer does not match the expected issuer.
    IssuerMismatch {
        /// The issuer the token claims
        actual: String,
        /// The issuer that was expected
        expected: String,
    },

    /// The token audience does not match the expected audience.
    AudienceMismatch {
        /// The audience the token claims
        actual: String,
        /// The audience that was expected
        expected: String,
    },

    /// The token has been revoked or blacklisted.
    Revoked {
        /// RFC3339 timestamp of when the token was revoked
        revoked_at: String,
    },
}

impl TokenValidationFailure {
    /// Create a `Malformed` failure.
    pub fn malformed(reason: impl Into<String>) -> Self {
        Self::Malformed(reason.into())
    }

    /// Create a `SignatureInvalid` failure.
    pub fn signature_invalid(reason: impl Into<String>) -> Self {
        Self::SignatureInvalid(reason.into())
    }

    /// Create an `InvalidClaims` failure.
    pub fn invalid_claims(reason: impl Into<String>) -> Self {
        Self::InvalidClaims(reason.into())
    }

    /// Create an `Expired` failure.
    pub fn expired(expired_at: impl Into<String>) -> Self {
        Self::Expired {
            expired_at: expired_at.into(),
        }
    }

    /// Create a `NotYetValid` failure.
    pub fn not_yet_valid(valid_from: impl Into<String>) -> Self {
        Self::NotYetValid {
            valid_from: valid_from.into(),
        }
    }

    /// Create an `IssuerMismatch` failure.
    pub fn issuer_mismatch(actual: impl Into<String>, expected: impl Into<String>) -> Self {
        Self::IssuerMismatch {
            actual: actual.into(),
            expected: expected.into(),
        }
    }

    /// Create an `AudienceMismatch` failure.
    pub fn audience_mismatch(actual: impl Into<String>, expected: impl Into<String>) -> Self {
        Self::AudienceMismatch {
            actual: actual.into(),
            expected: expected.into(),
        }
    }

    /// Create a `Revoked` failure.
    pub fn revoked(revoked_at: impl Into<String>) -> Self {
        Self::Revoked {
            revoked_at: revoked_at.into(),
        }
    }

    /// Check if this failure is due to expiration.
    pub fn is_expired(&self) -> bool {
        matches!(self, Self::Expired { .. })
    }

    /// Check if this failure is due to the token not yet being valid.
    pub fn is_not_yet_valid(&self) -> bool {
        matches!(self, Self::NotYetValid { .. })
    }

    /// Check if this failure is due to signature invalidity.
    pub fn is_signature_invalid(&self) -> bool {
        matches!(self, Self::SignatureInvalid(_))
    }

    /// Check if this failure is due to the token being malformed.
    pub fn is_malformed(&self) -> bool {
        matches!(self, Self::Malformed(_))
    }

    /// Check if this failure is due to claims being invalid.
    pub fn is_invalid_claims(&self) -> bool {
        matches!(self, Self::InvalidClaims(_))
    }

    /// Check if this failure is due to an issuer mismatch.
    pub fn is_issuer_mismatch(&self) -> bool {
        matches!(self, Self::IssuerMismatch { .. })
    }

    /// Check if this failure is due to an audience mismatch.
    pub fn is_audience_mismatch(&self) -> bool {
        matches!(self, Self::AudienceMismatch { .. })
    }

    /// Check if this failure is due to the token being revoked.
    pub fn is_revoked(&self) -> bool {
        matches!(self, Self::Revoked { .. })
    }
}

impl From<TokenValidationFailure> for TokenError {
    fn from(failure: TokenValidationFailure) -> Self {
        match failure {
            TokenValidationFailure::Malformed(reason) => TokenError::malformed(reason),
            TokenValidationFailure::SignatureInvalid(reason) => TokenError::signature_invalid(reason),
            TokenValidationFailure::InvalidClaims(reason) => TokenError::invalid_claims(reason),
            TokenValidationFailure::Expired { expired_at } => TokenError::expired(expired_at),
            TokenValidationFailure::NotYetValid { valid_from } => TokenError::not_yet_valid(valid_from),
            TokenValidationFailure::IssuerMismatch { actual, expected } => {
                TokenError::issuer_mismatch(expected, actual)
            }
            TokenValidationFailure::AudienceMismatch { actual, expected } => {
                TokenError::audience_mismatch(expected, actual)
            }
            TokenValidationFailure::Revoked { revoked_at } => TokenError::revoked(revoked_at),
        }
    }
}

impl std::fmt::Display for TokenValidationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(reason) => write!(f, "Token is malformed: {}", reason),
            Self::SignatureInvalid(reason) => write!(f, "Token signature is invalid: {}", reason),
            Self::InvalidClaims(reason) => write!(f, "Token claims are invalid: {}", reason),
            Self::Expired { expired_at } => write!(f, "Token expired at {}", expired_at),
            Self::NotYetValid { valid_from } => write!(f, "Token not valid until {}", valid_from),
            Self::IssuerMismatch { actual, expected } => {
                write!(f, "Token issuer mismatch: expected '{}' but got '{}'", expected, actual)
            }
            Self::AudienceMismatch { actual, expected } => {
                write!(f, "Token audience mismatch: expected '{}' but got '{}'", expected, actual)
            }
            Self::Revoked { revoked_at } => write!(f, "Token was revoked at {}", revoked_at),
        }
    }
}
