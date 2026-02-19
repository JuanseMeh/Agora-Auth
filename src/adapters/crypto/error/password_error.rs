/// Errors specific to password hashing operations.

/*
This module defines errors specific to the password hashing adapter.

These errors represent failures in cryptographic password operations,
independent of business logic. They are NOT domain errors.

Design Principles:
 - **Isolation**: Password errors never leak cryptographic details upward
 - **Mapping**: All argon2 errors are caught and mapped to PasswordError
 - **No panic**: All password operations return Results
 - **Deterministic**: Same input always produces same error type
*/

/// Error type for password hashing operations.
///
/// Variants are organized by concern:
/// - `Hashing`: Password hashing/verification failures
/// - `Verification`: Password verification failures
/// - `InvalidHash`: Invalid hash format or corrupted hash
#[derive(Debug, Clone)]
pub enum PasswordError {
    /// Password hashing failed
    Hashing {
        reason: String,
    },
    /// Password verification failed
    VerificationFailed {
        reason: String,
    },
    /// Invalid hash format or corrupted hash
    InvalidHash {
        reason: String,
    },
}

impl PasswordError {
    /// Create a hashing error
    pub fn hashing(reason: impl Into<String>) -> Self {
        Self::Hashing {
            reason: reason.into(),
        }
    }

    /// Create a verification failed error
    pub fn verification_failed(reason: impl Into<String>) -> Self {
        Self::VerificationFailed {
            reason: reason.into(),
        }
    }

    /// Create an invalid hash error
    pub fn invalid_hash(reason: impl Into<String>) -> Self {
        Self::InvalidHash {
            reason: reason.into(),
        }
    }
}

impl std::fmt::Display for PasswordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Hashing { reason } => write!(f, "Password hashing failed: {}", reason),
            Self::VerificationFailed { reason } => {
                write!(f, "Password verification failed: {}", reason)
            }
            Self::InvalidHash { reason } => write!(f, "Invalid hash format: {}", reason),
        }
    }
}

impl std::error::Error for PasswordError {}
