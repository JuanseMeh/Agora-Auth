/// Errors related to credential validity and format.

/*
 This error type answers the question: "Are the credentials valid and well-formed?"
 It covers failures where credentials themselves are invalid, malformed, or incompatible,
 independent of the authentication flow.
*/ 
 #[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialError {
    /// Credential is missing required fields
    MissingRequired {
        field: String,
    },
    /// Credential format is invalid or malformed
    InvalidFormat {
        credential_type: String,
        reason: String,
    },
    /// Credential has expired
    Expired {
        expired_at: String,
    },
    /// Credential is not yet valid (before activation date)
    NotYetValid {
        valid_from: String,
    },
    /// Credential does not match expected encoding or type
    TypeMismatch {
        expected: String,
        actual: String,
    },
    /// Credential hash or signature verification failed
    VerificationFailed {
        reason: String,
    },
    /// Credential is revoked or blacklisted
    Revoked {
        revoked_at: String,
    },
    /// Credential strength does not meet security requirements
    InsufficientStrength {
        reason: String,
    },
}

impl CredentialError {
    /// Create a MissingRequired error for the given field
    pub fn missing_required(field: impl Into<String>) -> Self {
        Self::MissingRequired {
            field: field.into(),
        }
    }

    /// Create an InvalidFormat error
    pub fn invalid_format(credential_type: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidFormat {
            credential_type: credential_type.into(),
            reason: reason.into(),
        }
    }

    /// Create an Expired error
    pub fn expired(expired_at: impl Into<String>) -> Self {
        Self::Expired {
            expired_at: expired_at.into(),
        }
    }

    /// Create a NotYetValid error
    pub fn not_yet_valid(valid_from: impl Into<String>) -> Self {
        Self::NotYetValid {
            valid_from: valid_from.into(),
        }
    }

    /// Create a TypeMismatch error
    pub fn type_mismatch(expected: impl Into<String>, actual: impl Into<String>) -> Self {
        Self::TypeMismatch {
            expected: expected.into(),
            actual: actual.into(),
        }
    }

    /// Create a VerificationFailed error
    pub fn verification_failed(reason: impl Into<String>) -> Self {
        Self::VerificationFailed {
            reason: reason.into(),
        }
    }

    /// Create a Revoked error
    pub fn revoked(revoked_at: impl Into<String>) -> Self {
        Self::Revoked {
            revoked_at: revoked_at.into(),
        }
    }

    /// Create an InsufficientStrength error
    pub fn insufficient_strength(reason: impl Into<String>) -> Self {
        Self::InsufficientStrength {
            reason: reason.into(),
        }
    }
}

impl std::fmt::Display for CredentialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingRequired { field } => write!(f, "Missing required field: {}", field),
            Self::InvalidFormat {
                credential_type,
                reason,
            } => write!(f, "Invalid {} format: {}", credential_type, reason),
            Self::Expired { expired_at } => write!(f, "Credential expired at: {}", expired_at),
            Self::NotYetValid { valid_from } => {
                write!(f, "Credential not valid until: {}", valid_from)
            }
            Self::TypeMismatch { expected, actual } => {
                write!(f, "Type mismatch: expected {}, got {}", expected, actual)
            }
            Self::VerificationFailed { reason } => {
                write!(f, "Credential verification failed: {}", reason)
            }
            Self::Revoked { revoked_at } => {
                write!(f, "Credential revoked at: {}", revoked_at)
            }
            Self::InsufficientStrength { reason } => {
                write!(f, "Credential strength insufficient: {}", reason)
            }
        }
    }
}
  
