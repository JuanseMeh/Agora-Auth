/// Errors related to token validity and integrity.

/*
 This error type answers the question: "Is the trust artifact valid and intact?"
It covers failures where tokens themselves are invalid, malformed, tampered with,
or cannot be verified, independent of the underlying credentials.
*/
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenError {
    /// Token is malformed or corrupted
    Malformed {
        reason: String,
    },
    /// Token signature or HMAC verification failed
    SignatureInvalid {
        reason: String,
    },
    /// Token claims contain invalid or inconsistent data
    InvalidClaims {
        reason: String,
    },
    /// Token has expired
    Expired {
        expired_at: String,
    },
    /// Token is not yet valid (before issued-at or not-before time)
    NotYetValid {
        valid_from: String,
    },
    /// Token issuer does not match expected issuer
    IssuerMismatch {
        expected: String,
        actual: String,
    },
    /// Token audience does not match expected audience
    AudienceMismatch {
        expected: String,
        actual: String,
    },
    /// Token has been revoked or blacklisted
    Revoked {
        revoked_at: String,
    },
    /// Token algorithm is unsupported or invalid
    UnsupportedAlgorithm {
        algorithm: String,
    },
    /// Token key ID (kid) does not match any known key
    KeyIdNotFound {
        kid: String,
    },
}

impl TokenError {
    /// Create a Malformed error
    pub fn malformed(reason: impl Into<String>) -> Self {
        Self::Malformed {
            reason: reason.into(),
        }
    }

    /// Create a SignatureInvalid error
    pub fn signature_invalid(reason: impl Into<String>) -> Self {
        Self::SignatureInvalid {
            reason: reason.into(),
        }
    }

    /// Create an InvalidClaims error
    pub fn invalid_claims(reason: impl Into<String>) -> Self {
        Self::InvalidClaims {
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

    /// Create an IssuerMismatch error
    pub fn issuer_mismatch(expected: impl Into<String>, actual: impl Into<String>) -> Self {
        Self::IssuerMismatch {
            expected: expected.into(),
            actual: actual.into(),
        }
    }

    /// Create an AudienceMismatch error
    pub fn audience_mismatch(expected: impl Into<String>, actual: impl Into<String>) -> Self {
        Self::AudienceMismatch {
            expected: expected.into(),
            actual: actual.into(),
        }
    }

    /// Create a Revoked error
    pub fn revoked(revoked_at: impl Into<String>) -> Self {
        Self::Revoked {
            revoked_at: revoked_at.into(),
        }
    }

    /// Create an UnsupportedAlgorithm error
    pub fn unsupported_algorithm(algorithm: impl Into<String>) -> Self {
        Self::UnsupportedAlgorithm {
            algorithm: algorithm.into(),
        }
    }

    /// Create a KeyIdNotFound error
    pub fn key_id_not_found(kid: impl Into<String>) -> Self {
        Self::KeyIdNotFound {
            kid: kid.into(),
        }
    }
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed { reason } => write!(f, "Token is malformed: {}", reason),
            Self::SignatureInvalid { reason } => {
                write!(f, "Token signature verification failed: {}", reason)
            }
            Self::InvalidClaims { reason } => {
                write!(f, "Token contains invalid claims: {}", reason)
            }
            Self::Expired { expired_at } => write!(f, "Token expired at: {}", expired_at),
            Self::NotYetValid { valid_from } => {
                write!(f, "Token not valid until: {}", valid_from)
            }
            Self::IssuerMismatch { expected, actual } => {
                write!(f, "Token issuer mismatch: expected {}, got {}", expected, actual)
            }
            Self::AudienceMismatch { expected, actual } => {
                write!(
                    f,
                    "Token audience mismatch: expected {}, got {}",
                    expected, actual
                )
            }
            Self::Revoked { revoked_at } => {
                write!(f, "Token has been revoked at: {}", revoked_at)
            }
            Self::UnsupportedAlgorithm { algorithm } => {
                write!(f, "Token algorithm not supported: {}", algorithm)
            }
            Self::KeyIdNotFound { kid } => {
                write!(f, "Token key ID not found: {}", kid)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_malformed() {
        let err = TokenError::malformed("missing dot separators");
        assert_eq!(
            err,
            TokenError::Malformed {
                reason: "missing dot separators".to_string()
            }
        );
    }

    #[test]
    fn test_signature_invalid() {
        let err = TokenError::signature_invalid("hmac verification failed");
        assert_eq!(
            err,
            TokenError::SignatureInvalid {
                reason: "hmac verification failed".to_string()
            }
        );
    }

    #[test]
    fn test_display_expired() {
        let err = TokenError::expired("2025-01-01T00:00:00Z");
        assert_eq!(err.to_string(), "Token expired at: 2025-01-01T00:00:00Z");
    }

    #[test]
    fn test_issuer_mismatch() {
        let err = TokenError::issuer_mismatch("auth.example.com", "attacker.example.com");
        assert_eq!(
            err.to_string(),
            "Token issuer mismatch: expected auth.example.com, got attacker.example.com"
        );
    }
}
