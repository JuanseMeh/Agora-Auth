use crate::core::error::TokenError;

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
fn test_malformed_display() {
    let err = TokenError::malformed("invalid base64 encoding");
    assert_eq!(
        err.to_string(),
        "Token is malformed: invalid base64 encoding"
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
fn test_signature_invalid_display() {
    let err = TokenError::signature_invalid("key mismatch");
    assert_eq!(
        err.to_string(),
        "Token signature verification failed: key mismatch"
    );
}

#[test]
fn test_invalid_claims() {
    let err = TokenError::invalid_claims("sub and aud are inconsistent");
    assert_eq!(
        err,
        TokenError::InvalidClaims {
            reason: "sub and aud are inconsistent".to_string()
        }
    );
}

#[test]
fn test_invalid_claims_display() {
    let err = TokenError::invalid_claims("iat is in the future");
    assert_eq!(
        err.to_string(),
        "Token contains invalid claims: iat is in the future"
    );
}

#[test]
fn test_expired() {
    let err = TokenError::expired("2025-01-01T00:00:00Z");
    assert_eq!(
        err,
        TokenError::Expired {
            expired_at: "2025-01-01T00:00:00Z".to_string()
        }
    );
}

#[test]
fn test_expired_display() {
    let err = TokenError::expired("2025-12-31T23:59:59Z");
    assert_eq!(err.to_string(), "Token expired at: 2025-12-31T23:59:59Z");
}

#[test]
fn test_not_yet_valid() {
    let err = TokenError::not_yet_valid("2026-03-01T00:00:00Z");
    assert_eq!(
        err,
        TokenError::NotYetValid {
            valid_from: "2026-03-01T00:00:00Z".to_string()
        }
    );
}

#[test]
fn test_not_yet_valid_display() {
    let err = TokenError::not_yet_valid("2026-06-15T12:00:00Z");
    assert_eq!(
        err.to_string(),
        "Token not valid until: 2026-06-15T12:00:00Z"
    );
}

#[test]
fn test_issuer_mismatch() {
    let err = TokenError::issuer_mismatch("auth.example.com", "attacker.example.com");
    assert_eq!(
        err,
        TokenError::IssuerMismatch {
            expected: "auth.example.com".to_string(),
            actual: "attacker.example.com".to_string()
        }
    );
}

#[test]
fn test_issuer_mismatch_display() {
    let err = TokenError::issuer_mismatch("auth.example.com", "attacker.example.com");
    assert_eq!(
        err.to_string(),
        "Token issuer mismatch: expected auth.example.com, got attacker.example.com"
    );
}

#[test]
fn test_audience_mismatch() {
    let err = TokenError::audience_mismatch("api.example.com", "web.example.com");
    assert_eq!(
        err,
        TokenError::AudienceMismatch {
            expected: "api.example.com".to_string(),
            actual: "web.example.com".to_string()
        }
    );
}

#[test]
fn test_audience_mismatch_display() {
    let err = TokenError::audience_mismatch("api.example.com", "web.example.com");
    assert_eq!(
        err.to_string(),
        "Token audience mismatch: expected api.example.com, got web.example.com"
    );
}

#[test]
fn test_revoked() {
    let err = TokenError::revoked("2026-01-15T10:30:00Z");
    assert_eq!(
        err,
        TokenError::Revoked {
            revoked_at: "2026-01-15T10:30:00Z".to_string()
        }
    );
}

#[test]
fn test_revoked_display() {
    let err = TokenError::revoked("2026-02-08T14:20:00Z");
    assert_eq!(
        err.to_string(),
        "Token has been revoked at: 2026-02-08T14:20:00Z"
    );
}

#[test]
fn test_unsupported_algorithm() {
    let err = TokenError::unsupported_algorithm("HS128");
    assert_eq!(
        err,
        TokenError::UnsupportedAlgorithm {
            algorithm: "HS128".to_string()
        }
    );
}

#[test]
fn test_unsupported_algorithm_display() {
    let err = TokenError::unsupported_algorithm("CUSTOM_ALG");
    assert_eq!(
        err.to_string(),
        "Token algorithm not supported: CUSTOM_ALG"
    );
}

#[test]
fn test_key_id_not_found() {
    let err = TokenError::key_id_not_found("key-2024-01");
    assert_eq!(
        err,
        TokenError::KeyIdNotFound {
            kid: "key-2024-01".to_string()
        }
    );
}

#[test]
fn test_key_id_not_found_display() {
    let err = TokenError::key_id_not_found("unknown-key-id");
    assert_eq!(err.to_string(), "Token key ID not found: unknown-key-id");
}

#[test]
fn test_token_error_equality() {
    let err1 = TokenError::malformed("test");
    let err2 = TokenError::malformed("test");
    assert_eq!(err1, err2);
}

#[test]
fn test_token_error_inequality() {
    let err1 = TokenError::malformed("test1");
    let err2 = TokenError::malformed("test2");
    assert_ne!(err1, err2);
}

#[test]
fn test_token_error_clone() {
    let err = TokenError::signature_invalid("hmac fail");
    let cloned = err.clone();
    assert_eq!(err, cloned);
}
