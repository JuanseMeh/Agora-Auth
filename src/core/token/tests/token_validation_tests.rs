use crate::core::token::TokenValidationFailure;
use crate::core::error::TokenError;

#[test]
fn token_validation_failure_malformed() {
    let failure = TokenValidationFailure::malformed("invalid format");
    assert!(failure.is_malformed());
    assert!(!failure.is_expired());
    assert!(!failure.is_not_yet_valid());
    assert!(!failure.is_signature_invalid());
}

#[test]
fn token_validation_failure_signature_invalid() {
    let failure = TokenValidationFailure::signature_invalid("verification failed");
    assert!(failure.is_signature_invalid());
    assert!(!failure.is_malformed());
}

#[test]
fn token_validation_failure_invalid_claims() {
    let failure = TokenValidationFailure::invalid_claims("missing required claim");
    assert!(failure.is_invalid_claims());
    assert!(!failure.is_expired());
}

#[test]
fn token_validation_failure_expired() {
    let failure = TokenValidationFailure::expired("2026-02-12T11:00:00Z");
    assert!(failure.is_expired());
    assert!(!failure.is_not_yet_valid());

    // Check the timestamp is preserved
    if let TokenValidationFailure::Expired { expired_at } = failure {
        assert_eq!(expired_at, "2026-02-12T11:00:00Z");
    } else {
        panic!("Expected Expired variant");
    }
}

#[test]
fn token_validation_failure_not_yet_valid() {
    let failure = TokenValidationFailure::not_yet_valid("2026-02-12T10:00:00Z");
    assert!(failure.is_not_yet_valid());
    assert!(!failure.is_expired());

    // Check the timestamp is preserved
    if let TokenValidationFailure::NotYetValid { valid_from } = failure {
        assert_eq!(valid_from, "2026-02-12T10:00:00Z");
    } else {
        panic!("Expected NotYetValid variant");
    }
}

#[test]
fn token_validation_failure_issuer_mismatch() {
    let failure = TokenValidationFailure::issuer_mismatch("example.com", "other.com");
    assert!(failure.is_issuer_mismatch());
    assert!(!failure.is_audience_mismatch());

    if let TokenValidationFailure::IssuerMismatch { actual, expected } = failure {
        assert_eq!(actual, "example.com");
        assert_eq!(expected, "other.com");
    } else {
        panic!("Expected IssuerMismatch variant");
    }
}

#[test]
fn token_validation_failure_audience_mismatch() {
    let failure = TokenValidationFailure::audience_mismatch("api1", "api2");
    assert!(failure.is_audience_mismatch());
    assert!(!failure.is_issuer_mismatch());

    if let TokenValidationFailure::AudienceMismatch { actual, expected } = failure {
        assert_eq!(actual, "api1");
        assert_eq!(expected, "api2");
    } else {
        panic!("Expected AudienceMismatch variant");
    }
}

#[test]
fn token_validation_failure_revoked() {
    let failure = TokenValidationFailure::revoked("2026-02-12T09:00:00Z");
    assert!(failure.is_revoked());
    assert!(!failure.is_expired());

    if let TokenValidationFailure::Revoked { revoked_at } = failure {
        assert_eq!(revoked_at, "2026-02-12T09:00:00Z");
    } else {
        panic!("Expected Revoked variant");
    }
}

#[test]
fn token_validation_failure_equality() {
    let f1 = TokenValidationFailure::malformed("test");
    let f2 = TokenValidationFailure::malformed("test");
    let f3 = TokenValidationFailure::malformed("different");

    assert_eq!(f1, f2);
    assert_ne!(f1, f3);
}

#[test]
fn token_validation_failure_clone() {
    let failure = TokenValidationFailure::expired("2026-02-12T11:00:00Z");
    let cloned = failure.clone();
    assert_eq!(failure, cloned);
}

#[test]
fn token_validation_failure_display() {
    let malformed = TokenValidationFailure::malformed("invalid utf8");
    assert!(format!("{}", malformed).contains("malformed"));

    let expired = TokenValidationFailure::expired("2026-02-12T11:00:00Z");
    assert!(format!("{}", expired).contains("expired"));

    let not_yet = TokenValidationFailure::not_yet_valid("2026-02-12T10:00:00Z");
    assert!(format!("{}", not_yet).contains("not valid"));

    let issuer = TokenValidationFailure::issuer_mismatch("actual.com", "expected.com");
    let display = format!("{}", issuer);
    assert!(display.contains("issuer"));
    assert!(display.contains("expected.com"));
    assert!(display.contains("actual.com"));

    let audience = TokenValidationFailure::audience_mismatch("aud1", "aud2");
    let display = format!("{}", audience);
    assert!(display.contains("audience"));
    assert!(display.contains("aud2"));
    assert!(display.contains("aud1"));

    let revoked = TokenValidationFailure::revoked("2026-02-12T09:00:00Z");
    assert!(format!("{}", revoked).contains("revoked"));
}

#[test]
fn token_validation_failure_to_token_error_malformed() {
    let failure = TokenValidationFailure::malformed("bad format");
    let error: TokenError = failure.into();

    match error {
        TokenError::Malformed { reason } => assert_eq!(reason, "bad format"),
        _ => panic!("Expected Malformed error"),
    }
}

#[test]
fn token_validation_failure_to_token_error_signature() {
    let failure = TokenValidationFailure::signature_invalid("bad sig");
    let error: TokenError = failure.into();

    match error {
        TokenError::SignatureInvalid { reason } => assert_eq!(reason, "bad sig"),
        _ => panic!("Expected SignatureInvalid error"),
    }
}

#[test]
fn token_validation_failure_to_token_error_expired() {
    let failure = TokenValidationFailure::expired("2026-02-12T11:00:00Z");
    let error: TokenError = failure.into();

    match error {
        TokenError::Expired { expired_at } => assert_eq!(expired_at, "2026-02-12T11:00:00Z"),
        _ => panic!("Expected Expired error"),
    }
}

#[test]
fn token_validation_failure_to_token_error_issuer_mismatch() {
    let failure = TokenValidationFailure::issuer_mismatch("actual", "expected");
    let error: TokenError = failure.into();

    match error {
        TokenError::IssuerMismatch { expected, actual } => {
            assert_eq!(expected, "expected");
            assert_eq!(actual, "actual");
        }
        _ => panic!("Expected IssuerMismatch error"),
    }
}

#[test]
fn token_validation_failure_to_token_error_revoked() {
    let failure = TokenValidationFailure::revoked("2026-02-11T00:00:00Z");
    let error: TokenError = failure.into();

    match error {
        TokenError::Revoked { revoked_at } => assert_eq!(revoked_at, "2026-02-11T00:00:00Z"),
        _ => panic!("Expected Revoked error"),
    }
}

#[test]
fn token_validation_failure_with_string_conversion() {
    // Test with different Into<String> types
    let failure1 = TokenValidationFailure::malformed("reason".to_string());
    let failure2 = TokenValidationFailure::malformed("reason");

    assert_eq!(failure1, failure2);
}

#[test]
fn token_validation_failure_all_variants_covered() {
    // Ensure we test all major failure categories
    let _malformed = TokenValidationFailure::malformed("test");
    let _signature_invalid = TokenValidationFailure::signature_invalid("test");
    let _invalid_claims = TokenValidationFailure::invalid_claims("test");
    let _expired = TokenValidationFailure::expired("test");
    let _not_yet_valid = TokenValidationFailure::not_yet_valid("test");
    let _issuer_mismatch = TokenValidationFailure::issuer_mismatch("a", "b");
    let _audience_mismatch = TokenValidationFailure::audience_mismatch("a", "b");
    let _revoked = TokenValidationFailure::revoked("test");

    // All variants compile and can be created
}
