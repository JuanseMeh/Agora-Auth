use crate::core::error::CredentialError;

#[test]
fn test_missing_required() {
    let err = CredentialError::missing_required("password");
    assert_eq!(
        err,
        CredentialError::MissingRequired {
            field: "password".to_string()
        }
    );
}

#[test]
fn test_missing_required_display() {
    let err = CredentialError::missing_required("username");
    assert_eq!(err.to_string(), "Missing required field: username");
}

#[test]
fn test_invalid_format() {
    let err = CredentialError::invalid_format("email", "not a valid email format");
    assert_eq!(
        err,
        CredentialError::InvalidFormat {
            credential_type: "email".to_string(),
            reason: "not a valid email format".to_string()
        }
    );
}

#[test]
fn test_invalid_format_display() {
    let err = CredentialError::invalid_format("api_key", "missing prefix");
    assert_eq!(err.to_string(), "Invalid api_key format: missing prefix");
}

#[test]
fn test_expired() {
    let err = CredentialError::expired("2025-01-01T00:00:00Z");
    assert_eq!(
        err,
        CredentialError::Expired {
            expired_at: "2025-01-01T00:00:00Z".to_string()
        }
    );
}

#[test]
fn test_expired_display() {
    let err = CredentialError::expired("2025-12-31T23:59:59Z");
    assert_eq!(
        err.to_string(),
        "Credential expired at: 2025-12-31T23:59:59Z"
    );
}

#[test]
fn test_not_yet_valid() {
    let err = CredentialError::not_yet_valid("2026-03-01T00:00:00Z");
    assert_eq!(
        err,
        CredentialError::NotYetValid {
            valid_from: "2026-03-01T00:00:00Z".to_string()
        }
    );
}

#[test]
fn test_not_yet_valid_display() {
    let err = CredentialError::not_yet_valid("2026-06-15T12:00:00Z");
    assert_eq!(
        err.to_string(),
        "Credential not valid until: 2026-06-15T12:00:00Z"
    );
}

#[test]
fn test_type_mismatch() {
    let err = CredentialError::type_mismatch("bcrypt_hash", "plain_text");
    assert_eq!(
        err,
        CredentialError::TypeMismatch {
            expected: "bcrypt_hash".to_string(),
            actual: "plain_text".to_string()
        }
    );
}

#[test]
fn test_type_mismatch_display() {
    let err = CredentialError::type_mismatch("jwt", "opaque_token");
    assert_eq!(
        err.to_string(),
        "Type mismatch: expected jwt, got opaque_token"
    );
}

#[test]
fn test_verification_failed() {
    let err = CredentialError::verification_failed("hmac mismatch");
    assert_eq!(
        err,
        CredentialError::VerificationFailed {
            reason: "hmac mismatch".to_string()
        }
    );
}

#[test]
fn test_verification_failed_display() {
    let err = CredentialError::verification_failed("signature invalid");
    assert_eq!(
        err.to_string(),
        "Credential verification failed: signature invalid"
    );
}

#[test]
fn test_revoked() {
    let err = CredentialError::revoked("2026-01-15T10:30:00Z");
    assert_eq!(
        err,
        CredentialError::Revoked {
            revoked_at: "2026-01-15T10:30:00Z".to_string()
        }
    );
}

#[test]
fn test_revoked_display() {
    let err = CredentialError::revoked("2026-02-08T14:20:00Z");
    assert_eq!(
        err.to_string(),
        "Credential revoked at: 2026-02-08T14:20:00Z"
    );
}

#[test]
fn test_insufficient_strength() {
    let err = CredentialError::insufficient_strength("password too short");
    assert_eq!(
        err,
        CredentialError::InsufficientStrength {
            reason: "password too short".to_string()
        }
    );
}

#[test]
fn test_insufficient_strength_display() {
    let err = CredentialError::insufficient_strength("lacks uppercase letters");
    assert_eq!(
        err.to_string(),
        "Credential strength insufficient: lacks uppercase letters"
    );
}

#[test]
fn test_credential_error_equality() {
    let err1 = CredentialError::missing_required("password");
    let err2 = CredentialError::missing_required("password");
    assert_eq!(err1, err2);
}

#[test]
fn test_credential_error_inequality() {
    let err1 = CredentialError::missing_required("password");
    let err2 = CredentialError::missing_required("username");
    assert_ne!(err1, err2);
}

#[test]
fn test_credential_error_clone() {
    let err = CredentialError::invalid_format("email", "no @");
    let cloned = err.clone();
    assert_eq!(err, cloned);
}
