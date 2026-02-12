use crate::core::error::AuthenticationError;

#[test]
fn test_user_not_found() {
    let err = AuthenticationError::user_not_found("username not in workspace");
    assert_eq!(
        err,
        AuthenticationError::UserNotFound {
            reason: "username not in workspace".to_string()
        }
    );
}

#[test]
fn test_user_not_found_display() {
    let err = AuthenticationError::user_not_found("invalid username");
    assert_eq!(err.to_string(), "User not found: invalid username");
}

#[test]
fn test_max_attempts_exceeded() {
    let err = AuthenticationError::max_attempts_exceeded(5);
    assert_eq!(err, AuthenticationError::MaxAttemptsExceeded { attempts: 5 });
}

#[test]
fn test_max_attempts_exceeded_display() {
    let err = AuthenticationError::max_attempts_exceeded(3);
    assert_eq!(
        err.to_string(),
        "Maximum authentication attempts exceeded: 3"
    );
}

#[test]
fn test_unsupported_auth_method() {
    let err = AuthenticationError::unsupported_auth_method("saml");
    assert_eq!(
        err,
        AuthenticationError::UnsupportedAuthMethod {
            method: "saml".to_string()
        }
    );
}

#[test]
fn test_unsupported_auth_method_display() {
    let err = AuthenticationError::unsupported_auth_method("oauth3");
    assert_eq!(
        err.to_string(),
        "Authentication method not supported: oauth3"
    );
}

#[test]
fn test_incomplete_flow() {
    let err = AuthenticationError::incomplete_flow("mfa_verification");
    assert_eq!(
        err,
        AuthenticationError::IncompleteFlow {
            stage: "mfa_verification".to_string()
        }
    );
}

#[test]
fn test_incomplete_flow_display() {
    let err = AuthenticationError::incomplete_flow("credential_check");
    assert_eq!(
        err.to_string(),
        "Authentication flow incomplete at stage: credential_check"
    );
}

#[test]
fn test_account_locked() {
    let err = AuthenticationError::account_locked("too many failed attempts");
    assert_eq!(
        err,
        AuthenticationError::AccountLocked {
            reason: "too many failed attempts".to_string()
        }
    );
}

#[test]
fn test_account_locked_display() {
    let err = AuthenticationError::account_locked("suspicious activity detected");
    assert_eq!(
        err.to_string(),
        "Account is locked: suspicious activity detected"
    );
}

#[test]
fn test_external_provider_rejected() {
    let err = AuthenticationError::external_provider_rejected("google", "invalid_scope");
    assert_eq!(
        err,
        AuthenticationError::ExternalProviderRejected {
            provider: "google".to_string(),
            reason: "invalid_scope".to_string()
        }
    );
}

#[test]
fn test_external_provider_rejected_display() {
    let err = AuthenticationError::external_provider_rejected("github", "code_expired");
    assert_eq!(
        err.to_string(),
        "External identity provider 'github' rejected authentication: code_expired"
    );
}

#[test]
fn test_authentication_error_equality() {
    let err1 = AuthenticationError::user_not_found("test");
    let err2 = AuthenticationError::user_not_found("test");
    assert_eq!(err1, err2);
}

#[test]
fn test_authentication_error_inequality() {
    let err1 = AuthenticationError::user_not_found("test1");
    let err2 = AuthenticationError::user_not_found("test2");
    assert_ne!(err1, err2);
}

#[test]
fn test_authentication_error_clone() {
    let err = AuthenticationError::user_not_found("test");
    let cloned = err.clone();
    assert_eq!(err, cloned);
}
