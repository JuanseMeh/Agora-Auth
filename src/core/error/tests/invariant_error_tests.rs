use crate::core::error::InvariantError;

#[test]
fn test_assertion_failed() {
    let err = InvariantError::assertion_failed("token_id.is_some()", "validate_token");
    assert_eq!(
        err,
        InvariantError::AssertionFailed {
            condition: "token_id.is_some()".to_string(),
            context: "validate_token".to_string()
        }
    );
}

#[test]
fn test_assertion_failed_display() {
    let err = InvariantError::assertion_failed("user != null", "authenticate_user");
    assert_eq!(
        err.to_string(),
        "Internal assertion failed: user != null (authenticate_user)"
    );
}

#[test]
fn test_dependency_unavailable() {
    let err = InvariantError::dependency_unavailable("clock", "system clock not accessible");
    assert_eq!(
        err,
        InvariantError::DependencyUnavailable {
            dependency: "clock".to_string(),
            reason: "system clock not accessible".to_string()
        }
    );
}

#[test]
fn test_dependency_unavailable_display() {
    let err = InvariantError::dependency_unavailable("crypto", "no randomness source");
    assert_eq!(
        err.to_string(),
        "Required dependency 'crypto' is unexpectedly unavailable: no randomness source"
    );
}

#[test]
fn test_inconsistent_state() {
    let err = InvariantError::inconsistent_state("token exp is before iat");
    assert_eq!(
        err,
        InvariantError::InconsistentState {
            description: "token exp is before iat".to_string()
        }
    );
}

#[test]
fn test_inconsistent_state_display() {
    let err = InvariantError::inconsistent_state("user_id mismatch between cache and db");
    assert_eq!(
        err.to_string(),
        "Internal state is inconsistent: user_id mismatch between cache and db"
    );
}

#[test]
fn test_invalid_configuration() {
    let err = InvariantError::invalid_configuration("missing jwt secret");
    assert_eq!(
        err,
        InvariantError::InvalidConfiguration {
            reason: "missing jwt secret".to_string()
        }
    );
}

#[test]
fn test_invalid_configuration_display() {
    let err = InvariantError::invalid_configuration("jwt expiry is negative");
    assert_eq!(
        err.to_string(),
        "Invalid configuration: jwt expiry is negative"
    );
}

#[test]
fn test_unreachable_code() {
    let err = InvariantError::unreachable_code("line 42");
    assert_eq!(
        err,
        InvariantError::UnreachableCode {
            location: "line 42".to_string()
        }
    );
}

#[test]
fn test_unreachable_code_display() {
    let err = InvariantError::unreachable_code("validate_token match branch");
    assert_eq!(
        err.to_string(),
        "Unreachable code was executed at: validate_token match branch"
    );
}

#[test]
fn test_invariant_error_equality() {
    let err1 = InvariantError::assertion_failed("test", "context");
    let err2 = InvariantError::assertion_failed("test", "context");
    assert_eq!(err1, err2);
}

#[test]
fn test_invariant_error_inequality() {
    let err1 = InvariantError::assertion_failed("test1", "context");
    let err2 = InvariantError::assertion_failed("test2", "context");
    assert_ne!(err1, err2);
}

#[test]
fn test_invariant_error_clone() {
    let err = InvariantError::dependency_unavailable("db", "connection lost");
    let cloned = err.clone();
    assert_eq!(err, cloned);
}

#[test]
fn test_different_invariant_types_are_unequal() {
    let err1 = InvariantError::assertion_failed("test", "ctx");
    let err2 = InvariantError::unreachable_code("test");
    assert_ne!(err1, err2);
}
