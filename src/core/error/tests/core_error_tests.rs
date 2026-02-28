use crate::core::error::{
    AuthenticationError, CredentialError, CoreError, InvariantError, TokenError,
};

#[test]
fn test_core_error_from_authentication() {
    let auth_err = AuthenticationError::user_not_found("test");
    let core_err: CoreError = auth_err.into();
    assert!(core_err.is_authentication());
    assert!(!core_err.is_credential());
    assert!(!core_err.is_token());
    assert!(!core_err.is_invariant());
}

#[test]
fn test_core_error_from_credential() {
    let cred_err = CredentialError::missing_required("password");
    let core_err: CoreError = cred_err.into();
    assert!(!core_err.is_authentication());
    assert!(core_err.is_credential());
    assert!(!core_err.is_token());
    assert!(!core_err.is_invariant());
}

#[test]
fn test_core_error_from_token() {
    let token_err = TokenError::malformed("test");
    let core_err: CoreError = token_err.into();
    assert!(!core_err.is_authentication());
    assert!(!core_err.is_credential());
    assert!(core_err.is_token());
    assert!(!core_err.is_invariant());
}

#[test]
fn test_core_error_from_invariant() {
    let inv_err = InvariantError::unreachable_code("line 42");
    let core_err: CoreError = inv_err.into();
    assert!(!core_err.is_authentication());
    assert!(!core_err.is_credential());
    assert!(!core_err.is_token());
    assert!(core_err.is_invariant());
}

#[test]
fn test_as_authentication() {
    let auth_err = AuthenticationError::user_not_found("test");
    let core_err: CoreError = auth_err.clone().into();
    assert_eq!(core_err.as_authentication(), Some(&auth_err));
}

#[test]
fn test_as_credential() {
    let cred_err = CredentialError::missing_required("test");
    let core_err: CoreError = cred_err.clone().into();
    assert_eq!(core_err.as_credential(), Some(&cred_err));
}

#[test]
fn test_as_token() {
    let token_err = TokenError::malformed("test");
    let core_err: CoreError = token_err.clone().into();
    assert_eq!(core_err.as_token(), Some(&token_err));
}

#[test]
fn test_as_invariant() {
    let inv_err = InvariantError::unreachable_code("test");
    let core_err: CoreError = inv_err.clone().into();
    assert_eq!(core_err.as_invariant(), Some(&inv_err));
}

#[test]
fn test_as_wrong_type_returns_none() {
    let auth_err = AuthenticationError::user_not_found("test");
    let core_err: CoreError = auth_err.into();
    assert!(core_err.as_credential().is_none());
    assert!(core_err.as_token().is_none());
    assert!(core_err.as_invariant().is_none());
}

#[test]
fn test_display_authentication_error() {
    let auth_err = AuthenticationError::user_not_found("test");
    let core_err: CoreError = auth_err.into();
    assert!(core_err.to_string().contains("Authentication error"));
}

#[test]
fn test_display_credential_error() {
    let cred_err = CredentialError::missing_required("password");
    let core_err: CoreError = cred_err.into();
    assert!(core_err.to_string().contains("Credential error"));
}

#[test]
fn test_display_token_error() {
    let token_err = TokenError::malformed("test");
    let core_err: CoreError = token_err.into();
    assert!(core_err.to_string().contains("Token error"));
}

#[test]
fn test_display_invariant_error() {
    let inv_err = InvariantError::unreachable_code("test");
    let core_err: CoreError = inv_err.into();
    assert!(core_err.to_string().contains("Invariant error"));
}

#[test]
fn test_core_error_debug() {
    let auth_err = AuthenticationError::user_not_found("test");
    let core_err: CoreError = auth_err.into();
    let debug_str = format!("{:?}", core_err);
    assert!(debug_str.contains("Authentication"));
}

#[test]
fn test_core_error_clone() {
    let auth_err = AuthenticationError::user_not_found("test");
    let core_err: CoreError = auth_err.into();
    let cloned = core_err.clone();
    assert_eq!(core_err.to_string(), cloned.to_string());
}
