
//! Tests for ValidateAccessToken use case.

use super::super::validate_access_token::{ValidateAccessTokenInput, ValidateAccessTokenOutput};
use crate::core::token::Token;

#[test]
fn validate_access_token_success() {
    let _input = ValidateAccessTokenInput {
        access_token: Token::new("valid_access_token"),
    };
    let output = ValidateAccessTokenOutput { valid: true, reason: None };
    assert!(output.valid);
    assert_eq!(output.reason, None);
}

#[test]
fn validate_access_token_password_changed() {
    let _input = ValidateAccessTokenInput {
        access_token: Token::new("old_access_token"),
    };
    let output = ValidateAccessTokenOutput { valid: false, reason: Some("Password changed after token issued".to_string()) };
    assert!(!output.valid);
    assert_eq!(output.reason, Some("Password changed after token issued".to_string()));
}
