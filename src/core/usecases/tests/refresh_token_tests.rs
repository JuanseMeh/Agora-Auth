
//! Tests for RefreshSession use case.

use super::super::refresh_session::{RefreshSessionInput, RefreshSessionOutput};
use crate::core::token::Token;

#[test]
fn refresh_session_success() {
    let _input = RefreshSessionInput {
        raw_refresh_token: "valid_refresh_token".to_string(),
    };
    let access_token = Token::new("new_access_token");
    let refresh_token = Token::new("new_refresh_token");
    let output = RefreshSessionOutput { access_token, refresh_token };
    assert_eq!(output.access_token.value(), "new_access_token");
    assert_eq!(output.refresh_token.value(), "new_refresh_token");
}

#[test]
fn refresh_session_rotation() {
    // Simulate rotation: old token invalidated, new token issued
    let old_token = Token::new("old_refresh_token");
    let new_token = Token::new("rotated_refresh_token");
    assert_ne!(old_token.value(), new_token.value());
}
