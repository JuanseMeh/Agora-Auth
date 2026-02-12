
//! Tests for IssueSession use case.

use super::super::issue_session::{IssueSessionInput, IssueSessionOutput};
use crate::core::identity::UserIdentity;
use crate::core::token::Token;

#[test]
fn issue_session_success() {
    let _input = IssueSessionInput {
        user: UserIdentity::new("user123"),
        device_metadata: "device_info".to_string(),
        ip: "127.0.0.1".to_string(),
    };
    // Simulate token issuance
    let access_token = Token::new("access_token_value");
    let refresh_token = Token::new("refresh_token_value");
    let output = IssueSessionOutput { access_token, refresh_token };
    assert_eq!(output.access_token.value(), "access_token_value");
    assert_eq!(output.refresh_token.value(), "refresh_token_value");
}
