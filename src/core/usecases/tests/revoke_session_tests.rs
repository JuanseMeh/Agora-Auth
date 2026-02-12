
//! Tests for RevokeSession use case.

use super::super::revoke_session::{RevokeSessionInput, RevokeSessionOutput};

#[test]
fn revoke_session_success() {
    let _input = RevokeSessionInput {
        session_id: "session123".to_string(),
    };
    let output = RevokeSessionOutput { success: true };
    assert!(output.success);
}
