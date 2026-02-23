
//! Tests for TokenPolicy.

use crate::core::usecases::policies::TokenPolicy;

#[test]
fn token_policy_access_ttl() {
    let policy = TokenPolicy::new(3600, 7200, false);
    assert_eq!(policy.access_ttl(), 3600);
}

#[test]
fn token_policy_refresh_ttl() {
    let policy = TokenPolicy::new(3600, 7200, false);
    assert_eq!(policy.refresh_ttl(), 7200);
}
