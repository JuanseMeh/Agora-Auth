
//! Tests for LockoutPolicy.

use crate::core::usecases::policies::LockoutPolicy;

#[test]
fn lockout_policy_enforces_max_attempts() {
    let policy = LockoutPolicy::new(3, 3600, true);
    assert!(policy.is_locked(3));
    assert!(!policy.is_locked(2));
}

#[test]
fn lockout_policy_resets_on_success() {
    let policy = LockoutPolicy::new(5, 3600, true);
    assert!(policy.should_reset_on_success());
    let policy2 = LockoutPolicy::new(5, 3600, false);
    assert!(!policy2.should_reset_on_success());
}
