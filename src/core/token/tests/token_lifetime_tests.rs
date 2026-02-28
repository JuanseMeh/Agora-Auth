use crate::core::token::TokenLifetime;

#[test]
fn token_lifetime_new() {
    let lifetime = TokenLifetime::new("2026-02-12T10:00:00Z", "2026-02-12T11:00:00Z");
    assert_eq!(lifetime.issued_at, "2026-02-12T10:00:00Z");
    assert_eq!(lifetime.expires_at, "2026-02-12T11:00:00Z");
    assert!(lifetime.not_before.is_none());
}

#[test]
fn token_lifetime_with_not_before() {
    let lifetime = TokenLifetime::new("2026-02-12T10:00:00Z", "2026-02-12T11:00:00Z")
        .with_not_before("2026-02-12T10:30:00Z");

    assert_eq!(lifetime.not_before, Some("2026-02-12T10:30:00Z".to_string()));
}

#[test]
fn token_lifetime_is_expired_true() {
    let lifetime = TokenLifetime::new("2026-02-12T10:00:00Z", "2026-02-12T11:00:00Z");

    // Exactly at expiration
    assert!(lifetime.is_expired("2026-02-12T11:00:00Z"));

    // After expiration
    assert!(lifetime.is_expired("2026-02-12T12:00:00Z"));
    assert!(lifetime.is_expired("2026-02-13T00:00:00Z"));
}

#[test]
fn token_lifetime_is_expired_false() {
    let lifetime = TokenLifetime::new("2026-02-12T10:00:00Z", "2026-02-12T11:00:00Z");

    // Before expiration
    assert!(!lifetime.is_expired("2026-02-12T10:00:00Z"));
    assert!(!lifetime.is_expired("2026-02-12T10:30:00Z"));
    assert!(!lifetime.is_expired("2026-02-12T10:59:59Z"));
}

#[test]
fn token_lifetime_is_not_yet_valid_before_issued_at() {
    let lifetime = TokenLifetime::new("2026-02-12T10:00:00Z", "2026-02-12T11:00:00Z");

    // Before issued_at
    assert!(lifetime.is_not_yet_valid("2026-02-12T09:59:59Z"));
    assert!(lifetime.is_not_yet_valid("2026-02-11T10:00:00Z"));
}

#[test]
fn token_lifetime_is_not_yet_valid_not_before() {
    let lifetime = TokenLifetime::new("2026-02-12T10:00:00Z", "2026-02-12T11:00:00Z")
        .with_not_before("2026-02-12T10:30:00Z");

    // Before not_before
    assert!(lifetime.is_not_yet_valid("2026-02-12T10:00:00Z"));
    assert!(lifetime.is_not_yet_valid("2026-02-12T10:15:00Z"));
    assert!(lifetime.is_not_yet_valid("2026-02-12T10:29:59Z"));

    // At or after not_before
    assert!(!lifetime.is_not_yet_valid("2026-02-12T10:30:00Z"));
    assert!(!lifetime.is_not_yet_valid("2026-02-12T10:45:00Z"));
}

#[test]
fn token_lifetime_is_not_yet_valid_false() {
    let lifetime = TokenLifetime::new("2026-02-12T10:00:00Z", "2026-02-12T11:00:00Z");

    // At issued_at
    assert!(!lifetime.is_not_yet_valid("2026-02-12T10:00:00Z"));

    // After issued_at
    assert!(!lifetime.is_not_yet_valid("2026-02-12T10:30:00Z"));
}

#[test]
fn token_lifetime_is_temporally_valid() {
    let lifetime = TokenLifetime::new("2026-02-12T10:00:00Z", "2026-02-12T11:00:00Z");

    // Valid window
    assert!(lifetime.is_temporally_valid("2026-02-12T10:00:00Z"));
    assert!(lifetime.is_temporally_valid("2026-02-12T10:30:00Z"));
    assert!(lifetime.is_temporally_valid("2026-02-12T10:59:59Z"));

    // Before issued_at (not yet valid)
    assert!(!lifetime.is_temporally_valid("2026-02-12T09:59:59Z"));

    // At or after expiration (expired)
    assert!(!lifetime.is_temporally_valid("2026-02-12T11:00:00Z"));
    assert!(!lifetime.is_temporally_valid("2026-02-12T12:00:00Z"));
}

#[test]
fn token_lifetime_is_temporally_valid_with_not_before() {
    let lifetime = TokenLifetime::new("2026-02-12T10:00:00Z", "2026-02-12T11:00:00Z")
        .with_not_before("2026-02-12T10:30:00Z");

    // Before not_before (not yet valid)
    assert!(!lifetime.is_temporally_valid("2026-02-12T10:00:00Z"));
    assert!(!lifetime.is_temporally_valid("2026-02-12T10:15:00Z"));

    // Between not_before and expires_at (valid)
    assert!(lifetime.is_temporally_valid("2026-02-12T10:30:00Z"));
    assert!(lifetime.is_temporally_valid("2026-02-12T10:45:00Z"));

    // At or after expires_at (expired)
    assert!(!lifetime.is_temporally_valid("2026-02-12T11:00:00Z"));
}

#[test]
fn token_lifetime_valid_from() {
    let lifetime_without_nb =
        TokenLifetime::new("2026-02-12T10:00:00Z", "2026-02-12T11:00:00Z");
    assert_eq!(lifetime_without_nb.valid_from(), "2026-02-12T10:00:00Z");

    let lifetime_with_nb = TokenLifetime::new("2026-02-12T10:00:00Z", "2026-02-12T11:00:00Z")
        .with_not_before("2026-02-12T10:30:00Z");
    assert_eq!(lifetime_with_nb.valid_from(), "2026-02-12T10:30:00Z");
}

#[test]
fn token_lifetime_valid_until() {
    let lifetime = TokenLifetime::new("2026-02-12T10:00:00Z", "2026-02-12T11:00:00Z");
    assert_eq!(lifetime.valid_until(), "2026-02-12T11:00:00Z");
}

#[test]
fn token_lifetime_equality() {
    let lifetime1 = TokenLifetime::new("2026-02-12T10:00:00Z", "2026-02-12T11:00:00Z");
    let lifetime2 = TokenLifetime::new("2026-02-12T10:00:00Z", "2026-02-12T11:00:00Z");

    assert_eq!(lifetime1, lifetime2);
}

#[test]
fn token_lifetime_clone() {
    let lifetime1 = TokenLifetime::new("2026-02-12T10:00:00Z", "2026-02-12T11:00:00Z")
        .with_not_before("2026-02-12T10:30:00Z");

    let lifetime2 = lifetime1.clone();

    assert_eq!(lifetime1, lifetime2);
}

#[test]
fn token_lifetime_edge_case_same_issued_expires() {
    // Edge case: issued and expires at the same instant
    let lifetime = TokenLifetime::new("2026-02-12T10:00:00Z", "2026-02-12T10:00:00Z");

    // Exactly at the time: should be expired
    assert!(lifetime.is_expired("2026-02-12T10:00:00Z"));

    // Before: should not be expired but not yet valid
    assert!(!lifetime.is_expired("2026-02-12T09:59:59Z"));
    assert!(lifetime.is_not_yet_valid("2026-02-12T09:59:59Z"));
}

#[test]
fn token_lifetime_rfc3339_string_comparison() {
    // Verify RFC3339 timestamps are compared correctly as strings
    let lifetime = TokenLifetime::new("2026-02-12T10:00:00Z", "2026-02-12T11:00:00Z");

    // These timestamps should compare lexicographically as expected
    assert!(!lifetime.is_expired("2026-02-12T10:59:59Z"));
    assert!(lifetime.is_expired("2026-02-12T11:00:00Z"));
    assert!(lifetime.is_expired("2026-02-12T11:00:01Z"));
}
