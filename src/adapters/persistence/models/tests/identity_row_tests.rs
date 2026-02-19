/// Tests for IdentityRow model.

use chrono::{Duration, Utc};

use crate::adapters::persistence::models::IdentityRow;

#[test]
fn identity_row_is_locked_when_locked_until_in_future() {
    let now = Utc::now();
    let future = now + Duration::hours(1);

    let row = IdentityRow {
        user_id: "user1".to_string(),
        identifier: "john@example.com".to_string(),
        password_hash: "hash".to_string(),
        failed_attempts: 3,
        locked_until: Some(future),
        password_changed_at: now,
        created_at: now,
        updated_at: now,
    };

    assert!(row.is_locked(now));
}

#[test]
fn identity_row_not_locked_when_locked_until_in_past() {
    let now = Utc::now();
    let past = now - Duration::hours(1);

    let row = IdentityRow {
        user_id: "user1".to_string(),
        identifier: "john@example.com".to_string(),
        password_hash: "hash".to_string(),
        failed_attempts: 0,
        locked_until: Some(past),
        password_changed_at: now,
        created_at: now,
        updated_at: now,
    };

    assert!(!row.is_locked(now));
}

#[test]
fn identity_row_not_locked_when_locked_until_is_none() {
    let now = Utc::now();

    let row = IdentityRow {
        user_id: "user1".to_string(),
        identifier: "john@example.com".to_string(),
        password_hash: "hash".to_string(),
        failed_attempts: 0,
        locked_until: None,
        password_changed_at: now,
        created_at: now,
        updated_at: now,
    };

    assert!(!row.is_locked(now));
}

#[test]
fn identity_row_lock_remaining_returns_duration_when_locked() {
    let now = Utc::now();
    let future = now + Duration::hours(2);

    let row = IdentityRow {
        user_id: "user1".to_string(),
        identifier: "john@example.com".to_string(),
        password_hash: "hash".to_string(),
        failed_attempts: 3,
        locked_until: Some(future),
        password_changed_at: now,
        created_at: now,
        updated_at: now,
    };

    let remaining = row.lock_remaining(now);
    assert!(remaining.is_some());

    let duration = remaining.unwrap();
    let expected_secs = (future - now).num_seconds() as u64;
    assert!(duration.as_secs() >= expected_secs - 1); // Account for execution time
}

#[test]
fn identity_row_lock_remaining_returns_none_when_not_locked() {
    let now = Utc::now();

    let row = IdentityRow {
        user_id: "user1".to_string(),
        identifier: "john@example.com".to_string(),
        password_hash: "hash".to_string(),
        failed_attempts: 0,
        locked_until: None,
        password_changed_at: now,
        created_at: now,
        updated_at: now,
    };

    let remaining = row.lock_remaining(now);
    assert!(remaining.is_none());
}

#[test]
fn identity_row_lock_remaining_returns_none_when_lock_expired() {
    let now = Utc::now();
    let past = now - Duration::hours(1);

    let row = IdentityRow {
        user_id: "user1".to_string(),
        identifier: "john@example.com".to_string(),
        password_hash: "hash".to_string(),
        failed_attempts: 0,
        locked_until: Some(past),
        password_changed_at: now,
        created_at: now,
        updated_at: now,
    };

    let remaining = row.lock_remaining(now);
    assert!(remaining.is_none());
}
