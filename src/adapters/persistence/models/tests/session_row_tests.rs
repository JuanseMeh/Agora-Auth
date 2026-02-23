/// Tests for SessionRow model.

use chrono::{Duration, Utc};

use crate::adapters::persistence::models::SessionRow;

#[test]
fn session_row_is_active_when_not_revoked_and_not_expired() {
    let now = Utc::now();
    let future = now + Duration::hours(1);

    let row = SessionRow {
        id: "session1".to_string(),
        user_id: "user1".to_string(),
        refresh_token_hash: "hash".to_string(),
        created_at: now,
        expires_at: future,
        revoked_at: None,
        ip_address: "127.0.0.1".to_string(),
        user_agent: "Mozilla".to_string(),
        updated_at: now,
    };

    assert!(row.is_active(now));
}

#[test]
fn session_row_not_active_when_revoked() {
    let now = Utc::now();
    let future = now + Duration::hours(1);

    let row = SessionRow {
        id: "session1".to_string(),
        user_id: "user1".to_string(),
        refresh_token_hash: "hash".to_string(),
        created_at: now,
        expires_at: future,
        revoked_at: Some(now),
        ip_address: "127.0.0.1".to_string(),
        user_agent: "Mozilla".to_string(),
        updated_at: now,
    };

    assert!(!row.is_active(now));
}

#[test]
fn session_row_not_active_when_expired() {
    let now = Utc::now();
    let past = now - Duration::hours(1);

    let row = SessionRow {
        id: "session1".to_string(),
        user_id: "user1".to_string(),
        refresh_token_hash: "hash".to_string(),
        created_at: past,
        expires_at: past + Duration::minutes(30),
        revoked_at: None,
        ip_address: "127.0.0.1".to_string(),
        user_agent: "Mozilla".to_string(),
        updated_at: past,
    };

    assert!(!row.is_active(now));
}

#[test]
fn session_row_is_expired_when_past_expiration() {
    let now = Utc::now();
    let past = now - Duration::hours(1);

    let row = SessionRow {
        id: "session1".to_string(),
        user_id: "user1".to_string(),
        refresh_token_hash: "hash".to_string(),
        created_at: past - Duration::hours(2),
        expires_at: past,
        revoked_at: None,
        ip_address: "127.0.0.1".to_string(),
        user_agent: "Mozilla".to_string(),
        updated_at: past,
    };

    assert!(row.is_expired(now));
}

#[test]
fn session_row_not_expired_when_before_expiration() {
    let now = Utc::now();
    let future = now + Duration::hours(1);

    let row = SessionRow {
        id: "session1".to_string(),
        user_id: "user1".to_string(),
        refresh_token_hash: "hash".to_string(),
        created_at: now,
        expires_at: future,
        revoked_at: None,
        ip_address: "127.0.0.1".to_string(),
        user_agent: "Mozilla".to_string(),
        updated_at: now,
    };

    assert!(!row.is_expired(now));
}

#[test]
fn session_row_is_revoked_when_revoked_at_is_set() {
    let now = Utc::now();
    let future = now + Duration::hours(1);

    let row = SessionRow {
        id: "session1".to_string(),
        user_id: "user1".to_string(),
        refresh_token_hash: "hash".to_string(),
        created_at: now,
        expires_at: future,
        revoked_at: Some(now),
        ip_address: "127.0.0.1".to_string(),
        user_agent: "Mozilla".to_string(),
        updated_at: now,
    };

    assert!(row.is_revoked());
}

#[test]
fn session_row_not_revoked_when_revoked_at_is_none() {
    let now = Utc::now();
    let future = now + Duration::hours(1);

    let row = SessionRow {
        id: "session1".to_string(),
        user_id: "user1".to_string(),
        refresh_token_hash: "hash".to_string(),
        created_at: now,
        expires_at: future,
        revoked_at: None,
        ip_address: "127.0.0.1".to_string(),
        user_agent: "Mozilla".to_string(),
        updated_at: now,
    };

    assert!(!row.is_revoked());
}

#[test]
fn session_row_time_to_expiration_returns_duration_when_active() {
    let now = Utc::now();
    let future = now + Duration::hours(2);

    let row = SessionRow {
        id: "session1".to_string(),
        user_id: "user1".to_string(),
        refresh_token_hash: "hash".to_string(),
        created_at: now,
        expires_at: future,
        revoked_at: None,
        ip_address: "127.0.0.1".to_string(),
        user_agent: "Mozilla".to_string(),
        updated_at: now,
    };

    let remaining = row.time_to_expiration(now);
    assert!(remaining.is_some());

    let duration = remaining.unwrap();
    let expected_secs = (future - now).num_seconds() as u64;
    assert!(duration.as_secs() >= expected_secs - 1); // Account for execution time
}

#[test]
fn session_row_time_to_expiration_returns_none_when_expired() {
    let now = Utc::now();
    let past = now - Duration::hours(1);

    let row = SessionRow {
        id: "session1".to_string(),
        user_id: "user1".to_string(),
        refresh_token_hash: "hash".to_string(),
        created_at: past - Duration::hours(2),
        expires_at: past,
        revoked_at: None,
        ip_address: "127.0.0.1".to_string(),
        user_agent: "Mozilla".to_string(),
        updated_at: past,
    };

    let remaining = row.time_to_expiration(now);
    assert!(remaining.is_none());
}
