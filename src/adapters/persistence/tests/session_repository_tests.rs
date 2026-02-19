/// Integration tests for SessionRepositorySql.
///
/// These tests require a running PostgreSQL instance.
/// Run with: `cargo test -- --ignored --nocapture` when database is ready

use crate::adapters::persistence::{
    database::Database,
    models::SessionRow,
    repositories::SessionRepositorySql,
    error::PersistenceError,
    to_uuid,
};
use chrono::Utc;

/// Helper to get test database URL from environment or use docker-compose default
fn get_test_database_url() -> String {
    std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://auth:password@localhost:5432/auth".to_string())
}

/// Helper to set up a test database and repository
async fn setup_test_db() -> Result<(Database, SessionRepositorySql), PersistenceError> {
    let database = Database::new_default(&get_test_database_url()).await?;
    let repository = SessionRepositorySql::new(database.clone());
    Ok((database, repository))
}

/// Helper to clean up test data
async fn cleanup_session(db: &Database, session_id: &str) -> Result<(), PersistenceError> {
    let session_id_uuid = to_uuid(session_id);
    sqlx::query("DELETE FROM auth_session WHERE id = $1::uuid")
        .bind(&session_id_uuid)
        .execute(db.pool())
        .await
        .map_err(|e| {
            crate::adapters::persistence::error::PersistenceError::Execution(
                crate::adapters::persistence::error::ExecutionError::query_failed(
                    format!("Failed to cleanup test data: {}", e)
                )
            )
        })?;
    Ok(())
}

/// Helper to ensure test identity exists
async fn ensure_test_identity(db: &Database, user_id: &str) -> Result<(), PersistenceError> {
    let now = Utc::now();
    let user_id_uuid = to_uuid(user_id);
    
    // First clean up any existing identity
    let _ = sqlx::query("DELETE FROM identity_credential WHERE user_id = $1::uuid")
        .bind(&user_id_uuid)
        .execute(db.pool())
        .await;

    // Insert test identity
    sqlx::query(
        r#"
        INSERT INTO identity_credential 
        (user_id, identifier, password_hash, failed_attempts, password_changed_at, created_at, updated_at)
        VALUES ($1::uuid, $2, $3, $4, $5, $6, $7)
        "#
    )
    .bind(&user_id_uuid)
    .bind(format!("user_{}@example.com", user_id))
    .bind("$2b$12$hash")
    .bind(0)
    .bind(now)
    .bind(now)
    .bind(now)
    .execute(db.pool())
    .await
    .map_err(|e| {
        crate::adapters::persistence::error::PersistenceError::Execution(
            crate::adapters::persistence::error::ExecutionError::query_failed(
                format!("Failed to create test identity: {}", e)
            )
        )
    })?;

    Ok(())
}

#[tokio::test]
#[ignore] // Requires running PostgreSQL instance
async fn test_create_session_success() {
    let (db, _repo) = setup_test_db()
        .await
        .expect("Failed to setup test database");

    let session_id = "550e8400-e29b-41d4-a716-446655440010";
    let user_id = "550e8400-e29b-41d4-a716-446655440011";

    // Ensure test identity exists
    ensure_test_identity(&db, user_id)
        .await
        .expect("Failed to create test identity");

    // Cleanup first
    let _ = cleanup_session(&db, session_id).await;

    let now = Utc::now();
    let expires_at = now + chrono::Duration::days(7);
    let session_id_uuid = to_uuid(session_id);
    let user_id_uuid = to_uuid(user_id);

    // Create session
    let result = sqlx::query(
        r#"
        INSERT INTO auth_session 
        (id, user_id, refresh_token_hash, created_at, expires_at, ip_address, user_agent, updated_at)
        VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8)
        "#
    )
    .bind(&session_id_uuid)
    .bind(&user_id_uuid)
    .bind("$2b$12$refresh_token_hash_123")
    .bind(now)
    .bind(expires_at)
    .bind("192.168.1.1")
    .bind("Mozilla/5.0")
    .bind(now)
    .execute(db.pool())
    .await;

    assert!(result.is_ok(), "Session creation should succeed");

    // Verify session was created by querying directly
    let check = sqlx::query_scalar::<_, String>(
        "SELECT id::TEXT FROM auth_session WHERE id = $1::uuid"
    )
    .bind(&session_id_uuid)
    .fetch_optional(db.pool())
    .await;
    
    assert!(check.is_ok(), "Should find created session");
    assert!(check.unwrap().is_some(), "Session should exist");

    // Cleanup
    let _ = cleanup_session(&db, session_id).await;
    db.shutdown().await;
}

#[tokio::test]
#[ignore] // Requires running PostgreSQL instance
async fn test_session_is_active() {
    let (db, _repo): (Database, SessionRepositorySql) = setup_test_db()
        .await
        .expect("Failed to setup test database");

    let now = Utc::now();
    let expires_at = now + chrono::Duration::days(7);

    // Create an active session
    let session = SessionRow {
        id: "550e8400-e29b-41d4-a716-446655440020".to_string(),
        user_id: "550e8400-e29b-41d4-a716-446655440021".to_string(),
        refresh_token_hash: "$2b$12$hash".to_string(),
        created_at: now,
        expires_at,
        revoked_at: None,
        ip_address: "192.168.1.1".to_string(),
        user_agent: "Mozilla/5.0".to_string(),
        updated_at: now,
    };

    assert!(session.is_active(now), "Non-revoked, non-expired session should be active");
    assert!(!session.is_active(expires_at + chrono::Duration::seconds(1)), "Expired session should not be active");

    db.shutdown().await;
}

#[tokio::test]
#[ignore] // Requires running PostgreSQL instance
async fn test_session_is_expired() {
    let (db, _repo) = setup_test_db()
        .await
        .expect("Failed to setup test database");

    let now = Utc::now();

    // Create an expired session
    let session = SessionRow {
        id: "550e8400-e29b-41d4-a716-446655440030".to_string(),
        user_id: "550e8400-e29b-41d4-a716-446655440031".to_string(),
        refresh_token_hash: "$2b$12$hash".to_string(),
        created_at: now - chrono::Duration::days(10),
        expires_at: now - chrono::Duration::days(3),
        revoked_at: None,
        ip_address: "192.168.1.1".to_string(),
        user_agent: "Mozilla/5.0".to_string(),
        updated_at: now,
    };

    assert!(session.is_expired(now), "Session with past expiry should be expired");
    assert!(!session.is_expired(now - chrono::Duration::days(4)), "Session should not be expired before expiry time");

    db.shutdown().await;
}

#[tokio::test]
#[ignore] // Requires running PostgreSQL instance
async fn test_session_is_revoked() {
    let (db, _repo) = setup_test_db()
        .await
        .expect("Failed to setup test database");

    let now = Utc::now();
    let expires_at = now + chrono::Duration::days(7);

    // Create a revoked session
    let session = SessionRow {
        id: "550e8400-e29b-41d4-a716-446655440040".to_string(),
        user_id: "550e8400-e29b-41d4-a716-446655440041".to_string(),
        refresh_token_hash: "$2b$12$hash".to_string(),
        created_at: now,
        expires_at,
        revoked_at: Some(now - chrono::Duration::hours(1)),
        ip_address: "192.168.1.1".to_string(),
        user_agent: "Mozilla/5.0".to_string(),
        updated_at: now,
    };

    assert!(session.is_revoked(), "Session with revoked_at should be revoked");
    assert!(!session.is_active(now), "Revoked session should not be active");

    db.shutdown().await;
}

#[tokio::test]
#[ignore] // Requires running PostgreSQL instance
async fn test_find_sessions_by_user_id() {
    let (db, _repo) = setup_test_db()
        .await
        .expect("Failed to setup test database");

    let user_id = "550e8400-e29b-41d4-a716-446655440050";

    // Ensure test identity exists
    ensure_test_identity(&db, user_id)
        .await
        .expect("Failed to create test identity");

    // Create multiple sessions for same user
    let now = Utc::now();
    let expires_at = now + chrono::Duration::days(7);

    let session_ids = vec![
        "550e8400-e29b-41d4-a716-446655440051",
        "550e8400-e29b-41d4-a716-446655440052",
        "550e8400-e29b-41d4-a716-446655440053",
    ];
    let user_id_uuid = to_uuid(user_id);

    for (idx, session_id) in session_ids.iter().enumerate() {
        let _ = cleanup_session(&db, session_id).await;
        let session_id_uuid = to_uuid(session_id);

        sqlx::query(
            r#"
            INSERT INTO auth_session 
            (id, user_id, refresh_token_hash, created_at, expires_at, ip_address, user_agent, updated_at)
            VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8)
            "#
        )
        .bind(&session_id_uuid)
        .bind(&user_id_uuid)
        .bind(format!("$2b$12$hash_{}", idx))
        .bind(now)
        .bind(expires_at)
        .bind("192.168.1.1")
        .bind("Mozilla/5.0")
        .bind(now)
        .execute(db.pool())
        .await
        .expect(&format!("Failed to create session {}", idx));
    }

    // Verify sessions were created by checking directly
    let mut found_count = 0;
    for session_id in session_ids.iter() {
        let session_id_uuid = to_uuid(session_id);
        let check_result = sqlx::query_scalar::<_, String>(
            "SELECT user_id::TEXT FROM auth_session WHERE id = $1::uuid"
        )
        .bind(&session_id_uuid)
        .fetch_optional(db.pool())
        .await
        .expect(&format!("Failed to check session {}", session_id));
        
        if let Some(stored_user_id) = check_result {
            if stored_user_id == user_id_uuid {
                found_count += 1;
            }
        }
    }
    assert_eq!(found_count, 3, "Should find all 3 sessions");

    // Cleanup
    for session_id in session_ids {
        let _ = cleanup_session(&db, session_id).await;
    }
    db.shutdown().await;
}

#[tokio::test]
#[ignore] // Requires running PostgreSQL instance
async fn test_revoke_session() {
    let (db, repo) = setup_test_db()
        .await
        .expect("Failed to setup test database");

    let session_id = "550e8400-e29b-41d4-a716-446655440060";
    let user_id = "550e8400-e29b-41d4-a716-446655440061";

    // Ensure test identity exists
    ensure_test_identity(&db, user_id)
        .await
        .expect("Failed to create test identity");

    // Cleanup first
    let _ = cleanup_session(&db, session_id).await;

    let now = Utc::now();
    let expires_at = now + chrono::Duration::days(7);
    let session_id_uuid = to_uuid(session_id);
    let user_id_uuid = to_uuid(user_id);

    // Create active session
    sqlx::query(
        r#"
        INSERT INTO auth_session 
        (id, user_id, refresh_token_hash, created_at, expires_at, ip_address, user_agent, updated_at)
        VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8)
        "#
    )
    .bind(&session_id_uuid)
    .bind(&user_id_uuid)
    .bind("$2b$12$hash")
    .bind(now)
    .bind(expires_at)
    .bind("192.168.1.1")
    .bind("Mozilla/5.0")
    .bind(now)
    .execute(db.pool())
    .await
    .expect("Failed to create session");

    // Revoke the session
    let revoke_result = repo.revoke_session(session_id).await;
    assert!(revoke_result.is_ok(), "Revoke should succeed");

    // Verify session is revoked by checking revoked_at timestamp
    let check_result = sqlx::query_scalar::<_, Option<String>>(
        "SELECT revoked_at::TEXT FROM auth_session WHERE id = $1::uuid"
    )
    .bind(&session_id_uuid)
    .fetch_optional(db.pool())
    .await;
    
    assert!(check_result.is_ok(), "Should find revoked session");
    let revoked_at = check_result.unwrap().flatten();
    assert!(revoked_at.is_some(), "Session should be marked as revoked");

    // Cleanup
    let _ = cleanup_session(&db, session_id).await;
    db.shutdown().await;
}
