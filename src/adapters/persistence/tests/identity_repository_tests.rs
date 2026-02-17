/// Integration tests for IdentityRepositorySql.
///
/// These tests require a running PostgreSQL instance.
/// Run with: `cargo test -- --ignored --nocapture` when database is ready

use crate::adapters::persistence::{
    database::Database,
    models::IdentityRow,
    repositories::IdentityRepositorySql,
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
async fn setup_test_db() -> Result<(Database, IdentityRepositorySql), PersistenceError> {
    let database = Database::new_default(&get_test_database_url()).await?;
    let repository = IdentityRepositorySql::new(database.clone());
    Ok((database, repository))
}

/// Helper to clean up test data by identifier
async fn cleanup_identity(db: &Database, identifier: &str) -> Result<(), PersistenceError> {
    sqlx::query("DELETE FROM identity_credential WHERE identifier = $1")
        .bind(identifier)
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

/// Helper to clean up test data by user_id
async fn cleanup_identity_by_user_id(db: &Database, user_id: &str) -> Result<(), PersistenceError> {
    let user_id_uuid = to_uuid(user_id);
    sqlx::query("DELETE FROM identity_credential WHERE user_id = $1::uuid")
        .bind(&user_id_uuid)
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

#[tokio::test]
#[ignore] // Requires running PostgreSQL instance
async fn test_find_identity_by_identifier_success() {
    let (db, repo) = setup_test_db()
        .await
        .expect("Failed to setup test database");

    let identifier = "success.test@example.com";
    let user_id_str = "550e8400-e29b-41d4-a716-446655440100";
    
    // Cleanup first (by both identifier and user_id to be thorough)
    let _ = cleanup_identity(&db, identifier).await;
    let _ = cleanup_identity_by_user_id(&db, user_id_str).await;

    // Insert test data
    let now = Utc::now();
    let user_id_uuid = to_uuid(user_id_str);
    sqlx::query(
        r#"
        INSERT INTO identity_credential 
        (user_id, identifier, password_hash, failed_attempts, password_changed_at, created_at, updated_at)
        VALUES ($1::uuid, $2, $3, $4, $5, $6, $7)
        "#
    )
    .bind(&user_id_uuid)
    .bind(identifier)
    .bind("$2b$12$abcdefghijklmnopqrstuvwxyz")
    .bind(0)
    .bind(now)
    .bind(now)
    .bind(now)
    .execute(db.pool())
    .await
    .expect("Failed to insert test identity");

    // Test the repository method
    let result = repo.find_by_identifier(identifier).await;

    assert!(result.is_ok(), "find_by_identifier should succeed: {:?}", result);
    let identity = result.unwrap();
    assert_eq!(identity.identifier, identifier);
    assert_eq!(identity.failed_attempts, 0);
    assert!(!identity.is_locked(Utc::now()));

    // Cleanup
    let _ = cleanup_identity(&db, identifier).await;
    db.shutdown().await;
}

#[tokio::test]
#[ignore] // Requires running PostgreSQL instance
async fn test_find_identity_by_identifier_not_found() {
    let (db, repo) = setup_test_db()
        .await
        .expect("Failed to setup test database");

    let identifier = "nonexistent@example.com";

    // Ensure it doesn't exist
    let _ = cleanup_identity(&db, identifier).await;

    // Test the repository method
    let result = repo.find_by_identifier(identifier).await;

    assert!(result.is_err(), "find_by_identifier should fail for non-existent identity");
    match result {
        Err(PersistenceError::Execution(e)) => {
            assert!(e.to_string().contains("not found") || e.to_string().contains("NotFound"));
        }
        _ => panic!("Expected ExecutionError::NotFound"),
    }

    db.shutdown().await;
}

#[tokio::test]
#[ignore] // Requires running PostgreSQL instance
async fn test_find_identity_by_user_id_success() {
    let (db, repo) = setup_test_db()
        .await
        .expect("Failed to setup test database");

    let user_id = "550e8400-e29b-41d4-a716-446655440101";
    let identifier = "byid.test@example.com";

    // Cleanup first (by both identifier and user_id to be thorough)
    let _ = cleanup_identity(&db, identifier).await;
    let _ = cleanup_identity_by_user_id(&db, user_id).await;

    // Insert test data
    let now = Utc::now();
    let user_id_uuid = to_uuid(user_id);
    sqlx::query(
        r#"
        INSERT INTO identity_credential 
        (user_id, identifier, password_hash, failed_attempts, password_changed_at, created_at, updated_at)
        VALUES ($1::uuid, $2, $3, $4, $5, $6, $7)
        "#
    )
    .bind(&user_id_uuid)
    .bind(identifier)
    .bind("$2b$12$hashedpassword123456789")
    .bind(0)
    .bind(now)
    .bind(now)
    .bind(now)
    .execute(db.pool())
    .await
    .expect("Failed to insert test identity");

    // Test the repository method
    let result: Result<IdentityRow, PersistenceError> = repo.find_by_id(user_id).await;

    assert!(result.is_ok(), "find_by_id should succeed: {:?}", result);
    let identity = result.unwrap();
    assert_eq!(identity.user_id, user_id);
    assert_eq!(identity.identifier, identifier);

    // Cleanup
    let _ = cleanup_identity(&db, identifier).await;
    db.shutdown().await;
}

#[tokio::test]
#[ignore] // Requires running PostgreSQL instance
async fn test_identity_row_is_locked() {
    let (db, _repo) = setup_test_db()
        .await
        .expect("Failed to setup test database");

    let now = Utc::now();
    let locked_until = now + chrono::Duration::hours(1);

    // Create a locked identity
    let identity = IdentityRow {
        user_id: "550e8400-e29b-41d4-a716-446655440002".to_string(),
        identifier: "locked@example.com".to_string(),
        password_hash: "$2b$12$hash".to_string(),
        failed_attempts: 5,
        locked_until: Some(locked_until),
        password_changed_at: now,
        created_at: now,
        updated_at: now,
    };

    // Test lock status
    assert!(identity.is_locked(now), "Identity should be locked");
    assert!(!identity.is_locked(locked_until + chrono::Duration::seconds(1)), "Identity should be unlocked after lock time");

    // Test lock remaining time
    let remaining = identity.lock_remaining(now);
    assert!(remaining.is_some(), "Should have remaining lock time");
    assert!(remaining.unwrap().as_secs() > 3500 && remaining.unwrap().as_secs() <= 3600);

    db.shutdown().await;
}

#[tokio::test]
#[ignore] // Requires running PostgreSQL instance
async fn test_identity_row_failed_attempts_validation() {
    let (db, _repo) = setup_test_db()
        .await
        .expect("Failed to setup test database");

    let now = Utc::now();

    // Create an identity with high failed attempts
    let identity = IdentityRow {
        user_id: "550e8400-e29b-41d4-a716-446655440003".to_string(),
        identifier: "attempts@example.com".to_string(),
        password_hash: "$2b$12$hash".to_string(),
        failed_attempts: 10,
        locked_until: None,
        password_changed_at: now,
        created_at: now,
        updated_at: now,
    };

    // Verify failed attempts are tracked
    assert_eq!(identity.failed_attempts, 10);
    assert!(!identity.is_locked(now), "Should not be locked without locked_until");

    db.shutdown().await;
}

#[tokio::test]
#[ignore] // Requires running PostgreSQL instance
async fn test_identity_duplicate_identifier_constraint() {
    let (db, _repo) = setup_test_db()
        .await
        .expect("Failed to setup test database");

    let identifier = "duplicatetest@example.com";
    let _now = Utc::now();

    // Cleanup first
    let _ = cleanup_identity(&db, identifier).await;

    // Insert first identity
    let now = Utc::now();
    let user_id_1 = to_uuid("550e8400-e29b-41d4-a716-446655440004");
    let result1 = sqlx::query(
        r#"
        INSERT INTO identity_credential 
        (user_id, identifier, password_hash, failed_attempts, password_changed_at, created_at, updated_at)
        VALUES ($1::uuid, $2, $3, $4, $5, $6, $7)
        "#
    )
    .bind(&user_id_1)
    .bind(identifier)
    .bind("$2b$12$hash1")
    .bind(0)
    .bind(now)
    .bind(now)
    .bind(now)
    .execute(db.pool())
    .await;

    assert!(result1.is_ok(), "First insert should succeed");

    // Try to insert duplicate identifier
    let user_id_2 = to_uuid("550e8400-e29b-41d4-a716-446655440005");
    let result2 = sqlx::query(
        r#"
        INSERT INTO identity_credential 
        (user_id, identifier, password_hash, failed_attempts, password_changed_at, created_at, updated_at)
        VALUES ($1::uuid, $2, $3, $4, $5, $6, $7)
        "#
    )
    .bind(&user_id_2)
    .bind(identifier)
    .bind("$2b$12$hash2")
    .bind(0)
    .bind(now)
    .bind(now)
    .bind(now)
    .execute(db.pool())
    .await;

    assert!(result2.is_err(), "Duplicate identifier should violate constraint");

    // Cleanup
    let _ = cleanup_identity(&db, identifier).await;
    db.shutdown().await;
}
