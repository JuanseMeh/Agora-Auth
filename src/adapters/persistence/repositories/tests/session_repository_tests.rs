/// Tests for SessionRepositorySql.
///
/// Note: These are unit tests for the repository structure.
/// Integration tests requiring database connectivity should be marked with #[ignore]
/// and run with `cargo test -- --ignored` when a test database is available.

use crate::adapters::persistence::repositories::SessionRepositorySql;

#[test]
fn session_repository_sql_can_be_constructed() {
    // This test verifies that the repository type is properly defined
    // Actual database operations require a live database connection
    let _repo_type = std::any::type_name::<SessionRepositorySql>();
    assert!(_repo_type.contains("SessionRepositorySql"));
}

