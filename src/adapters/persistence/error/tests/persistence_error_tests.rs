#[cfg(test)]
mod tests {
    use crate::adapters::persistence::error::{
        PersistenceError, ExecutionError, ConstraintError, ConnectionError, MappingError,
    };

    #[test]
    fn test_not_found_creation() {
        let err = PersistenceError::not_found("User");
        assert!(err.is_not_found());
        assert!(!err.is_conflict());
    }

    #[test]
    fn test_unique_violation_creation() {
        let err = PersistenceError::unique_violation("duplicate identifier");
        assert!(err.is_conflict());
        assert!(!err.is_not_found());
    }

    #[test]
    fn test_unavailable_creation() {
        let err = PersistenceError::unavailable("connection pool exhausted");
        assert!(err.is_unavailable());
        assert!(err.is_retryable());
    }

    #[test]
    fn test_transaction_failed_is_compromised() {
        let err = PersistenceError::transaction_failed("rollback failed");
        assert!(err.is_transaction_compromised());
    }

    #[test]
    fn test_deserialization_failed_is_compromised() {
        let err = PersistenceError::deserialization_failed("Identity", "invalid json");
        assert!(err.is_transaction_compromised());
    }

    #[test]
    fn test_corrupted_state_is_compromised() {
        let err = PersistenceError::corrupted_state("data integrity violation");
        assert!(err.is_transaction_compromised());
    }

    #[test]
    fn test_retryable_conditions() {
        let unavailable = PersistenceError::unavailable("timeout");
        let query_failed = PersistenceError::query_failed("connection reset");

        assert!(unavailable.is_retryable());
        assert!(query_failed.is_retryable());
    }

    #[test]
    fn test_non_retryable_conditions() {
        let not_found = PersistenceError::not_found("User");
        let conflict = PersistenceError::unique_violation("duplicate key");
        let deserialization = PersistenceError::deserialization_failed("Session", "invalid");

        assert!(!not_found.is_retryable());
        assert!(!conflict.is_retryable());
        assert!(!deserialization.is_retryable());
    }

    #[test]
    fn test_display_formatting() {
        let err = PersistenceError::not_found("User");
        assert!(err.to_string().contains("User"));
        assert!(err.to_string().contains("not found"));

        let err = PersistenceError::unique_violation("duplicate identifier");
        assert!(err.to_string().contains("unique constraint"));

        let err = PersistenceError::unavailable("connection timeout");
        assert!(err.to_string().contains("unavailable"));
    }

    #[test]
    fn test_execution_error_variants() {
        let not_found = ExecutionError::not_found("Session");
        assert!(not_found.to_string().contains("not found"));

        let query_failed = ExecutionError::query_failed("timeout");
        assert!(query_failed.to_string().contains("query failed"));

        let transaction_failed = ExecutionError::transaction_failed("rollback");
        assert!(transaction_failed.is_transaction_compromised());
    }

    #[test]
    fn test_mapping_error_variants() {
        let deserialization = MappingError::deserialization_failed("Identity", "invalid data");
        assert!(deserialization.is_transaction_compromised());
        assert!(deserialization.to_string().contains("deserialize"));

        let type_mismatch = MappingError::type_mismatch(
            "Session",
            "expires_at",
            "DateTime",
            "String",
        );
        assert!(type_mismatch.to_string().contains("type mismatch"));
    }

    #[test]
    fn test_connection_error_variants() {
        let unavailable = ConnectionError::unavailable("no connection");
        assert!(unavailable.to_string().contains("unavailable"));

        let pool_exhausted = ConnectionError::pool_exhausted("max connections");
        assert!(pool_exhausted.is_retryable());
        assert!(pool_exhausted.to_string().contains("pool exhausted"));

        let timeout = ConnectionError::timeout("30s");
        assert!(timeout.is_retryable());
    }

    #[test]
    fn test_constraint_error_variants() {
        let unique = ConstraintError::unique_violation("user_email");
        assert!(unique.to_string().contains("unique constraint"));

        let fk = ConstraintError::foreign_key_violation("user_id");
        assert!(fk.to_string().contains("foreign key"));

        let not_null = ConstraintError::not_null_violation("password_hash");
        assert!(not_null.to_string().contains("not null"));
    }
}
