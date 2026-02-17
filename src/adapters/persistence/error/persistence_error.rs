use super::{
    connection_error::ConnectionError, 
    constraint_error::ConstraintError, 
    execution_error::ExecutionError, 
    mapping_error::MappingError
};

/// Errors specific to persistence adapter operations.

/*
This error type answers the question: "Did the database operation succeed?"

It covers failures in:
 - Connection and pool management
 - SQL query execution
 - Data mapping and serialization
 - Transaction coordination
 - Constraint violations

It explicitly does NOT cover:
 - Business logic validation
 - Authentication semantics
 - Cryptographic operations
*/

/// Error type for persistence adapter operations.
///
/// Variants are organized by concern:
/// - `Connection`: Connection pool and network issues
/// - `Mapping`: Data mapping and serialization issues
/// - `Constraint`: Database constraint violations
/// - `Execution`: Query execution and transaction issues
#[derive(Debug, Clone)]
pub enum PersistenceError {
    /// Connection pool or database connectivity issue
    Connection(ConnectionError),
    /// Data mapping or serialization issue
    Mapping(MappingError),
    /// Constraint violation (unique, foreign key, etc.)
    Constraint(ConstraintError),
    /// Query execution or transaction issue
    Execution(ExecutionError),
}

impl PersistenceError {
    /// Create a not found error for the given entity type
    pub fn not_found(entity_type: impl Into<String>) -> Self {
        PersistenceError::Execution(ExecutionError::not_found(entity_type))
    }

    /// Create a unique constraint violation error
    pub fn unique_violation(reason: impl Into<String>) -> Self {
        PersistenceError::Constraint(ConstraintError::unique_violation(reason))
    }

    /// Create an unavailable error (connection issue)
    pub fn unavailable(reason: impl Into<String>) -> Self {
        PersistenceError::Connection(ConnectionError::unavailable(reason))
    }

    /// Create a serialization failed error
    pub fn serialization_failed(
        entity_type: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        PersistenceError::Mapping(MappingError::serialization_failed(entity_type, reason))
    }

    /// Create a deserialization failed error
    pub fn deserialization_failed(
        entity_type: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        PersistenceError::Mapping(MappingError::deserialization_failed(entity_type, reason))
    }

    /// Create a transaction failed error
    pub fn transaction_failed(reason: impl Into<String>) -> Self {
        PersistenceError::Execution(ExecutionError::transaction_failed(reason))
    }

    /// Create a query failed error
    pub fn query_failed(reason: impl Into<String>) -> Self {
        PersistenceError::Execution(ExecutionError::query_failed(reason))
    }

    /// Create a corrupted state error
    pub fn corrupted_state(reason: impl Into<String>) -> Self {
        PersistenceError::Execution(ExecutionError::corrupted_state(reason))
    }

    /// Returns true if this is a not found error
    pub fn is_not_found(&self) -> bool {
        matches!(self, PersistenceError::Execution(ExecutionError::NotFound { .. }))
    }

    /// Returns true if this is a unique constraint violation
    pub fn is_conflict(&self) -> bool {
        matches!(
            self,
            PersistenceError::Constraint(ConstraintError::UniqueViolation { .. })
        )
    }

    /// Returns true if this is a connection/unavailability error
    pub fn is_unavailable(&self) -> bool {
        matches!(self, PersistenceError::Connection(_))
    }

    /// Returns true if this error indicates the transaction is compromised
    ///
    /// If true, the transaction should be rolled back immediately.
    pub fn is_transaction_compromised(&self) -> bool {
        match self {
            PersistenceError::Connection(_) => false,
            PersistenceError::Mapping(e) => e.is_transaction_compromised(),
            PersistenceError::Constraint(_) => false, // Not inherently compromising
            PersistenceError::Execution(e) => e.is_transaction_compromised(),
        }
    }

    /// Returns true if this error is retryable
    ///
    /// Retryable errors are those caused by temporary conditions like
    /// connection timeouts or connection pool exhaustion.
    pub fn is_retryable(&self) -> bool {
        match self {
            PersistenceError::Connection(e) => e.is_retryable(),
            PersistenceError::Mapping(_) => false,
            PersistenceError::Constraint(_) => false,
            PersistenceError::Execution(e) => e.is_retryable(),
        }
    }
}

impl std::fmt::Display for PersistenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PersistenceError::Connection(e) => write!(f, "{}", e),
            PersistenceError::Mapping(e) => write!(f, "{}", e),
            PersistenceError::Constraint(e) => write!(f, "{}", e),
            PersistenceError::Execution(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for PersistenceError {}
