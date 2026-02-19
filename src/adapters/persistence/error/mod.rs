// Persistence layer error types.

/*
This module defines errors specific to the persistence adapter layer.

These errors represent failures in database operations and data mapping,
independent of business logic. They are NOT domain errors.

Design Principles:
 - **Isolation**: Persistence errors never leak SQL/database details upward
 - **Mapping**: All sqlx errors are caught and mapped to PersistenceError
 - **No panic**: All database operations return Results
 - **Transaction-aware**: Errors indicate whether transaction is compromised
 - **Recoverable**: Errors distinguish retryable from fatal conditions

Errors are organized by concern:
 - `ConnectionError`: Connection pool and network issues
 - `MappingError`: Data mapping and serialization issues
 - `ConstraintError`: Database constraint violations
 - `ExecutionError`: Query execution and transaction issues
 - `PersistenceError`: Top-level enum that wraps all of the above
*/

pub mod connection_error;
pub mod constraint_error;
pub mod execution_error;
pub mod mapping_error;
pub mod persistence_error;

pub use connection_error::ConnectionError;
pub use constraint_error::ConstraintError;
pub use execution_error::ExecutionError;
pub use mapping_error::MappingError;
pub use persistence_error::PersistenceError;

#[cfg(test)]
mod tests;