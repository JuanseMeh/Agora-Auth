/// Errors related to query execution and transaction operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionError {
    /// Entity was not found in the database
    NotFound { entity_type: String },
    /// Query execution failed
    QueryFailed { reason: String },
    /// Transaction failed or was rolled back
    TransactionFailed { reason: String },
    /// Transaction is in an invalid state for the operation
    InvalidTransactionState { reason: String },
    /// Database is in a corrupted or invalid state
    CorruptedState { reason: String },
}

impl ExecutionError {
    pub fn not_found(entity_type: impl Into<String>) -> Self {
        Self::NotFound {
            entity_type: entity_type.into(),
        }
    }

    pub fn query_failed(reason: impl Into<String>) -> Self {
        Self::QueryFailed {
            reason: reason.into(),
        }
    }

    pub fn transaction_failed(reason: impl Into<String>) -> Self {
        Self::TransactionFailed {
            reason: reason.into(),
        }
    }

    pub fn invalid_transaction_state(reason: impl Into<String>) -> Self {
        Self::InvalidTransactionState {
            reason: reason.into(),
        }
    }

    pub fn corrupted_state(reason: impl Into<String>) -> Self {
        Self::CorruptedState {
            reason: reason.into(),
        }
    }

    /// Returns true if this error indicates the transaction is compromised
    pub fn is_transaction_compromised(&self) -> bool {
        matches!(
            self,
            ExecutionError::TransactionFailed { .. }
                | ExecutionError::InvalidTransactionState { .. }
                | ExecutionError::CorruptedState { .. }
        )
    }

    /// Returns true if this error is retryable
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            ExecutionError::QueryFailed { .. } | ExecutionError::CorruptedState { .. }
        )
    }
}

impl std::fmt::Display for ExecutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecutionError::NotFound { entity_type } => {
                write!(f, "{} not found in database", entity_type)
            }
            ExecutionError::QueryFailed { reason } => {
                write!(f, "query failed: {}", reason)
            }
            ExecutionError::TransactionFailed { reason } => {
                write!(f, "transaction failed: {}", reason)
            }
            ExecutionError::InvalidTransactionState { reason } => {
                write!(f, "invalid transaction state: {}", reason)
            }
            ExecutionError::CorruptedState { reason } => {
                write!(f, "database in corrupted state: {}", reason)
            }
        }
    }
}

impl std::error::Error for ExecutionError {}
