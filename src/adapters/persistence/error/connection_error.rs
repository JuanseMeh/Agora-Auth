/// Errors related to connection pool and database availability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionError {
    /// Database connection failed or is unavailable
    Unavailable { reason: String },
    /// Connection pool is exhausted or misconfigured
    PoolExhausted { reason: String },
    /// Connection timeout occurred
    Timeout { reason: String },
}

impl ConnectionError {
    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self::Unavailable {
            reason: reason.into(),
        }
    }

    pub fn pool_exhausted(reason: impl Into<String>) -> Self {
        Self::PoolExhausted {
            reason: reason.into(),
        }
    }

    pub fn timeout(reason: impl Into<String>) -> Self {
        Self::Timeout {
            reason: reason.into(),
        }
    }

    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            ConnectionError::Unavailable { .. }
                | ConnectionError::Timeout { .. }
                | ConnectionError::PoolExhausted { .. }
        )
    }
}

impl std::fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionError::Unavailable { reason } => write!(f, "database unavailable: {}", reason),
            ConnectionError::PoolExhausted { reason } => write!(f, "connection pool exhausted: {}", reason),
            ConnectionError::Timeout { reason } => write!(f, "connection timeout: {}", reason),
        }
    }
}

impl std::error::Error for ConnectionError {}
