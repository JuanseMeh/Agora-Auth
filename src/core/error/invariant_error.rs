/// Errors that represent invariant violations—situations that should never occur.

/*
 This error type is used when internal state or preconditions are violated,
 indicating a bug or corrupted state in the application rather than
 normal failure scenarios. These are programmer errors, not user errors.
*/
 #[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvariantError {
    /// An internal assertion failed
    AssertionFailed {
        condition: String,
        context: String,
    },
    /// Required dependency or service is unavailable unexpectedly
    DependencyUnavailable {
        dependency: String,
        reason: String,
    },
    /// Internal state is inconsistent or corrupted
    InconsistentState {
        description: String,
    },
    /// Configuration is invalid or incomplete
    InvalidConfiguration {
        reason: String,
    },
    /// Unreachable code was executed (logic error)
    UnreachableCode {
        location: String,
    },
    /// An invariant was violated (generic)
    Violated {
        description: String,
    },
}

impl InvariantError {
    /// Create an AssertionFailed error
    pub fn assertion_failed(
        condition: impl Into<String>,
        context: impl Into<String>,
    ) -> Self {
        Self::AssertionFailed {
            condition: condition.into(),
            context: context.into(),
        }
    }

    /// Create a DependencyUnavailable error
    pub fn dependency_unavailable(
        dependency: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self::DependencyUnavailable {
            dependency: dependency.into(),
            reason: reason.into(),
        }
    }

    /// Create an InconsistentState error
    pub fn inconsistent_state(description: impl Into<String>) -> Self {
        Self::InconsistentState {
            description: description.into(),
        }
    }

    /// Create an InvalidConfiguration error
    pub fn invalid_configuration(reason: impl Into<String>) -> Self {
        Self::InvalidConfiguration {
            reason: reason.into(),
        }
    }

    /// Create an UnreachableCode error
    pub fn unreachable_code(location: impl Into<String>) -> Self {
        Self::UnreachableCode {
            location: location.into(),
        }
    }

    /// Create a Violated error
    pub fn violated(description: impl Into<String>) -> Self {
        Self::Violated {
            description: description.into(),
        }
    }
}

impl std::fmt::Display for InvariantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AssertionFailed { condition, context } => {
                write!(
                    f,
                    "Internal assertion failed: {} ({})",
                    condition, context
                )
            }
            Self::DependencyUnavailable { dependency, reason } => {
                write!(
                    f,
                    "Required dependency '{}' is unexpectedly unavailable: {}",
                    dependency, reason
                )
            }
            Self::InconsistentState { description } => {
                write!(f, "Internal state is inconsistent: {}", description)
            }
            Self::InvalidConfiguration { reason } => {
                write!(f, "Invalid configuration: {}", reason)
            }
            Self::UnreachableCode { location } => {
                write!(f, "Unreachable code was executed at: {}", location)
            }
            Self::Violated { description } => {
                write!(f, "Invariant violated: {}", description)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assertion_failed() {
        let err = InvariantError::assertion_failed("token_id.is_some()", "validate_token");
        assert_eq!(
            err,
            InvariantError::AssertionFailed {
                condition: "token_id.is_some()".to_string(),
                context: "validate_token".to_string()
            }
        );
    }

    #[test]
    fn test_dependency_unavailable() {
        let err = InvariantError::dependency_unavailable("clock", "system clock not accessible");
        assert_eq!(
            err,
            InvariantError::DependencyUnavailable {
                dependency: "clock".to_string(),
                reason: "system clock not accessible".to_string()
            }
        );
    }

    #[test]
    fn test_display_inconsistent_state() {
        let err =
            InvariantError::inconsistent_state("token exp is before iat");
        assert_eq!(
            err.to_string(),
            "Internal state is inconsistent: token exp is before iat"
        );
    }
}
