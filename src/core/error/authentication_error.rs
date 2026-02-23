/// Errors related to authentication failures.

/* 
 This error type answers the question: "Could the identity be proven?"
 It covers failures where the authentication process itself fails,
 but not the validity of individual credentials or tokens.
*/ 
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthenticationError {
    /// User could not be found in the system
    UserNotFound {
        reason: String,
    },
    /// Authentication attempt exceeded maximum retries
    MaxAttemptsExceeded {
        attempts: u32,
    },
    /// Authentication method not supported for this user
    UnsupportedAuthMethod {
        method: String,
    },
    /// Authentication flow was interrupted or incomplete
    IncompleteFlow {
        stage: String,
    },
    /// User account is locked or disabled
    AccountLocked {
        reason: String,
    },
    /// External identity provider rejected the authentication
    ExternalProviderRejected {
        provider: String,
        reason: String,
    },
}

impl AuthenticationError {
    /// Create a UserNotFound error with the given reason
    pub fn user_not_found(reason: impl Into<String>) -> Self {
        Self::UserNotFound {
            reason: reason.into(),
        }
    }

    /// Create a MaxAttemptsExceeded error with the given number of attempts
    pub fn max_attempts_exceeded(attempts: u32) -> Self {
        Self::MaxAttemptsExceeded { attempts }
    }

    /// Create an UnsupportedAuthMethod error for the given method
    pub fn unsupported_auth_method(method: impl Into<String>) -> Self {
        Self::UnsupportedAuthMethod {
            method: method.into(),
        }
    }

    /// Create an IncompleteFlow error for the given stage
    pub fn incomplete_flow(stage: impl Into<String>) -> Self {
        Self::IncompleteFlow {
            stage: stage.into(),
        }
    }

    /// Create an AccountLocked error with the given reason
    pub fn account_locked(reason: impl Into<String>) -> Self {
        Self::AccountLocked {
            reason: reason.into(),
        }
    }

    /// Returns true if this error is an AccountLocked variant
    pub fn is_account_locked(&self) -> bool {
        matches!(self, Self::AccountLocked { .. })
    }

    /// Create an ExternalProviderRejected error
    pub fn external_provider_rejected(
        provider: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self::ExternalProviderRejected {
            provider: provider.into(),
            reason: reason.into(),
        }
    }
}

impl std::fmt::Display for AuthenticationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UserNotFound { reason } => write!(f, "User not found: {}", reason),
            Self::MaxAttemptsExceeded { attempts } => {
                write!(f, "Maximum authentication attempts exceeded: {}", attempts)
            }
            Self::UnsupportedAuthMethod { method } => {
                write!(f, "Authentication method not supported: {}", method)
            }
            Self::IncompleteFlow { stage } => {
                write!(f, "Authentication flow incomplete at stage: {}", stage)
            }
            Self::AccountLocked { reason } => {
                write!(f, "Account is locked: {}", reason)
            }
            Self::ExternalProviderRejected { provider, reason } => {
                write!(
                    f,
                    "External identity provider '{}' rejected authentication: {}",
                    provider, reason
                )
            }
        }
    }
}
