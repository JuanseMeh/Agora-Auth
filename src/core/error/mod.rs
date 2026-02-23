// Core error types for the authentication domain.

// This module defines the complete error semantics for the auth core layer.
/* 
Errors are organized by ownership and responsibility:
 - [`AuthenticationError`]: Identity could not be proven
 - [`CredentialError`]: Credentials are invalid or malformed
 - [`TokenError`]: Trust artifacts are invalid or compromised
 - [`InvariantError`]: Internal invariants were violated (programmer errors)

Design Principles:
 - **No transport concepts**: Errors contain no HTTP status codes or similar
 - **No exceptions**: Errors are values, not panics
 - **Domain language**: Errors express intent, not technical implementation
 - **Immutable**: All errors are value objects with no mutable state
  - **Stable**: Errors remain unchanged across refactors
*/
pub mod authentication_error;
pub mod credential_error;
pub mod token_error;
pub mod invariant_error;

pub use authentication_error::AuthenticationError;
pub use credential_error::CredentialError;
pub use token_error::TokenError;
pub use invariant_error::InvariantError;

#[cfg(test)]
mod tests;

/// Core error type that encompasses all authentication domain failures.
///
/// This is the main error type used throughout the auth core layer.
/// Each variant represents a different category of failure with its own semantics.
#[derive(Debug, Clone)]
pub enum CoreError {
    /// Authentication process failed
    Authentication(AuthenticationError),
    /// Credential validation failed
    Credential(CredentialError),
    /// Token validation failed
    Token(TokenError),
    /// Internal invariant was violated
    Invariant(InvariantError),
}

impl CoreError {
    /// Returns true if this error represents an authentication failure
    pub fn is_authentication(&self) -> bool {
        matches!(self, CoreError::Authentication(_))
    }

    /// Returns true if this error represents a credential failure
    pub fn is_credential(&self) -> bool {
        matches!(self, CoreError::Credential(_))
    }

    /// Returns true if this error represents a token failure
    pub fn is_token(&self) -> bool {
        matches!(self, CoreError::Token(_))
    }

    /// Returns true if this error represents an invariant violation
    pub fn is_invariant(&self) -> bool {
        matches!(self, CoreError::Invariant(_))
    }

    /// Extracts the authentication error if this is one
    pub fn as_authentication(&self) -> Option<&AuthenticationError> {
        match self {
            CoreError::Authentication(err) => Some(err),
            _ => None,
        }
    }

    /// Extracts the credential error if this is one
    pub fn as_credential(&self) -> Option<&CredentialError> {
        match self {
            CoreError::Credential(err) => Some(err),
            _ => None,
        }
    }

    /// Extracts the token error if this is one
    pub fn as_token(&self) -> Option<&TokenError> {
        match self {
            CoreError::Token(err) => Some(err),
            _ => None,
        }
    }

    /// Extracts the invariant error if this is one
    pub fn as_invariant(&self) -> Option<&InvariantError> {
        match self {
            CoreError::Invariant(err) => Some(err),
            _ => None,
        }
    }
}

impl std::fmt::Display for CoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CoreError::Authentication(err) => write!(f, "Authentication error: {}", err),
            CoreError::Credential(err) => write!(f, "Credential error: {}", err),
            CoreError::Token(err) => write!(f, "Token error: {}", err),
            CoreError::Invariant(err) => write!(f, "Invariant error: {}", err),
        }
    }
}

impl From<AuthenticationError> for CoreError {
    fn from(err: AuthenticationError) -> Self {
        CoreError::Authentication(err)
    }
}

impl From<CredentialError> for CoreError {
    fn from(err: CredentialError) -> Self {
        CoreError::Credential(err)
    }
}

impl From<TokenError> for CoreError {
    fn from(err: TokenError) -> Self {
        CoreError::Token(err)
    }
}

impl From<InvariantError> for CoreError {
    fn from(err: InvariantError) -> Self {
        CoreError::Invariant(err)
    }
}
