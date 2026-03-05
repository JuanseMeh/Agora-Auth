use crate::core::error::InvariantError;
use std::fmt;

use super::{UserIdentity, IdentityClaims};

/// Composition of a user identity (workspace removed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextualIdentity {
    pub user: Option<UserIdentity>,
}

impl ContextualIdentity {
    /// Construct a contextual identity.
    ///
    /// User must be present. Violations map to `InvariantError`.
    pub fn new(
        user: Option<UserIdentity>,
    ) -> Result<Self, InvariantError> {
        if user.is_none() {
            return Err(InvariantError::invalid_configuration(
                "ContextualIdentity requires a user",
            ));
        }
        Ok(Self { user })
    }

    /// Project into token-safe claims.
    pub fn to_claims(&self) -> IdentityClaims {
        IdentityClaims {
            user_id: self.user.as_ref().map(|u| u.to_claims_id()),
        }
    }

    /// Returns true if a user identity is present.
    pub fn has_user(&self) -> bool {
        self.user.is_some()
    }

    /// Returns the user identifier if present.
    pub fn user_id(&self) -> Option<&str> {
        self.user.as_ref().map(|u| u.id())
    }
}

impl fmt::Display for ContextualIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.user {
            Some(u) => write!(f, "{}", u),
            None => write!(f, "<anonymous>"),
        }
    }
}

/// Ergonomic conversion from a user identity.
impl From<UserIdentity> for ContextualIdentity {
    fn from(user: UserIdentity) -> Self {
        Self::new(Some(user)).unwrap()
    }
}

