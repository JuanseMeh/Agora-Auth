use crate::core::error::InvariantError;
use std::fmt;

use super::{UserIdentity, WorkspaceIdentity, IdentityClaims};

/// Composition of a user identity and an optional workspace identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextualIdentity {
    pub user: Option<UserIdentity>,
    pub workspace: Option<WorkspaceIdentity>,
}

impl ContextualIdentity {
    /// Construct a contextual identity.
    ///
    /// At least one of `user` or `workspace` must be present. Violations map
    /// to `InvariantError`.
    pub fn new(
        user: Option<UserIdentity>,
        workspace: Option<WorkspaceIdentity>,
    ) -> Result<Self, InvariantError> {
        if user.is_none() && workspace.is_none() {
            return Err(InvariantError::invalid_configuration(
                "ContextualIdentity requires a user or a workspace",
            ));
        }
        Ok(Self { user, workspace })
    }

    /// Project into token-safe claims.
    pub fn to_claims(&self) -> IdentityClaims {
        IdentityClaims {
            user_id: self.user.as_ref().map(|u| u.to_claims_id()),
            workspace_id: self.workspace.as_ref().map(|w| w.to_claims_id()),
        }
    }

    /// Returns true if a user identity is present.
    pub fn has_user(&self) -> bool {
        self.user.is_some()
    }

    /// Returns true if a workspace identity is present.
    pub fn has_workspace(&self) -> bool {
        self.workspace.is_some()
    }

    /// Returns the user identifier if present.
    pub fn user_id(&self) -> Option<&str> {
        self.user.as_ref().map(|u| u.id())
    }

    /// Returns the workspace identifier if present.
    pub fn workspace_id(&self) -> Option<&str> {
        self.workspace.as_ref().map(|w| w.id())
    }
}

impl fmt::Display for ContextualIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.user, &self.workspace) {
            (Some(u), Some(w)) => write!(f, "{}@{}", u, w),
            (Some(u), None) => write!(f, "{}", u),
            (None, Some(w)) => write!(f, "{}", w),
            (None, None) => write!(f, "<anonymous>"),
        }
    }
}

/// Ergonomic conversion from a user identity.
impl From<UserIdentity> for ContextualIdentity {
    fn from(user: UserIdentity) -> Self {
        Self::new(Some(user), None).unwrap()
    }
}

/// Ergonomic conversion from a workspace identity.
impl From<WorkspaceIdentity> for ContextualIdentity {
    fn from(workspace: WorkspaceIdentity) -> Self {
        Self::new(None, Some(workspace)).unwrap()
    }
}

