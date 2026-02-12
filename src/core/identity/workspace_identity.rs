use std::fmt;

/// Opaque workspace identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceIdentity {
    pub id: String,
}

impl WorkspaceIdentity {
    /// Create a new workspace identity from a string-like id.
    pub fn new(id: impl Into<String>) -> Self {
        Self { id: id.into() }
    }

    /// Returns the internal identifier.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Export a claims-safe string representation.
    pub fn to_claims_id(&self) -> String {
        self.id.clone()
    }
}

impl fmt::Display for WorkspaceIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WorkspaceIdentity({})", self.id)
    }
}

