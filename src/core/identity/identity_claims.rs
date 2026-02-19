/// Token-safe, data-only representation of an identity.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
pub struct IdentityClaims {
    /// Optional user identifier suitable for embedding in claims
    pub user_id: Option<String>,
    /// Optional workspace identifier suitable for embedding in claims
    pub workspace_id: Option<String>,
}

impl IdentityClaims {
    /// True if there is no identity information present
    pub fn is_empty(&self) -> bool {
        self.user_id.is_none() && self.workspace_id.is_none()
    }
}
