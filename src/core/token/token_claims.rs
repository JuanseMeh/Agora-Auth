/// Token claims representing identity context and temporal bounds.
///
/// `TokenClaims` is a data-only type that projects identity information
/// and temporal validity bounds suitable for embedding in a token.
///
/// # Responsibility
///
/// This type answers the question: "What identity and temporal assertions
/// does this token make?" It is intentionally immutable and contains no
/// business logic — it is purely an identity projection.
///
/// # Design Principles
///
/// - **Data-only**: No methods that compute or perform authorization checks
/// - **Immutable**: All fields are public and fixed after construction
/// - **Domain-driven**: Uses domain types like `IdentityClaims` and `TokenLifetime`
/// - **Transport-safe**: Can be safely serialized without exposing secrets
///
/// # Non-Responsibility
///
/// This type does NOT:
/// - Encode permissions or scopes
/// - Encode business rules
/// - Imply authorization sufficiency
/// - Define how claims are serialized

use crate::core::identity::IdentityClaims;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenClaims {
    /// Identity context: user and workspace identifiers.
    pub identity: IdentityClaims,

    /// When the token was issued (as RFC3339 timestamp).
    /// This is used to detect forged or replayed tokens.
    pub issued_at: String,

    /// When the token expires (as RFC3339 timestamp).
    /// After this time, the token is no longer valid.
    pub expires_at: String,

    /// Optional "not before" time (as RFC3339 timestamp).
    /// If present, the token is not valid before this time.
    pub not_before: Option<String>,

    /// Optional list of scopes or capabilities this token grants.
    ///
    /// **Important**: Scopes are context data, not authorization rules.
    /// Authorization decisions MUST NOT be made solely from token scopes.
    /// Scopes indicate what the token claims to grant; enforcement happens elsewhere.
    pub scopes: Option<Vec<String>>,
}

impl TokenClaims {
    /// Create a new `TokenClaims` with required identity and temporal bounds.
    pub fn new(
        identity: IdentityClaims,
        issued_at: impl Into<String>,
        expires_at: impl Into<String>,
    ) -> Self {
        Self {
            identity,
            issued_at: issued_at.into(),
            expires_at: expires_at.into(),
            not_before: None,
            scopes: None,
        }
    }

    /// Set an optional "not before" time.
    pub fn with_not_before(mut self, not_before: impl Into<String>) -> Self {
        self.not_before = Some(not_before.into());
        self
    }

    /// Set optional scopes.
    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = Some(scopes);
        self
    }

    /// Check if this claims object represents any identity.
    ///
    /// Returns `true` if at least one identity field (user_id or workspace_id) is present.
    pub fn has_identity(&self) -> bool {
        !self.identity.is_empty()
    }

    /// Check if scopes are present.
    pub fn has_scopes(&self) -> bool {
        self.scopes.as_ref().map(|s| !s.is_empty()).unwrap_or(false)
    }

    /// Get scopes as a slice if present, otherwise an empty slice.
    pub fn scopes(&self) -> &[String] {
        self.scopes.as_deref().unwrap_or(&[])
    }
}
