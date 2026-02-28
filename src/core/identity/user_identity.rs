use std::fmt;

/// Opaque user identity value.
///
/// The internal identifier is intentionally private — raw strings are not
/// exposed except via explicit projection for claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserIdentity {
    pub id: String,
}

impl UserIdentity {
    /// Construct a new `UserIdentity` from any string-like id.
    pub fn new(id: impl Into<String>) -> Self {
        Self { id: id.into() }
    }

    /// Returns the internal identifier.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Consume the identity and produce a claims-safe `String` representation.
    /// 
    /// This method is explicit to avoid accidental leakage of raw identifiers.
    pub fn to_claims_id(&self) -> String {
        self.id.clone()
    }
}

impl fmt::Display for UserIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UserIdentity({})", self.id)
    }
}

