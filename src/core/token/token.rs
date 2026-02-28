/// Opaque trust artifact representing a validated identity assertion.
///
/// A `Token` is an opaque value object that represents an issued trust artifact.
/// It contains no encoding assumptions and makes no claims about its format,
/// serialization, or transport mechanism. The token is intentionally opaque
/// to prevent accidental misuse in the core domain.
///
/// # Design Principles
///
/// - **Opaque**: No direct serialization or decoding interface
/// - **Transport-agnostic**: Could be JWT, PASETO, or any other format
/// - **Immutable**: Once created, a token cannot be modified
/// - **Claim-bearing**: Carries assertions about identity and validity
///
/// # Responsibility
///
/// The `Token` type represents "what is a trust artifact?" in domain terms.
/// Signature verification, key management, and format decoding belong to adapters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    /// The opaque token value. Format and encoding are unknown to the core domain.
    value: String,
}

impl Token {
    /// Create a new token from an opaque value.
    ///
    /// This constructor does not validate the token format or content —
    /// that is the responsibility of adapters and verification logic.
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
        }
    }

    /// Borrow the opaque token value.
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Consume the token and return its opaque value.
    pub fn into_value(self) -> String {
        self.value
    }

    /// Return the byte length of the token value.
    pub fn len(&self) -> usize {
        self.value.len()
    }

    /// Return whether the token value is empty.
    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }
}

impl AsRef<str> for Token {
    fn as_ref(&self) -> &str {
        &self.value
    }
}

impl std::fmt::Display for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Token(****)")
    }
}
