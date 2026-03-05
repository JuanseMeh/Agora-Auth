/// Token claims representing identity context and temporal bounds.
///
/// `TokenClaims` is a data-only type that projects identity information
/// and temporal validity bounds suitable for embedding in a token.
///
/// # Design Principles
///
/// - **Data-only**: No methods that compute or perform authorization checks
/// - **Immutable**: All fields are public and fixed after construction
/// - **Transport-safe**: Can be safely serialized without exposing secrets
/// - **JWT Standard Compliant**: Uses i64 timestamps (UNIX epoch)
///
/// # Target JWT Structure
///
/// ```json
/// {
///   "sub": "user_uuid",
///   "sid": "session_uuid",
///   "aud": ["auth_service"],
///   "iat": 1772712911,
///   "exp": 1772716511,
///   "nbf": 1772712911,
///   "token_type": "access",
///   "scope": ["read", "write"]
/// }
/// ```

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TokenClaims {
    /// Subject (user identifier) - maps to JWT "sub" claim
    pub sub: String,

    /// Session ID for revocation/tracking - maps to JWT "sid" claim
    pub sid: Option<String>,

    /// Audience (intended service(s)) - maps to JWT "aud" claim
    pub aud: Option<Vec<String>>,

    /// Issued at timestamp (Unix epoch seconds) - maps to JWT "iat" claim
    pub iat: i64,

    /// Expiration timestamp (Unix epoch seconds) - maps to JWT "exp" claim
    pub exp: i64,

    /// Not before timestamp (Unix epoch seconds) - maps to JWT "nbf" claim
    pub nbf: Option<i64>,

    /// Scopes/permissions - maps to JWT "scope" claim (space-separated string)
    /// Always a vector, never null - empty vector serializes to empty string
    #[serde(default)]
    pub scope: Vec<String>,

    /// Token type: "access", "refresh", or "service" - maps to JWT "token_type" claim
    pub token_type: String,
}

impl TokenClaims {
    /// Create a new `TokenClaims` with required identity and temporal bounds.
    pub fn new(
        sub: String,
        iat: i64,
        exp: i64,
        token_type: String,
    ) -> Self {
        Self {
            sub,
            sid: None,
            aud: None,
            iat,
            exp,
            nbf: None,
            scope: vec![],
            token_type,
        }
    }

    /// Set session ID for revocation tracking.
    pub fn with_sid(mut self, sid: impl Into<String>) -> Self {
        self.sid = Some(sid.into());
        self
    }

    /// Set audience for the token.
    pub fn with_audience(mut self, audience: Vec<String>) -> Self {
        self.aud = Some(audience);
        self
    }

    /// Set "not before" timestamp.
    pub fn with_not_before(mut self, nbf: i64) -> Self {
        self.nbf = Some(nbf);
        self
    }

    /// Set scopes/permissions.
    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.scope = scopes;
        self
    }

    /// Check if this claims object has a valid subject.
    pub fn has_identity(&self) -> bool {
        !self.sub.is_empty()
    }

    /// Check if scopes are present.
    pub fn has_scopes(&self) -> bool {
        !self.scope.is_empty()
    }

    /// Get scopes as a slice.
    pub fn scopes(&self) -> &[String] {
        &self.scope
    }
}

