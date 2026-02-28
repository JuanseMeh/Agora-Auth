/// Token lifetime validation semantics.
///
/// `TokenLifetime` encapsulates the temporal bounds of a token and provides
/// deterministic validation of time-based constraints independent of any
/// specific clock implementation.
///
/// # Responsibility
///
/// Core defines:
/// - "Token is expired" (current time > expires_at)
/// - "Token not yet valid" (current time < not_before or issued_at)
///
/// Core does NOT define:
/// - Clock source implementation (provided by `Clock` port)
/// - How times are persisted or synchronized
/// - Timezone handling (times are assumed RFC3339)
///
/// # Design Principles
///
/// - **Deterministic**: Given a reference time, validation result is always the same
/// - **Explicit**: No implicit behavior or side effects
/// - **Temporal-only**: Contains only time-based validation rules
/// - **Immutable**: Cannot be modified after construction

/// Represents the temporal bounds and validity window of a token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenLifetime {
    /// When the token was issued (RFC3339 format).
    /// Tokens issued in the future are invalid.
    pub issued_at: String,

    /// When the token expires (RFC3339 format).
    /// After this time, the token is considered expired.
    pub expires_at: String,

    /// Optional "not before" time (RFC3339 format).
    /// If present, tokens are invalid before this time.
    /// This may differ from `issued_at` to support delayed validity.
    pub not_before: Option<String>,
}

impl TokenLifetime {
    /// Create a new `TokenLifetime` with issued and expiration times.
    pub fn new(issued_at: impl Into<String>, expires_at: impl Into<String>) -> Self {
        Self {
            issued_at: issued_at.into(),
            expires_at: expires_at.into(),
            not_before: None,
        }
    }

    /// Set an optional "not before" time.
    pub fn with_not_before(mut self, not_before: impl Into<String>) -> Self {
        self.not_before = Some(not_before.into());
        self
    }

    /// Check if token is expired relative to a reference time.
    ///
    /// Returns `true` if `reference_time` is greater than or equal to `expires_at`.
    ///
    /// # Arguments
    ///
    /// * `reference_time` - RFC3339 timestamp to compare against (typically current time from Clock)
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let lifetime = TokenLifetime::new("2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z");
    /// assert!(lifetime.is_expired("2026-01-03T00:00:00Z")); // In the future
    /// assert!(!lifetime.is_expired("2026-01-01T12:00:00Z")); // Before expiration
    /// ```
    pub fn is_expired(&self, reference_time: &str) -> bool {
        reference_time >= self.expires_at.as_str()
    }

    /// Check if token is not yet valid relative to a reference time.
    ///
    /// A token is "not yet valid" if:
    /// - `reference_time` is before `issued_at`, OR
    /// - `not_before` is set and `reference_time` is before `not_before`
    ///
    /// Returns `true` if the token should not be accepted yet.
    ///
    /// # Arguments
    ///
    /// * `reference_time` - RFC3339 timestamp to compare against (typically current time from Clock)
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let lifetime = TokenLifetime::new("2026-02-01T00:00:00Z", "2026-02-02T00:00:00Z");
    /// assert!(lifetime.is_not_yet_valid("2026-01-01T00:00:00Z")); // Before issued_at
    /// assert!(!lifetime.is_not_yet_valid("2026-02-01T12:00:00Z")); // After issued_at
    ///
    /// let delayed = TokenLifetime::new("2026-02-01T00:00:00Z", "2026-02-02T00:00:00Z")
    ///     .with_not_before("2026-02-01T12:00:00Z");
    /// assert!(delayed.is_not_yet_valid("2026-02-01T06:00:00Z")); // Before not_before
    /// ```
    pub fn is_not_yet_valid(&self, reference_time: &str) -> bool {
        // Check if before issued_at
        if reference_time < self.issued_at.as_str() {
            return true;
        }

        // Check if before not_before (if set)
        if let Some(ref nb) = self.not_before {
            if reference_time < nb.as_str() {
                return true;
            }
        }

        false
    }

    /// Check if token is temporally valid at a reference time.
    ///
    /// A token is valid if it is neither expired nor "not yet valid".
    ///
    /// Returns `true` if the token is within its validity window.
    ///
    /// # Arguments
    ///
    /// * `reference_time` - RFC3339 timestamp to compare against (typically current time from Clock)
    pub fn is_temporally_valid(&self, reference_time: &str) -> bool {
        !self.is_expired(reference_time) && !self.is_not_yet_valid(reference_time)
    }

    /// Get the "not before" time if set, otherwise the issued_at time.
    ///
    /// This represents the earliest time the token becomes valid.
    pub fn valid_from(&self) -> &str {
        self.not_before.as_deref().unwrap_or(&self.issued_at)
    }

    /// Get the expiration time.
    pub fn valid_until(&self) -> &str {
        &self.expires_at
    }
}
