/// Opaque representation of a persisted credential (hashed/encoded).

/* 
 Core must not know about hashing algorithms or the inner representation.
 This type therefore intentionally keeps its inner data private and does not
 provide comparison or direct accessors that would expose the secret/hash.
*/
#[derive(Clone)]
 pub struct StoredCredential {
	repr: String,
	pub failed_attempts: u32,
	pub locked_until: Option<String>,
}

impl StoredCredential {
	/// Create a `StoredCredential` from an already-produced opaque representation.
	///
	/// Adapters (persistence layer) are expected to construct this value from
	/// whatever storage stores; core will treat it as an opaque token.
	pub fn from_hash(hash: impl Into<String>) -> Self {
		Self { 
			repr: hash.into(),
			failed_attempts: 0,
			locked_until: None,
		}
	}

	/// Create a `StoredCredential` with all fields populated.
	///
	/// Used by adapters when loading from persistence.
	pub fn from_parts(
		hash: impl Into<String>,
		failed_attempts: u32,
		locked_until: Option<String>,
	) -> Self {
		Self {
			repr: hash.into(),
			failed_attempts,
			locked_until,
		}
	}
}

impl std::fmt::Debug for StoredCredential {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("StoredCredential([REDACTED])")
	}
}

impl StoredCredential {
	/// Returns true when the stored representation is non-empty.
	///
	/// This method intentionally does not reveal the representation itself,
	/// only a minimal, non-sensitive property that adapters may find useful
	/// in tests or sanity checks.
	pub fn is_non_empty(&self) -> bool {
		!self.repr.is_empty()
	}

	/// Returns the length of the stored representation. This leaks only the
	/// length (not content), which may be useful for assertions in tests and
	/// adapters without exposing secrets.
	pub fn repr_len(&self) -> usize {
		self.repr.len()
	}

	/// Returns the stored hash representation as a string slice.
    ///
    /// This method is intended for use by password hashing adapters that need
    /// to access the hash string for verification purposes. The hash is already
    /// in its encoded form (e.g., PHC format) and does not expose the raw password.
    ///
    /// # Security Note
    ///
    /// The returned string is the hashed/encoded credential, not a plaintext secret.
    /// It is safe to use for cryptographic verification operations.
    pub fn as_hash_str(&self) -> &str {
        &self.repr
    }
}
