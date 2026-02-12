/// Opaque representation of a persisted credential (hashed/encoded).

/* 
 Core must not know about hashing algorithms or the inner representation.
 This type therefore intentionally keeps its inner data private and does not
 provide comparison or direct accessors that would expose the secret/hash.
*/
 pub struct StoredCredential {
	repr: String,
}

impl StoredCredential {
	/// Create a `StoredCredential` from an already-produced opaque representation.
	///
	/// Adapters (persistence layer) are expected to construct this value from
	/// whatever storage stores; core will treat it as an opaque token.
	pub fn from_hash(hash: impl Into<String>) -> Self {
		Self { repr: hash.into() }
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
}
