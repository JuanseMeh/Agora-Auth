use crate::core::error::CredentialError;

/*  
 Transient credential presented during an authentication attempt.

 This type intentionally does not implement `Clone` to avoid accidental
 copying of sensitive secret material. Callers may consume it (move) and
 provide the inner secret to a hashing/verification port.
*/
pub struct RawCredential {
	secret: String,
}

impl RawCredential {
	/// Create a new `RawCredential` from a secret string.
	pub fn new(secret: impl Into<String>) -> Self {
		Self {
			secret: secret.into(),
		}
	}

	/// Borrow the secret as `&str` for validation purposes.
	pub fn as_str(&self) -> &str {
		&self.secret
	}

	/// Consume the credential and return the inner secret. Ownership is
	/// transferred to the caller so core cannot accidentally persist it.
	pub fn into_inner(self) -> String {
		self.secret
	}

	/// Length of the secret in bytes.
	pub fn len(&self) -> usize {
		self.secret.len()
	}

	/// Validate this credential against a policy.
	///
	/// Validation is pure and deterministic; it does not perform hashing or
	/// any side effects. Failures map to `CredentialError`.
	pub fn validate(&self, policy: &crate::core::credentials::CredentialPolicy) -> Result<(), CredentialError> {
		// Required
		if self.secret.is_empty() {
			return Err(CredentialError::missing_required("secret"));
		}

		// Minimum length
		if self.secret.len() < policy.min_length {
			return Err(CredentialError::insufficient_strength(format!("minimum length is {}", policy.min_length)));
		}

		// Optional format check (placeholder supplied by policy)
		if let Some(check) = policy.format_check {
			if !check(self.as_str()) {
				return Err(CredentialError::invalid_format("credential", "format check failed"));
			}
		}

		// Entropy check is intentionally a placeholder: policy may contain a
		// description/marker; actual entropy measurement belongs to adapters.
		if let Some(_note) = &policy.entropy_note {
			// no-op here; policy only documents the requirement
		}

		Ok(())
	}
}

