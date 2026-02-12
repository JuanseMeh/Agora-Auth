use crate::core::error::CredentialError;

/* 
 Policy describing credential validation rules.

 This type is intentionally simple and focuses on rules that are deterministic
 and pure. Complex checks (real entropy estimation, external blacklists, or
 algorithmic checks) belong to adapters.
*/
pub struct CredentialPolicy {
	/// Minimum secret length in bytes.
	pub min_length: usize,

	/// Whether to enforce a basic complexity rule (placeholder).
	pub require_complexity: bool,

	/// Optional format check function. When present it is invoked during
	/// validation. Kept as a function pointer to avoid bringing heavy deps into
	/// the core.
	pub format_check: Option<fn(&str) -> bool>,

	/// Placeholder note describing entropy expectations. Not used for logic
	/// inside core, only documentation/reporting.
	pub entropy_note: Option<String>,
}

impl Default for CredentialPolicy {
	fn default() -> Self {
		Self {
			min_length: 8,
			require_complexity: true,
			format_check: None,
			entropy_note: None,
		}
	}
}

impl CredentialPolicy {
	/// Validate a raw credential according to this policy. Returns a
	/// `CredentialError` on failure.
	pub fn validate_raw(&self, raw: &crate::core::credentials::RawCredential) -> Result<(), CredentialError> {
		raw.validate(self)
	}
}
