use crate::core::error::CredentialError;

/// Lifecycle state for credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialStatus {
	Active,
	Revoked { revoked_at: Option<String> },
	Expired { expired_at: Option<String> },
	NotYetValid { valid_from: Option<String> },
}

impl CredentialStatus {
	pub fn is_active(&self) -> bool {
		matches!(self, CredentialStatus::Active)
	}

	/// Ensure the credential may be used for verification. Violations map to
	/// `CredentialError`.
	pub fn ensure_verifiable(&self) -> Result<(), CredentialError> {
		match self {
			CredentialStatus::Active => Ok(()),
			CredentialStatus::Revoked { revoked_at } => Err(CredentialError::revoked(revoked_at.clone().unwrap_or_default())),
			CredentialStatus::Expired { expired_at } => Err(CredentialError::expired(expired_at.clone().unwrap_or_default())),
			CredentialStatus::NotYetValid { valid_from } => Err(CredentialError::not_yet_valid(valid_from.clone().unwrap_or_default())),
		}
	}
}
