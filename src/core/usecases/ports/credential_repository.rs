//! Port for credential repository access.
//!
//! Abstracts credential lookup and mutation for authentication use cases.
//!
//! Adapters must implement this trait to provide persistence or external credential management.

use crate::core::credentials::StoredCredential;

/// Contract for credential repository access.
pub trait CredentialRepository {
	/// Get the stored credential for a user by user id.
	fn get_by_user_id(&self, user_id: &str) -> Option<StoredCredential>;

	/// Update the failed login attempts counter for a user.
	fn update_failed_attempts(&self, user_id: &str, attempts: u32);

	/// Lock the user account until a given timestamp (as RFC3339 string or epoch seconds).
	fn lock_until(&self, user_id: &str, until: &str);

	/// Update the user's password to a new stored credential.
	fn update_password(&self, user_id: &str, new_credential: StoredCredential);

	/// Initialize credential state for a new user.
	///
	/// Sets failed_attempts to 0 and no lock.
	///
	/// # Arguments
	/// * `user_id` - The user ID to initialize
	///
	/// # Errors
	/// Returns an error if the operation fails.
	fn initialize_credential_state(&self, user_id: &str) -> Result<(), String>;
}
