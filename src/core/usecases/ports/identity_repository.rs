//! Port for identity repository access.
//!
//! Abstracts user and workspace identity lookup for authentication use cases.
//!
//! Adapters must implement this trait to provide persistence or external identity resolution.

use crate::core::identity::UserIdentity;
use crate::core::identity::WorkspaceIdentity;

/// Contract for identity repository access.
pub trait IdentityRepository {
	/// Find a user identity by a unique identifier (e.g., username, email).
	fn find_by_identifier(&self, identifier: &str) -> Option<UserIdentity>;

	/// Find a user identity by its unique id.
	fn find_by_id(&self, id: &str) -> Option<UserIdentity>;

	/// Find a workspace identity by its unique id.
	fn find_workspace_by_id(&self, id: &str) -> Option<WorkspaceIdentity>;

	/// Create a new identity with the given credentials.
	///
	/// # Arguments
	/// * `user_id` - Unique user identifier
	/// * `identifier` - User's unique identifier (username/email)
	/// * `password_hash` - Hashed password
	/// * `salt` - Password salt
	/// * `algorithm` - Hashing algorithm used
	/// * `iterations` - Number of hashing iterations
	///
	/// # Errors
	/// Returns an error if the identifier already exists or persistence fails.
	fn create(
		&self,
		user_id: &uuid::Uuid,
		identifier: &str,
		password_hash: &str,
		salt: &str,
		algorithm: &str,
		iterations: u32,
	) -> Result<(), String>;
}
