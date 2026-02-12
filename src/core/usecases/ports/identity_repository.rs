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
}
