//! Port for session repository access.
//!
//! Abstracts session creation, lookup, revocation, and cleanup for authentication use cases.
//!
//! Adapters must implement this trait to provide persistence or external session management.

use crate::core::identity::UserIdentity;

/// Opaque session type for use case contracts (to be defined in usecases).
pub struct Session {/* fields omitted for now */}

/// Contract for session repository access.
pub trait SessionRepository {
	/// Create a new session for a user.
	fn create_session(&self, user: &UserIdentity, refresh_token_hash: &str, metadata: &str);

	/// Find a session by refresh token hash.
	fn find_by_refresh_token_hash(&self, hash: &str) -> Option<Session>;

	/// Revoke a session by id or token hash.
	fn revoke_session(&self, session_id: &str);

	/// Revoke all sessions for a user.
	fn revoke_all_for_user(&self, user_id: &str);

	/// Delete all expired sessions.
	fn delete_expired(&self);
}
