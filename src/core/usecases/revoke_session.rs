//! Use case: RevokeSession
//!
//! Orchestrates session revocation (mark revoked_at, idempotent, no deletion).
//!
//! Responsibilities:
//! - Mark revoked_at
//! - No deletion
//! - Idempotent

/// Input contract for RevokeSession use case.
pub struct RevokeSessionInput {
	pub session_id: String,
}

/// Output contract for RevokeSession use case.
pub struct RevokeSessionOutput {
	pub success: bool,
}

/// Use case struct (scaffold, no implementation yet).
pub struct RevokeSession;
