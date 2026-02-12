//! Use case: AuthenticateUser
//!
//! Orchestrates user authentication by verifying identity, lockout status, and credentials.
//!
//! Responsibilities:
//! - Find user
//! - Check locked_until
//! - Verify password
//! - Reset or increment failed_attempts
//! - Enforce lockout policy
//! - Return domain identity
//!
//! Does NOT:
//! - Issue tokens
//! - Create sessions
//!
//! Returns AuthenticatedUser context only.

use crate::core::identity::UserIdentity;

/// Input contract for AuthenticateUser use case.
pub struct AuthenticateUserInput {
	pub identifier: String,
	pub password: String,
}

/// Output contract for AuthenticateUser use case.
pub struct AuthenticateUserOutput {
	pub user: UserIdentity,
	// Add more fields as needed (e.g., contextual identity, credential status)
}

/// Use case struct (scaffold, no implementation yet).
pub struct AuthenticateUser;
