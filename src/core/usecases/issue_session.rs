//! Use case: IssueSession
//!
//! Orchestrates session issuance for an authenticated user.
//!
//! Responsibilities:
//! - Generate refresh token
//! - Hash refresh token
//! - Persist session
//! - Generate access token
//! - Return both tokens
//!
//! Uses:
//! - TokenService
//! - SessionRepository
//! - PasswordHasher (for refresh hashing if reused)
//!
//! Returns new token pair and session lifecycle initiation.

use crate::core::identity::UserIdentity;
use crate::core::token::Token;

/// Input contract for IssueSession use case.
pub struct IssueSessionInput {
	pub user: UserIdentity,
	pub device_metadata: String,
	pub ip: String,
}

/// Output contract for IssueSession use case.
pub struct IssueSessionOutput {
	pub access_token: Token,
	pub refresh_token: Token,
}

/// Use case struct (scaffold, no implementation yet).
pub struct IssueSession;
