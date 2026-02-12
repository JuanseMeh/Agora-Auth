//! Use case: ValidateAccessToken
//!
//! Orchestrates access token validation and domain error mapping.
//!
//! Responsibilities:
//! - Delegate to TokenService
//! - Map failure to domain error
//! - Optionally check password version
//! - If password_changed_at > token.issued_at → token invalid

use crate::core::token::Token;

/// Input contract for ValidateAccessToken use case.
pub struct ValidateAccessTokenInput {
	pub access_token: Token,
}

/// Output contract for ValidateAccessToken use case.
pub struct ValidateAccessTokenOutput {
	pub valid: bool,
	pub reason: Option<String>,
}

/// Use case struct (scaffold, no implementation yet).
pub struct ValidateAccessToken;
