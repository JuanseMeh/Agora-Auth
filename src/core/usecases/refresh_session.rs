//! Use case: RefreshSession
//!
//! Orchestrates refresh token rotation and access token renewal.
//!
//! Responsibilities:
//! - Validate refresh token cryptographically
//! - Extract subject
//! - Hash raw refresh
//! - Lookup session
//! - Check revoked_at
//! - Check expires_at
//! - Rotate refresh token
//! - Issue new access token
//! - Invalidate old refresh token (one-time use)
//!
//! Returns new token pair.

use crate::core::token::Token;

/// Input contract for RefreshSession use case.
pub struct RefreshSessionInput {
	pub raw_refresh_token: String,
}

/// Output contract for RefreshSession use case.
pub struct RefreshSessionOutput {
	pub access_token: Token,
	pub refresh_token: Token,
}

/// Use case struct (scaffold, no implementation yet).
pub struct RefreshSession;
