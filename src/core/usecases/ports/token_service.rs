//! Port for token issuance and validation.
//!
//! Abstracts access and refresh token issuance and validation for authentication use cases.
//!
//! Adapters must implement this trait to provide concrete token logic (e.g., JWT, PASETO).

use crate::core::token::Token;

/// Contract for token service.
pub trait TokenService: Send + Sync {
	/// Issue a new access token for a subject (user id, claims, etc.).
	fn issue_access_token(&self, subject: &str, claims: &str) -> Token;

	/// Issue a new refresh token for a subject.
	fn issue_refresh_token(&self, subject: &str, claims: &str) -> Token;

	/// Issue a new service token for service-to-service authentication.
	fn issue_service_token(&self, subject: &str, claims: &str) -> Token;

	/// Validate an access token and return claims if valid.
	fn validate_access_token(&self, token: &Token) -> Result<String, ()>;

	/// Validate a refresh token and return claims if valid.
	fn validate_refresh_token(&self, token: &Token) -> Result<String, ()>;

	/// Validate a service token and return claims if valid.
	fn validate_service_token(&self, token: &Token) -> Result<String, ()>;
}
