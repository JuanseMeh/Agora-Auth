//! Port for password hashing and verification.
//!
//! Abstracts password hashing and verification for authentication use cases.
//!
//! Adapters must implement this trait to provide concrete hashing algorithms.

use crate::core::credentials::StoredCredential;

/// Contract for password hashing and verification.
pub trait PasswordHasher {
	/// Hash a raw password and return a stored credential.
	fn hash(&self, raw: &str) -> StoredCredential;

	/// Verify a raw password against a stored credential.
	fn verify(&self, raw: &str, stored: &StoredCredential) -> bool;
}
