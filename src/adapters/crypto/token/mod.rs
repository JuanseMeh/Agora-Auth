//! HMAC-SHA256 token module for JWT signing and verification.
//!
//! This module provides HMAC-SHA256-based JWT token operations, implementing
//! the `TokenService` port from the core domain. HMAC-SHA256 is widely
//! supported and simpler to use than asymmetric algorithms like EdDSA.
//!
//! # Components
//!
//! - [`HmacTokenService`]: JWT token issuance and validation using HMAC-SHA256
//! - [`HmacKey`]: HMAC-SHA256 symmetric key generation and management
//!
//! # Example
//!
//! ```rust
//! use auth::adapters::crypto::token::{HmacTokenService, HmacKey};
//!
//! // Generate a new key
//! let key = HmacKey::generate().expect("Valid key");
//!
//! // Create token service
//! let token_service = HmacTokenService::from_secret_key(&key.as_bytes())
//!     .expect("Valid key");
//! ```
//!
//! # Security Considerations
//!
//! - Keys must be generated using cryptographically secure random number generators
//! - Secret keys must never be logged, transmitted, or stored insecurely
//! - Key rotation should be handled at the application level, not in this adapter

pub mod hmac_keys;
pub mod hmac_token_service;

pub use hmac_keys::{HmacKey, HMAC_KEY_SIZE};
pub use hmac_token_service::HmacTokenService;

#[cfg(test)]
mod tests;
