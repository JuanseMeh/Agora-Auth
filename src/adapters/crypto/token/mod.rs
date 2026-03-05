//! JWT token signing and verification using EdDSA (Ed25519) and HMAC-SHA256.
//!
//! This module provides JWT token operations using two algorithms:
//! - Ed25519-EdDSA: Asymmetric cryptographic signature scheme (recommended)
//! - HMAC-SHA256: Symmetric key-based message authentication (legacy)
//!
//! # Components
//!
//! - [`EddsaTokenService`]: JWT token issuance and validation using Ed25519-EdDSA
//! - [`EddsaKey`]: Ed25519 key generation and management
//! - [`HmacTokenService`]: JWT token issuance and validation using HMAC-SHA256
//! - [`HmacKey`]: HMAC-SHA256 symmetric key generation and management
//!
//! # Example
//!
//! ```rust
//! use auth::adapters::crypto::token::{EddsaTokenService, EddsaKey};
//!
//! // Generate a new key pair
//! let key = EddsaKey::generate().expect("Valid key");
//!
//! // Create token service
//! let token_service = EddsaTokenService::from_key(&key)
//!     .expect("Valid key");
//! ```
//!
//! # Security Considerations
//!
//! - Keys must be generated using cryptographically secure random number generators
//! - Private keys must never be logged, transmitted, or stored insecurely
//! - Key rotation should be handled at the application level, not in this adapter

pub mod eddsa_keys;
pub mod eddsa_token_service;
pub mod hmac_keys;
pub mod hmac_token_service;

pub use eddsa_keys::{EddsaKey, ED25519_KEY_SIZE};
pub use eddsa_token_service::EddsaTokenService;
pub use hmac_keys::{HmacKey, HMAC_KEY_SIZE};
pub use hmac_token_service::HmacTokenService;

#[cfg(test)]
mod tests;

