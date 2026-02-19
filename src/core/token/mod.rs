//! Core token domain types and validation semantics.
//!
//! This module defines the vocabulary and semantics for tokens in the core
//! authentication domain. It intentionally avoids cryptography, serialization,
//! and key management — those concerns belong to adapters and ports.
//!
//! # Core Concepts
//!
//! - [`Token`]: An opaque trust artifact with no encoding assumptions
//! - [`TokenClaims`]: Identity assertions and temporal bounds
//! - [`TokenLifetime`]: Temporal validation semantics (expiration, not-before)
//! - [`TokenValidationFailure`]: Semantic categories of validation failures
//!
//! # Design Principles
//!
//! **Transport-agnostic**: Tokens could be JWT, PASETO, or any other format.
//! The core domain makes no assumptions about how tokens are encoded or transmitted.
//!
//! **Claim discipline**: Claims carry identity context, never permissions.
//! Token claims cannot encode business rules or authorization decisions.
//!
//! **No crypto**: Core defines "what is a valid token" in domain terms.
//! Signature verification and key management belong to adapters.

pub mod token;
pub mod token_claims;
pub mod token_lifetime;
pub mod token_validation;

pub use token::Token;
pub use token_claims::TokenClaims;
pub use token_lifetime::TokenLifetime;
pub use token_validation::{TokenValidationFailure, TokenValidationResult};

#[cfg(test)]
mod tests;
